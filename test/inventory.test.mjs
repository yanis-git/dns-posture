// Zone parsing and classification. This is the code that decides whether a
// domain is safe to harden, so the fail-safe directions matter more than the
// happy path: an unknown MX must read as active, a revoked DKIM must not.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseZone, classify } from '../lib/inventory.mjs';
import { buildPolicy } from '../lib/harden.mjs';

// Any network call from these modules is a bug.
globalThis.fetch = () => { throw new Error('no network in unit tests'); };

const find = (records, type, name) => records.find((r) => r.type === type && r.name === name);

// A zone-file line for a policy record. Only textual types are quoted: quoting
// a CAA would produce `@ IN CAA "0 issue ";""`, which is not a zone file.
const zoneLine = (r) => `${r.subDomain || '@'}   ${r.ttl} IN ${r.fieldType}     `
  + (r.fieldType === 'TXT' ? `"${r.target}"` : r.target);

describe('parseZone', () => {
  test('a quoted semicolon is data, not a comment', () => {
    const [rec] = parseZone('_dmarc 3600 IN TXT "v=DMARC1; p=reject; sp=reject"');
    assert.equal(rec.rdata, '"v=DMARC1; p=reject; sp=reject"');
  });

  test('an unquoted trailing comment is stripped', () => {
    const [rec] = parseZone('www 3600 IN A 1.2.3.4 ; legacy host');
    assert.equal(rec.rdata, '1.2.3.4');
  });

  test('a single-line SOA is skipped', () => {
    const records = parseZone([
      '@	IN SOA dns101.ovh.net. tech.ovh.net. (2088953526 86400 3600 3600000 60)',
      '        IN NS     dns101.ovh.net.',
    ].join('\n'));
    assert.deepEqual(records.map((r) => r.type), ['NS']);
  });

  test('a multi-line SOA is skipped up to its closing paren', () => {
    const records = parseZone([
      '@ IN SOA dns101.ovh.net. tech.ovh.net. (',
      '   2088953526 ; serial',
      '   86400 3600 3600000 60 )',
      'www 3600 IN A 1.2.3.4',
    ].join('\n'));
    assert.deepEqual(records.map((r) => r.type), ['A']);
  });

  test('$TTL and $ORIGIN directives are ignored', () => {
    const records = parseZone('$TTL 3600\n$ORIGIN example.com.\nwww IN A 1.2.3.4');
    assert.equal(records.length, 1);
  });

  test('an indented record inherits the previous name', () => {
    const records = parseZone('www 3600 IN A 1.2.3.4\n        3600 IN A 5.6.7.8');
    assert.deepEqual(records.map((r) => r.name), ['www', 'www']);
  });

  test('a leading TTL or IN is never mistaken for a name', () => {
    const [rec] = parseZone('   3600 IN TXT     "v=spf1 -all"');
    assert.equal(rec.name, '@');
    assert.equal(rec.type, 'TXT');
  });

  // Regression: findIndex used to match the first RR-type token anywhere on the
  // line, so a subdomain named after a type stole the type slot and shifted the
  // name to the previous record's. `mx IN A ...` parsed as an MX -> the zone
  // classified as mail-active and was wrongly skipped by harden.
  for (const label of ['mx', 'ns', 'a', 'srv', 'ptr', 'caa']) {
    test(`a subdomain named "${label}" keeps its real type`, () => {
      const [rec] = parseZone(`${label} 3600 IN A 1.2.3.4`);
      assert.equal(rec.type, 'A', `${label} should parse as an A record`);
      assert.equal(rec.name, label);
      assert.equal(rec.rdata, '1.2.3.4');
    });
  }

  test('a real MX line still parses as MX', () => {
    const [rec] = parseZone('@ 3600 IN MX 10 aspmx.l.google.com.');
    assert.equal(rec.type, 'MX');
    assert.equal(rec.rdata, '10 aspmx.l.google.com.');
  });
});

describe('classify — mail detection', () => {
  const mx = (host) => [{ name: '@', type: 'MX', rdata: `10 ${host}` }];

  for (const [host, label] of [
    ['aspmx.l.google.com.', 'Google Workspace'],
    ['example-com.mail.protection.outlook.com.', 'Microsoft 365'],
    ['mxa.mailgun.org.', 'transactional ESP'],
    ['ex1.mail.ovh.net.', 'OVH Exchange/Pro'],
  ]) {
    test(`${label} MX -> mail-active`, () => {
      assert.equal(classify(mx(host)).state, 'mail-active');
    });
  }

  test('OVH default MX alone does not make a domain mail-active', () => {
    const res = classify(mx('mx1.mail.ovh.net.'));
    assert.equal(res.state, 'dormant');
    assert.match(res.signals.join(' '), /default OVH MX/);
  });

  test('an unrecognised MX is treated as active (fail-safe)', () => {
    const res = classify(mx('mail.some-host.example.'));
    assert.equal(res.state, 'mail-active');
    assert.match(res.signals.join(' '), /unknown MX/);
  });

  test('a null MX (RFC 7505) means no mail, not an unknown host', () => {
    const res = classify([{ name: '@', type: 'MX', rdata: '0 .' }]);
    assert.equal(res.state, 'dormant');
    assert.match(res.signals.join(' '), /null MX/);
  });

  test('a published DKIM key -> mail-active', () => {
    const res = classify([{ name: 'sel1._domainkey', type: 'TXT', rdata: '"v=DKIM1; k=rsa; p=MIIBIjANBg"' }]);
    assert.equal(res.state, 'mail-active');
  });

  test('a revoked DKIM key (p= empty) does NOT make a domain mail-active', () => {
    const res = classify([{ name: '*._domainkey', type: 'TXT', rdata: '"v=DKIM1; p="' }]);
    assert.equal(res.state, 'dormant');
  });

  test('a _domainkey CNAME (OVH MX Plan delegation) -> mail-active', () => {
    const res = classify([{ name: 'ovhmo123-selector1._domainkey', type: 'CNAME', rdata: 'ovhmo123-selector1._domainkey.ovh.com.' }]);
    assert.equal(res.state, 'mail-active');
  });
});

describe('classify — web detection', () => {
  test('a real A record -> web-active', () => {
    assert.equal(classify([{ name: '@', type: 'A', rdata: '203.0.113.10' }]).state, 'web-active');
  });

  test('the OVH parking IP alone stays dormant', () => {
    const res = classify([{ name: '@', type: 'A', rdata: '213.186.33.5' }]);
    assert.equal(res.state, 'dormant');
    assert.match(res.signals.join(' '), /OVH parking/);
  });

  test('www -> apex CNAME is an alias, not separate content', () => {
    const records = [{ name: 'www', type: 'CNAME', rdata: 'example.com.' }];
    assert.equal(classify(records, { domain: 'example.com' }).state, 'dormant');
    // Without the domain hint it cannot know, and errs on the side of "active".
    assert.equal(classify(records).state, 'web-active');
  });

  test('ftp CNAME and wildcard are not web content', () => {
    const res = classify([
      { name: 'ftp', type: 'CNAME', rdata: 'ftp.cluster021.hosting.ovh.net.' },
      { name: '*', type: 'A', rdata: '203.0.113.10' },
    ]);
    assert.equal(res.state, 'dormant');
  });

  test('a live subdomain is reported in the signals', () => {
    const res = classify([{ name: 'api', type: 'A', rdata: '203.0.113.10' }]);
    assert.equal(res.state, 'web-active');
    assert.match(res.signals.join(' '), /1 subdomain\(s\): api/);
  });

  test('an empty zone is dormant and says so', () => {
    assert.deepEqual(classify([]), {
      state: 'dormant',
      signals: ['empty zone'],
      apexSends: false,
      counts: { mx: 0, txt: 0, cname: 0, a: 0, total: 0 },
    });
  });

  describe('apex versus a delegated sending subdomain', () => {
    // A domain can route all its mail through `mg.` and never send from the
    // apex. The zone is in use — hardening it blind would break that mail — but
    // the apex is wide open, which is the half an audit has to see.
    const mailgunSubdomain = [
      { name: 'mg', type: 'MX', rdata: '10 mxa.eu.mailgun.org.' },
      { name: 'mg', type: 'TXT', rdata: '"v=spf1 include:mailgun.org ~all"' },
      { name: 'email._domainkey.mg', type: 'TXT', rdata: '"k=rsa; p=MIGf"' },
    ];

    test('the zone still classifies mail-active — the fail-safe direction holds', () => {
      assert.equal(classify(mailgunSubdomain).state, 'mail-active');
    });

    test('but the apex is reported as not sending', () => {
      assert.equal(classify(mailgunSubdomain).apexSends, false);
    });

    test('the signal names the subdomain instead of implying the apex', () => {
      const { signals } = classify(mailgunSubdomain);
      assert.ok(signals.some((x) => /MX transactional ESP on mg/.test(x)), signals.join(' | '));
      assert.ok(signals.some((x) => /apex itself does not send/.test(x)), signals.join(' | '));
    });

    test('an apex MX does set apexSends', () => {
      assert.equal(classify([{ name: '@', type: 'MX', rdata: '10 mxa.eu.mailgun.org.' }]).apexSends, true);
    });

    test('an apex DKIM selector sets it, a subdomain one does not', () => {
      const key = (name) => [{ name, type: 'TXT', rdata: '"v=DKIM1; k=rsa; p=MIGf"' }];
      assert.equal(classify(key('selector1._domainkey')).apexSends, true);
      assert.equal(classify(key('email._domainkey.mg')).apexSends, false);
    });

    test('an unrecognised MX at the apex stays fail-safe on both counts', () => {
      const out = classify([{ name: '@', type: 'MX', rdata: '10 mail.unknown-host.example.' }]);
      assert.equal(out.state, 'mail-active');
      assert.equal(out.apexSends, true);
    });
  });
});

describe('the hardened state is stable', () => {
  // The invariant that keeps the workflow convergent: once a zone has been
  // hardened, re-inventorying it must still read "dormant", or the domain
  // reappears in the queue for ever.
  test('a zone carrying exactly the policy classifies as dormant', () => {
    const zone = [
      '$TTL 3600',
      '@	IN SOA dns101.ovh.net. tech.ovh.net. (2088953526 86400 3600 3600000 60)',
      '        IN NS     dns101.ovh.net.',
      ...buildPolicy().map(zoneLine),
    ].join('\n');

    const records = parseZone(zone);
    assert.ok(find(records, 'TXT', '_dmarc'), 'the DMARC record should survive the round-trip');
    assert.equal(classify(records, { domain: 'example.com' }).state, 'dormant');
  });

  test('the same zone with null-MX is still dormant', () => {
    const zone = buildPolicy({ nullMx: true }).map(zoneLine).join('\n');
    assert.equal(classify(parseZone(zone), { domain: 'example.com' }).state, 'dormant');
  });

  test('the fully closed zone — CAA and null MX — is still dormant', () => {
    // CAA appears in no classify filter and in no host set: it only bumps
    // counts.total. Publishing a deny must never push a domain out of the
    // dormant queue, or --caa would hide the domains it just hardened.
    const zone = buildPolicy({ caa: true, nullMx: true }).map(zoneLine).join('\n');
    const records = parseZone(zone);
    assert.equal(records.filter((r) => r.type === 'CAA').length, 2);
    assert.equal(classify(records, { domain: 'example.com' }).state, 'dormant');
  });

  test('a zone holding nothing but a CAA is dormant, not active', () => {
    const records = [{ name: '@', type: 'CAA', rdata: '0 issue ";"' }];
    assert.equal(classify(records, { domain: 'example.com' }).state, 'dormant');
  });
});

describe('the quoted semicolon in a CAA', () => {
  // stripComment truncates at a `;` outside quotes. A CAA deny is *entirely*
  // a semicolon, so if OVH ever exports it unquoted the rdata arrives as
  // `0 issue` and every CAA control silently under-reports from the backups.
  test('a quoted deny survives the parser intact', () => {
    const records = parseZone('@ 3600 IN CAA 0 issue ";"');
    assert.equal(records.length, 1);
    assert.equal(records[0].type, 'CAA');
    assert.equal(records[0].rdata, '0 issue ";"');
  });

  test('an unquoted deny is truncated — the reason the quoted form is published', () => {
    assert.equal(parseZone('@ 3600 IN CAA 0 issue ;')[0].rdata, '0 issue');
  });

  test('an issuewild deny and an iodef round-trip too', () => {
    const records = parseZone([
      '@ 3600 IN CAA 0 issuewild ";"',
      '@ 3600 IN CAA 0 iodef "mailto:security@example.com"',
    ].join('\n'));
    assert.deepEqual(records.map((r) => r.rdata),
      ['0 issuewild ";"', '0 iodef "mailto:security@example.com"']);
  });
});
