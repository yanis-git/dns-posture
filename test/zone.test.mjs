// The record vocabulary every other module reads a zone through. Nothing here
// touches the network or the filesystem; the value is that the classifier, the
// check predicates and the write path all agree on what a record says, and
// they only agree because there is one copy of these rules.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  caaBlocker,
  isApexPolicyName,
  parseCaa,
  recordLabel,
  sameRecord,
  toZoneShape,
  txtValue,
} from '../lib/zone.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

describe('parseCaa', () => {
  // Tolerance here is what keeps planZone idempotent: a quoting variant we fail
  // to recognise reads as "different from the policy" and churns on every run.
  test('reads every quoting variant OVH might hand back', () => {
    for (const form of ['0 issue ";"', '0 issue ;', '"0 issue ;"', '0 "issue" ";"', '"0 issue \\";\\""']) {
      const caa = parseCaa(form);
      assert.equal(caa?.tag, 'issue', `tag lost on: ${form}`);
      assert.equal(caa.flags, 0);
    }
  });

  test('keeps the flags and lowercases the tag', () => {
    assert.deepEqual(parseCaa('128 ISSUEWILD "letsencrypt.org"'),
      { flags: 128, tag: 'issuewild', value: 'letsencrypt.org' });
  });

  test('returns null on something that is not a CAA at all', () => {
    assert.equal(parseCaa('v=spf1 -all'), null);
    assert.equal(parseCaa(''), null);
    assert.equal(parseCaa(undefined), null);
  });
});
describe('recordLabel', () => {
  test('does not double the quotes OVH already puts around a TXT target', () => {
    assert.equal(recordLabel({ subDomain: '', fieldType: 'TXT', target: '"v=spf1 -all"' }), '@ TXT "v=spf1 -all"');
  });

  test('quotes an unquoted target', () => {
    assert.equal(recordLabel({ subDomain: '_dmarc', fieldType: 'TXT', target: 'v=DMARC1; p=reject' }), '_dmarc TXT "v=DMARC1; p=reject"');
  });

  test('only a surrounding quote pair is stripped, not inner ones', () => {
    assert.equal(recordLabel({ subDomain: '@', fieldType: 'TXT', target: 'a "b" c' }), '@ TXT "a "b" c"');
  });

  test('a structured target carries its own quoting and gets none added', () => {
    // `@ CAA "0 issue ";""` is unreadable and does not round-trip.
    assert.equal(recordLabel({ subDomain: '', fieldType: 'CAA', target: '0 issue ";"' }), '@ CAA 0 issue ";"');
    assert.equal(recordLabel({ subDomain: '', fieldType: 'MX', target: '0 .' }), '@ MX 0 .');
    assert.equal(recordLabel({ subDomain: 'ftp', fieldType: 'CNAME', target: 'example.com.' }), 'ftp CNAME example.com.');
  });
});

describe('toZoneShape', () => {
  // A finding licenses a deletion. If the two views disagree about what a
  // record says, the deletion is executed against bytes no check ever read.
  test('an API-shaped record reads as the zone-file shape the checks expect', () => {
    assert.deepEqual(
      toZoneShape({ id: 7, subDomain: '_dmarc', fieldType: 'TXT', target: 'v=DMARC1; p=reject', ttl: 3600 }),
      { name: '_dmarc', type: 'TXT', rdata: 'v=DMARC1; p=reject' });
  });

  test('an empty subDomain becomes the apex, which is how a zone file spells it', () => {
    assert.equal(toZoneShape({ subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all' }).name, '@');
  });
});

describe('isApexPolicyName', () => {
  test('the three names the apex policy owns', () => {
    for (const name of ['@', '', '_dmarc', 'sel._domainkey', '*._domainkey', '_domainkey']) {
      assert.equal(isApexPolicyName(name), true, `should own: ${name || '(empty)'}`);
    }
  });

  test('a delegated sending subdomain is not ours, however similar the name', () => {
    // `email._domainkey.mg` is Mailgun's key, not an apex selector. Deleting
    // it takes the customer's mail with it — a dry-run on a real zone proposed
    // exactly that before the suffix test existed.
    for (const name of ['mg', '_dmarc.mg', 'email._domainkey.mg', 'www', '_domainkey.mg']) {
      assert.equal(isApexPolicyName(name), false, `should not own: ${name}`);
    }
  });
});

describe('txtValue', () => {
  test('long values split into quoted chunks concatenate, as DNS does', () => {
    assert.equal(txtValue('( "v=spf1 " "-all" )'), 'v=spf1 -all');
  });

  test('an unquoted value is returned as it stands', () => {
    assert.equal(txtValue('v=spf1 -all'), 'v=spf1 -all');
  });
});

describe('sameRecord', () => {
  test("OVH's dedicated SPF type still matches a wanted TXT at the same value", () => {
    // The zone export renders SPF/DKIM/DMARC fieldTypes as TXT. A record
    // already at the policy value is compliant whatever type OVH filed it under.
    assert.equal(
      sameRecord({ subDomain: '', fieldType: 'SPF', target: '"v=spf1 -all"' },
        { subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all' }),
      true);
  });

  test('a CAA matches across quoting variants, which is what stops the churn', () => {
    const wanted = { subDomain: '', fieldType: 'CAA', target: '0 issue ";"' };
    for (const form of ['0 issue ";"', '0 issue ;', '"0 issue ;"', '0 "issue" ";"']) {
      assert.equal(sameRecord({ subDomain: '', fieldType: 'CAA', target: form }, wanted), true, form);
    }
  });

  test('a different value is a different record', () => {
    assert.equal(
      sameRecord({ subDomain: '', fieldType: 'TXT', target: 'v=spf1 ~all' },
        { subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all' }),
      false);
  });
});

describe('caaBlocker', () => {
  // One predicate, three consumers: the n/a of the CAA controls, the write
  // refusal, and the resolver that demotes a CAA remedy. They cannot disagree.
  test('a parked zone is safe to deny', () => {
    assert.equal(caaBlocker([{ name: '@', type: 'A', rdata: '213.186.33.5' }], { state: 'dormant' }), null);
  });

  test('a web-active zone is never denied — the next renewal would fail', () => {
    assert.match(String(caaBlocker([], { state: 'web-active' })), /serves web content/);
  });

  test('an ACME challenge in flight blocks the deny', () => {
    const zone = [{ name: '_acme-challenge', type: 'TXT', rdata: '"token"' }];
    assert.match(String(caaBlocker(zone, { state: 'dormant' })), /ACME challenge/);
  });

  test('an OVH redirection marker blocks the deny', () => {
    const zone = [{ name: 'www', type: 'TXT', rdata: '"3|www.example.com"' }];
    assert.match(String(caaBlocker(zone, { state: 'dormant' })), /web redirection/);
  });

  test('a live apex outside the parking range blocks the deny', () => {
    const zone = [{ name: '@', type: 'A', rdata: '203.0.113.9' }];
    assert.match(String(caaBlocker(zone, { state: 'dormant' })), /still resolves to a live host/);
  });
});
