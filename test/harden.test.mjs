// The cleaner. Everything here is destructive in production, so the tests are
// written around what must NOT happen: no protected record deleted, no web
// redirect broken silently, no churn on an already-hardened zone.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildPolicy, planZone, applyPlan, fetchRecords, recordLabel, DEFAULT_CNAMES_TO_DROP } from '../lib/harden.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

let nextId = 1;
const rec = (fieldType, subDomain, target) => ({ id: nextId++, fieldType, subDomain, target, ttl: 3600 });
const plan = (records, over = {}) => planZone(records, { policy: buildPolicy(), ...over });
const subs = (list) => list.map((r) => r.subDomain || '@');

describe('buildPolicy', () => {
  test('publishes SPF -all, strict DMARC reject and a revoked DKIM wildcard', () => {
    const p = buildPolicy();
    assert.deepEqual(subs(p), ['@', '_dmarc', '*._domainkey']);
    assert.equal(p[0].target, 'v=spf1 -all');
    assert.equal(p[1].target, 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s');
    assert.equal(p[2].target, 'v=DKIM1; p=');
  });

  test('no rua is published unless one is asked for', () => {
    assert.doesNotMatch(buildPolicy()[1].target, /rua=/);
    assert.match(buildPolicy({ rua: 'mailto:dmarc@example.com' })[1].target, /rua=mailto:dmarc@example\.com$/);
  });

  test('null MX is opt-in', () => {
    assert.equal(buildPolicy().some((r) => r.fieldType === 'MX'), false);
    const nullMx = buildPolicy({ nullMx: true }).find((r) => r.fieldType === 'MX');
    assert.equal(nullMx.target, '0 .');
  });

  test('the TTL is applied to every record', () => {
    assert.ok(buildPolicy({ ttl: 60, caa: true, nullMx: true }).every((r) => r.ttl === 60));
  });

  test('CAA is opt-in — a plain policy publishes none', () => {
    assert.equal(buildPolicy().some((r) => r.fieldType === 'CAA'), false);
    assert.equal(buildPolicy({ nullMx: true }).some((r) => r.fieldType === 'CAA'), false);
  });

  test('--caa publishes the deny pair, and nothing a CA could still use', () => {
    const caa = buildPolicy({ caa: true }).filter((r) => r.fieldType === 'CAA');
    assert.deepEqual(caa.map((r) => r.target), ['0 issue ";"', '0 issuewild ";"']);
    assert.ok(caa.every((r) => r.subDomain === ''), 'a CAA deny belongs at the apex');
  });

  test('an iodef is published only when an address is given', () => {
    assert.equal(buildPolicy({ caa: true }).some((r) => /iodef/.test(r.target)), false);
    const iodef = buildPolicy({ caa: true, iodef: 'mailto:security@example.com' })
      .find((r) => /iodef/.test(r.target));
    assert.equal(iodef.target, '0 iodef "mailto:security@example.com"');
  });

  test('the three anti-spoofing records keep positions 0-2 whatever else is added', () => {
    // Callers and tests index into this array; CAA and MX append, never insert.
    const p = buildPolicy({ caa: true, nullMx: true, iodef: 'mailto:x@example.com' });
    assert.deepEqual(subs(p).slice(0, 3), ['@', '_dmarc', '*._domainkey']);
    assert.equal(p[0].target, 'v=spf1 -all');
    assert.ok(p.every((r) => r.why), 'every record explains itself in the plan output');
  });
});

describe('planZone — what gets deleted', () => {
  test('an apex MX is removed', () => {
    const p = plan([rec('MX', '', '10 mx1.mail.ovh.net.')]);
    assert.equal(p.delete.length, 1);
    assert.match(p.delete[0].reason, /MX at the apex/);
  });

  test('stale SPF/DKIM/DMARC are replaced by the policy', () => {
    const p = plan([rec('SPF', '', 'v=spf1 include:_spf.google.com ~all')]);
    assert.equal(p.delete.length, 1);
    assert.equal(p.create.length, 3);
  });

  test('the ftp CNAME goes, other CNAMEs stay', () => {
    const p = plan([rec('CNAME', 'ftp', 'ftp.ovh.net.'), rec('CNAME', 'www', 'example.com.')]);
    assert.deepEqual(subs(p.delete), ['ftp']);
    assert.ok(p.keep.some((r) => r.subDomain === 'www' && r.reason === 'out of scope'));
  });

  test('--drop-cname extends the default list without replacing it', () => {
    assert.deepEqual(DEFAULT_CNAMES_TO_DROP, ['ftp']);
    const p = plan([rec('CNAME', 'ftp', 'x.'), rec('CNAME', 'webmail', 'y.')], { cnamesToDrop: ['ftp', 'webmail'] });
    assert.deepEqual(subs(p.delete).sort(), ['ftp', 'webmail']);
  });
});

describe('planZone — what is protected', () => {
  test('the OVH web-redirect marker is kept by default', () => {
    const p = plan([rec('TXT', '', '3|www.example.com')]);
    assert.equal(p.delete.length, 0);
    assert.ok(p.keep.some((r) => r.reason === 'OVH redirection marker'));
  });

  test('--drop-redirect removes it, and says the redirect will break', () => {
    const p = plan([rec('TXT', '', '3|www.example.com')], { dropRedirect: true });
    assert.equal(p.delete.length, 1);
    assert.match(p.delete[0].reason, /the web redirect will break/);
  });

  test('--keep protects on the record value', () => {
    const p = plan([rec('TXT', '', 'google-site-verification=abc123')], { keepPatterns: [/site-verification/i] });
    assert.equal(p.delete.length, 0);
    assert.ok(p.keep.some((r) => r.reason === 'protected by --keep'));
  });

  test('--keep protects on the subdomain name too', () => {
    // Pinned on a _domainkey selector on purpose: an apex policy name, so it
    // WOULD be deleted without --keep. `_acme-challenge` no longer proves
    // anything here — the apex gate keeps it regardless.
    const sel = rec('TXT', 'selector1._domainkey', 'v=DKIM1; p=MIGf');
    assert.equal(plan([sel]).delete.length, 1);
    assert.equal(plan([sel], { keepPatterns: [/selector1/i] }).delete.length, 0);
  });

  test('--keep wins over the MX rule', () => {
    const p = plan([rec('MX', '', '10 mx1.mail.ovh.net.')], { keepPatterns: [/mx1/] });
    assert.equal(p.delete.length, 0);
  });
});

describe('the apex gate — a subdomain is not the apex', () => {
  // The policy is published at the apex, so it may only remove what competes
  // with it there. Before this gate existed, `planZone` filtered on the record
  // TYPE alone and proposed deleting a delegated sending subdomain whole: its
  // MX, its SPF, its DKIM key and its DMARC policy, all six records, on a zone
  // whose mail was working. The reason it printed was `MX on a dormant domain`
  // about a zone it had itself just classified mail-active.

  /** A zone shaped like a domain that delegates sending to `mg.`, with a
   *  stale apex policy that SHOULD still be replaced. */
  const delegatedSender = () => [
    rec('MX', 'mg', '10 mxa.eu.mailgun.org.'),
    rec('MX', 'mg', '10 mxb.eu.mailgun.org.'),
    rec('TXT', 'mg', 'v=spf1 include:mailgun.org ~all'),
    rec('TXT', '_dmarc.mg', 'v=DMARC1; p=none; rua=mailto:r@example.com'),
    rec('TXT', 'email._domainkey.mg', 'k=rsa; p=MIGfMA0GCS'),
    rec('CNAME', 'email.mg', 'eu.mailgun.org.'),
    rec('TXT', 'checker', 'google-site-verification=abc123'),
    rec('TXT', '', 'v=spf1 ~all'),
    rec('TXT', '_dmarc', 'v=DMARC1; p=none'),
    rec('TXT', 'selector1._domainkey', 'v=DKIM1; p=MIGfMA0GCS'),
  ];

  test('not one record of the delegated sending subdomain is deleted', () => {
    const p = plan(delegatedSender());
    const doomed = p.delete.filter((r) => /(^|\.)mg$/.test(r.subDomain || ''));
    assert.deepEqual(doomed, [], `would have deleted: ${doomed.map((r) => r.label).join(', ')}`);
  });

  test('a subdomain MX is never deleted — that is the one that broke mail', () => {
    assert.equal(plan(delegatedSender()).delete.filter((r) => r.fieldType === 'MX').length, 0);
  });

  test('the stale apex policy IS still replaced', () => {
    const p = plan(delegatedSender());
    assert.deepEqual(subs(p.delete).sort(), ['@', '_dmarc', 'selector1._domainkey']);
  });

  test('a third-party verification TXT on a subdomain survives', () => {
    const p = plan(delegatedSender());
    assert.ok(p.keep.some((r) => r.subDomain === 'checker'));
  });

  test('_dmarc is ours, _dmarc.mg is not', () => {
    const p = plan([rec('TXT', '_dmarc', 'v=DMARC1; p=none'), rec('TXT', '_dmarc.mg', 'v=DMARC1; p=none')]);
    assert.deepEqual(subs(p.delete), ['_dmarc']);
  });

  test('sel._domainkey is ours, sel._domainkey.mg is not', () => {
    const p = plan([rec('TXT', 'a._domainkey', 'v=DKIM1; p=x'), rec('TXT', 'a._domainkey.mg', 'v=DKIM1; p=x')]);
    assert.deepEqual(subs(p.delete), ['a._domainkey']);
  });

  test('an in-flight ACME challenge is no longer swept away', () => {
    // Deleting this mid-issuance fails the certificate request.
    assert.equal(plan([rec('TXT', '_acme-challenge', 'token')]).delete.length, 0);
  });

  test('the kept record says why, so the operator is not left guessing', () => {
    const p = plan([rec('MX', 'mg', '10 mxa.eu.mailgun.org.')]);
    assert.match(p.keep[0].reason, /out of scope: mg is not an apex policy name/);
  });

  test('the gate does not make the plan churn: twice in a row is stable', () => {
    const first = plan(delegatedSender());
    const settled = [...first.keep, ...first.create.map((w) => rec(w.fieldType, w.subDomain, w.target))];
    const second = plan(settled);
    assert.deepEqual(second.delete, []);
    assert.deepEqual(second.create, []);
  });
});

describe('planZone — idempotence', () => {
  const applied = (opts) => buildPolicy(opts).map((r) => ({ ...rec(r.fieldType, r.subDomain, r.target) }));

  test('an already-hardened zone yields an empty plan', () => {
    const p = plan(applied());
    assert.deepEqual(p.delete, []);
    assert.deepEqual(p.create, []);
    assert.equal(p.keep.filter((r) => r.reason === 'already compliant').length, 3);
  });

  test('OVH dedicated SPF/DKIM/DMARC fieldTypes count as compliant TXT', () => {
    const p = plan([
      rec('SPF', '', 'v=spf1 -all'),
      rec('DMARC', '_dmarc', 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s'),
      rec('DKIM', '*._domainkey', 'v=DKIM1; p='),
    ]);
    assert.deepEqual(p.delete, []);
    assert.deepEqual(p.create, []);
  });

  test('quoting and split strings do not cause needless churn', () => {
    const p = plan([rec('TXT', '', '"v=spf1" " -all"')]);
    assert.equal(p.create.some((r) => r.target === 'v=spf1 -all'), false);
  });

  test('a partially hardened zone only creates what is missing', () => {
    const p = plan([rec('TXT', '', 'v=spf1 -all')]);
    assert.deepEqual(subs(p.create), ['_dmarc', '*._domainkey']);
    assert.deepEqual(p.delete, []);
  });

  test('re-planning the result of an apply changes nothing', () => {
    const first = plan([rec('MX', '', '10 mx1.mail.ovh.net.'), rec('TXT', '', 'v=spf1 ~all')]);
    const after = first.create.map((r) => rec(r.fieldType, r.subDomain, r.target));
    const second = plan(after);
    assert.deepEqual(second.delete, []);
    assert.deepEqual(second.create, []);
  });
});

describe('applyPlan', () => {
  const fakeOvh = ({ failDelete = [], failPost = false, failRefresh = false } = {}) => {
    const calls = [];
    return {
      calls,
      async delete(path) {
        calls.push(['DELETE', path]);
        if (failDelete.some((id) => path.endsWith(`/${id}`))) throw new Error('boom');
      },
      async post(path, body) {
        calls.push(['POST', path, body]);
        if (path.endsWith('/refresh')) {
          if (failRefresh) throw new Error('refresh failed');
          return null;
        }
        if (failPost) throw new Error('nope');
        return { ...body };
      },
    };
  };

  test('deletes, creates, then refreshes the zone', async () => {
    const ovh = fakeOvh();
    const p = plan([rec('MX', '', '10 mx1.mail.ovh.net.')]);
    const done = await applyPlan(ovh, 'example.com', p);

    assert.equal(done.deleted.length, 1);
    assert.equal(done.created.length, 3);
    assert.deepEqual(done.errors, []);
    assert.equal(ovh.calls.at(-1)[1], '/domain/zone/example.com/refresh');
  });

  test('a failing deletion is collected, not thrown, and the rest still runs', async () => {
    const record = rec('MX', '', '10 mx1.mail.ovh.net.');
    const ovh = fakeOvh({ failDelete: [record.id] });
    const done = await applyPlan(ovh, 'example.com', plan([record]));

    assert.equal(done.deleted.length, 0);
    assert.equal(done.errors.length, 1);
    assert.match(done.errors[0], /^DELETE /);
    assert.equal(done.created.length, 3, 'creations must still happen');
  });

  test('a failing creation is collected per record', async () => {
    const done = await applyPlan(fakeOvh({ failPost: true }), 'example.com', plan([]));
    assert.equal(done.created.length, 0);
    assert.equal(done.errors.filter((e) => e.startsWith('CREATE')).length, 3);
  });

  test('a failing refresh is reported rather than swallowed', async () => {
    const done = await applyPlan(fakeOvh({ failRefresh: true }), 'example.com', plan([]));
    assert.ok(done.errors.some((e) => e.startsWith('REFRESH:')));
  });

  test('the zone name is URL-encoded in every path', async () => {
    const ovh = fakeOvh();
    await applyPlan(ovh, 'xn--exmple-cua.com', plan([]));
    assert.ok(ovh.calls.every(([, path]) => path.includes('xn--exmple-cua.com')));
  });

  test('an empty plan still refreshes and reports nothing done', async () => {
    const ovh = fakeOvh();
    const done = await applyPlan(ovh, 'example.com', { delete: [], create: [], keep: [] });
    assert.deepEqual(done, { deleted: [], created: [], errors: [] });
    assert.equal(ovh.calls.length, 1);
  });
});

describe('planZone and CAA', () => {
  const caaPolicy = { policy: buildPolicy({ caa: true }) };
  const labels = (list) => list.map((r) => r.label ?? recordLabel(r));

  test('a CAA is NEVER deleted by a policy that publishes none', () => {
    // The single most important line of the CAA work. Deleting a CAA without
    // republishing one LOOSENS the zone: no CAA at all means every CA in the
    // world may issue. A plain `harden` must leave it alone.
    const caa = rec('CAA', '', '0 issue "letsencrypt.org"');
    const out = plan([caa]);
    assert.equal(out.delete.length, 0);
    assert.equal(out.keep.find((r) => r.fieldType === 'CAA').reason, 'CAA out of scope (pass --caa)');
  });

  test('with --caa a permissive CAA is replaced by the deny pair', () => {
    const out = plan([rec('CAA', '', '0 issue "letsencrypt.org"')], caaPolicy);
    assert.equal(out.delete.length, 1);
    assert.match(out.delete[0].reason, /replaced by the closed-by-default policy/);
    assert.deepEqual(out.create.filter((r) => r.fieldType === 'CAA').map((r) => r.target),
      ['0 issue ";"', '0 issuewild ";"']);
  });

  test('a zone already closed produces an empty plan — idempotence', () => {
    const closed = buildPolicy({ caa: true })
      .map((r) => rec(r.fieldType, r.subDomain, r.fieldType === 'TXT' ? `"${r.target}"` : r.target));
    const out = plan(closed, caaPolicy);
    assert.deepEqual(out.delete, []);
    assert.deepEqual(out.create, []);
    assert.equal(out.keep.filter((r) => r.reason === 'already compliant').length, 5);
  });

  test('a half-closed zone creates exactly the missing issuewild', () => {
    const out = plan([rec('CAA', '', '0 issue ";"')], caaPolicy);
    assert.equal(out.create.filter((r) => r.fieldType === 'CAA').length, 1);
    assert.equal(out.create.find((r) => r.fieldType === 'CAA').target, '0 issuewild ";"');
    assert.equal(out.delete.filter((r) => r.fieldType === 'CAA').length, 0);
  });

  test('no churn whichever way OVH quoted the stored value', () => {
    for (const [issue, issuewild] of [
      ['0 issue ";"', '0 issuewild ";"'],
      ['0 issue ;', '0 issuewild ;'],
      ['"0 issue ;"', '"0 issuewild ;"'],
      ['0 "issue" ";"', '0 "issuewild" ";"'],
    ]) {
      const out = plan([rec('CAA', '', issue), rec('CAA', '', issuewild)], caaPolicy);
      const touched = out.delete.filter((r) => r.fieldType === 'CAA').length
        + out.create.filter((r) => r.fieldType === 'CAA').length;
      assert.equal(touched, 0, `churned on: ${issue}`);
    }
  });

  test('two policy entries never reconcile against the same record', () => {
    // Only one CAA exists; issue and issuewild must not both claim it.
    const out = plan([rec('CAA', '', '0 issue ";"')], caaPolicy);
    assert.equal(out.keep.filter((r) => r.fieldType === 'CAA' && r.reason === 'already compliant').length, 1);
  });

  test('--keep protects a legitimate CAA even under --caa', () => {
    const out = plan([rec('CAA', '', '0 issue "letsencrypt.org"')],
      { ...caaPolicy, keepPatterns: [/letsencrypt/i] });
    assert.equal(out.delete.length, 0);
    assert.equal(out.keep[0].reason, 'protected by --keep');
    // The deny is still published alongside it — by RFC 8659 the issue set is a
    // union, so issuance stays allowed. printPlan warns about exactly this.
    assert.ok(labels(out.create).some((l) => l.includes('0 issue ";"')));
  });

  test('a CAA on a subdomain is left alone — the policy only replaces the apex one', () => {
    // Changed deliberately. The policy publishes `@ CAA`, so it replaces `@ CAA`.
    // A CAA on www is a per-subdomain certificate decision someone made on
    // purpose, and deleting it is a deletion with nothing put back in its place.
    const out = plan([rec('CAA', 'www', '0 issue "letsencrypt.org"')], caaPolicy);
    assert.equal(out.delete.length, 0);
    assert.match(out.keep.find((r) => r.subDomain === 'www').reason, /not an apex policy name/);
  });
});

describe('fetchRecords', () => {
  const fakeZone = (byType) => ({
    calls: [],
    async get(path) {
      this.calls.push(path);
      const m = /fieldType=(\w+)/.exec(path);
      if (m) {
        const found = byType[m[1]];
        if (found === undefined) { const e = new Error('Not found'); e.status = 404; throw e; }
        if (found === 400) { const e = new Error('Bad enum'); e.status = 400; throw e; }
        return found.map((_, i) => `${m[1]}-${i}`);
      }
      const [type, i] = path.split('/').pop().split('-');
      return { id: path, fieldType: type, subDomain: '', target: byType[type][Number(i)] };
    },
  });

  test('CAA is among the types queried', async () => {
    const ovh = fakeZone({ CAA: ['0 issue ";"'] });
    const records = await fetchRecords(ovh, 'example.com');
    assert.ok(ovh.calls.some((c) => c.includes('fieldType=CAA')));
    assert.deepEqual(records.map((r) => r.target), ['0 issue ";"']);
  });

  test('a 400 on an unknown fieldType skips the type instead of aborting the run', async () => {
    // Seen on CAA: some accounts' API version does not know the enum value.
    // Losing one type must not cost the whole batch.
    const ovh = fakeZone({ TXT: ['"v=spf1 -all"'], CAA: 400 });
    const records = await fetchRecords(ovh, 'example.com');
    assert.deepEqual(records.map((r) => r.target), ['"v=spf1 -all"']);
  });

  test('anything other than a 404 or a 400 still propagates', async () => {
    const ovh = { async get() { const e = new Error('rate limited'); e.status = 429; throw e; } };
    await assert.rejects(() => fetchRecords(ovh, 'example.com'), /rate limited/);
  });
});
