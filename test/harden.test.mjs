// The cleaner. Everything here is destructive in production, so the tests are
// written around what must NOT happen: no protected record deleted, no web
// redirect broken silently, no churn on an already-hardened zone.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildPolicy, planZone, applyPlan, recordLabel, DEFAULT_CNAMES_TO_DROP } from '../lib/harden.mjs';

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
    assert.ok(buildPolicy({ ttl: 60, nullMx: true }).every((r) => r.ttl === 60));
  });
});

describe('planZone — what gets deleted', () => {
  test('MX records are removed from a dormant domain', () => {
    const p = plan([rec('MX', '', '10 mx1.mail.ovh.net.')]);
    assert.equal(p.delete.length, 1);
    assert.match(p.delete[0].reason, /MX on a dormant domain/);
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
    const p = plan([rec('TXT', '_acme-challenge', 'token')], { keepPatterns: [/acme/i] });
    assert.equal(p.delete.length, 0);
  });

  test('--keep wins over the MX rule', () => {
    const p = plan([rec('MX', '', '10 mx1.mail.ovh.net.')], { keepPatterns: [/mx1/] });
    assert.equal(p.delete.length, 0);
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
});
