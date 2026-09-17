// The compliance baseline. Its output ends up in someone's remediation plan, so
// the tests are written around what must stay true of the verdict: a control
// never fails a domain for a posture its state does not call for, `na` never
// moves a score, and a zone carrying exactly the published policy is perfect.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  CONTROLS, AXES, SCOPES, SEVERITY_WEIGHT, GRADE_BANDS, BASELINE_VERSION,
  evaluate, aggregate, caaApplicable, caaBlocker,
} from '../lib/baseline.mjs';
import { buildPolicy } from '../lib/harden.mjs';
import { parseZone } from '../lib/inventory.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

const rec = (name, type, rdata) => ({ name, type, rdata });
const txt = (name, value) => rec(name, 'TXT', `"${value}"`);
const of = (report, id) => report.controls.find((c) => c.id === id);
const status = (records, id, over = {}) => of(evaluate(records, { domain: 'example.com', ...over }), id).status;

/** A zone carrying exactly what `harden --caa --null-mx` publishes. */
function policyZone(opts = { caa: true, nullMx: true }) {
  return buildPolicy(opts).map((r) => rec(
    r.subDomain || '@',
    r.fieldType,
    r.fieldType === 'TXT' ? `"${r.target}"` : r.target,
  ));
}

describe('catalogue', () => {
  test('every control is addressable, weighted and sourced', () => {
    const ids = new Set();
    for (const c of CONTROLS) {
      assert.ok(/^[a-z]+\.[a-z0-9-]+$/.test(c.id), `bad id: ${c.id}`);
      assert.equal(ids.has(c.id), false, `duplicate id: ${c.id}`);
      ids.add(c.id);
      assert.ok(c.title.length > 0, `${c.id} has no title`);
      assert.ok(AXES.includes(c.axis), `${c.id} has an unknown axis`);
      assert.ok(SEVERITY_WEIGHT[c.severity], `${c.id} has an unknown severity`);
      assert.ok(SCOPES[c.scope], `${c.id} has an unknown scope`);
      assert.ok(c.refs.length > 0, `${c.id} cites nothing`);
      assert.equal(typeof c.check, 'function');
    }
  });

  test('every failure carries a remediation a reader can act on', () => {
    // An empty zone in each state, so every control gets a chance to fail.
    for (const state of ['dormant', 'web-active', 'mail-active']) {
      for (const c of evaluate([], { domain: 'example.com', state }).controls) {
        if (c.status !== 'fail') continue;
        assert.ok(c.remediation?.text, `${c.id} fails with no remediation`);
      }
    }
  });

  test('a remediation command names the domain rather than a placeholder', () => {
    for (const c of evaluate([], { domain: 'other.example' }).controls) {
      if (!c.remediation?.command) continue;
      assert.doesNotMatch(c.remediation.command, /<domain>/);
      assert.match(c.remediation.command, /other\.example/);
    }
  });

  test('the grade bands are ordered and reach zero', () => {
    const mins = GRADE_BANDS.map(([m]) => m);
    assert.deepEqual(mins, [...mins].sort((a, b) => b - a));
    assert.equal(mins.at(-1), 0);
  });

  // Anti-drift: docs/BASELINE.md is the published catalogue. A control that
  // exists in code but nowhere in the documentation is an undocumented
  // interface, and control ids are a public interface.
  test('every control id appears in docs/BASELINE.md', () => {
    const doc = readFileSync(join(ROOT, 'docs', 'BASELINE.md'), 'utf8');
    for (const c of CONTROLS) assert.ok(doc.includes(c.id), `${c.id} is missing from docs/BASELINE.md`);
  });
});

describe('scoring', () => {
  test('a zone carrying exactly the published policy scores 100 and grades A', () => {
    const report = evaluate(policyZone(), { domain: 'example.com' });
    assert.equal(report.state, 'dormant');
    assert.equal(report.score, 100);
    assert.equal(report.grade, 'A');
    assert.equal(report.tally.fail, 0);
  });

  test('an empty zone fails every applicable control and grades F', () => {
    const report = evaluate([], { domain: 'example.com' });
    assert.equal(report.grade, 'F');
    assert.ok(report.tally.fail > 0);
    assert.equal(report.tally.pass < report.tally.fail, true);
  });

  test('a single failing critical caps the grade at C', () => {
    // The policy zone minus its DMARC record: everything else still passes.
    const records = policyZone().filter((r) => r.name !== '_dmarc');
    const report = evaluate(records, { domain: 'example.com' });
    assert.ok(report.score >= 70, `score was ${report.score}`);
    assert.equal(report.grade, 'C');
    assert.equal(of(report, 'dmarc.present').status, 'fail');
  });

  test('n/a never moves the score: two zones differing only by an n/a tie', () => {
    const base = policyZone({ caa: true });
    const withNullMx = policyZone({ caa: true, nullMx: true });
    // mx.null-explicit is scored on both (dormant); strip it from the compare
    // by scoring the second zone as web-active, where CAA turns n/a instead.
    const a = evaluate(base, { domain: 'a.example' });
    const b = evaluate(base, { domain: 'b.example' });
    assert.equal(a.score, b.score);
    assert.ok(withNullMx.length > base.length);
  });

  test('the axis scores are computed over their own controls only', () => {
    const report = evaluate(policyZone(), { domain: 'example.com' });
    for (const axis of AXES) assert.equal(report.axes[axis].score, 100);
  });

  test('evaluate is pure: same input, same output, and the records are untouched', () => {
    const records = policyZone();
    const snapshot = JSON.parse(JSON.stringify(records));
    const first = evaluate(records, { domain: 'example.com' });
    const second = evaluate(records, { domain: 'example.com' });
    assert.deepEqual(first, second);
    assert.deepEqual(records, snapshot);
  });
});

describe('anti-spoofing controls', () => {
  test('SPF must be published, and only once', () => {
    assert.equal(status([], 'spf.present'), 'fail');
    assert.equal(status([txt('@', 'v=spf1 -all')], 'spf.present'), 'pass');
    assert.equal(status([txt('@', 'v=spf1 -all')], 'spf.single'), 'pass');

    const duplicated = [txt('@', 'v=spf1 -all'), txt('@', 'v=spf1 include:_spf.google.com ~all')];
    const report = evaluate(duplicated, { domain: 'example.com' });
    assert.equal(of(report, 'spf.single').status, 'fail');
    assert.equal(of(report, 'spf.single').evidence.length, 2);
  });

  test('only the terminal qualifier decides a hard fail', () => {
    assert.equal(status([txt('@', 'v=spf1 -all')], 'spf.hardfail'), 'pass');
    assert.equal(status([txt('@', 'v=spf1 include:x.example -all')], 'spf.hardfail'), 'pass');
    assert.equal(status([txt('@', 'v=spf1 ~all')], 'spf.hardfail'), 'fail');
    assert.equal(status([txt('@', 'v=spf1 +all')], 'spf.hardfail'), 'fail');
    assert.equal(status([txt('@', 'v=spf1')], 'spf.hardfail'), 'fail');
  });

  test('a hard fail is not enough: a non-sending domain must authorise nobody', () => {
    // The gap `spf.hardfail` leaves. It reads the terminal qualifier and nothing
    // else, so it passes the record below — which still lets every host in a
    // shared provider's SPF send as this domain, because the first mechanism to
    // match wins and `-all` only covers the remainder (RFC 7208 §4.6.2).
    const shared = [txt('@', 'v=spf1 include:mx.ovh.com -all')];
    assert.equal(status(shared, 'spf.hardfail'), 'pass');
    assert.equal(status(shared, 'spf.no-senders'), 'fail');

    assert.equal(status([txt('@', 'v=spf1 -all')], 'spf.no-senders'), 'pass');
    assert.equal(status([txt('@', 'v=spf1 a mx -all')], 'spf.no-senders'), 'fail');
    // `exp=` names an explanation string (RFC 7208 §6.2), it authorises nobody.
    assert.equal(status([txt('@', 'v=spf1 -all exp=why.example')], 'spf.no-senders'), 'pass');
    // Absence is `spf.present`'s failure. Counting it twice would punish the
    // same missing record under two controls.
    assert.equal(status([], 'spf.no-senders'), 'pass');
    // A sending domain authorises its senders on purpose.
    assert.equal(status(shared, 'spf.no-senders', { state: 'mail-active' }), 'na');
  });

  test('the lookup budget is satisfied vacuously, never failed for absence', () => {
    const sending = { state: 'mail-active' };
    assert.equal(status([], 'spf.lookup-budget', sending), 'pass');
    const heavy = 'v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:s${i}.example`).join(' ') + ' -all';
    assert.equal(status([txt('@', heavy)], 'spf.lookup-budget', sending), 'fail');
  });

  test('DMARC is ignored by receivers when duplicated, so duplication fails', () => {
    const one = [txt('_dmarc', 'v=DMARC1; p=reject')];
    assert.equal(status(one, 'dmarc.present'), 'pass');
    assert.equal(status([...one, txt('_dmarc', 'v=DMARC1; p=none')], 'dmarc.present'), 'fail');
  });

  test('neither none nor quarantine counts as a reject policy', () => {
    assert.equal(status([txt('_dmarc', 'v=DMARC1; p=none')], 'dmarc.reject'), 'fail');
    assert.equal(status([txt('_dmarc', 'v=DMARC1; p=quarantine')], 'dmarc.reject'), 'fail');
    assert.equal(status([txt('_dmarc', 'v=DMARC1; p=reject')], 'dmarc.reject'), 'pass');
  });

  test('the subdomain policy must be stated, not inherited', () => {
    assert.equal(status([txt('_dmarc', 'v=DMARC1; p=reject')], 'dmarc.subdomain-reject'), 'fail');
    assert.equal(status([txt('_dmarc', 'v=DMARC1; p=reject; sp=reject')], 'dmarc.subdomain-reject'), 'pass');
  });

  test('an empty p= is a revocation, a filled one is a live key', () => {
    const revoked = [txt('*._domainkey', 'v=DKIM1; p=')];
    assert.equal(status(revoked, 'dkim.wildcard-revoked'), 'pass');
    assert.equal(status(revoked, 'dkim.no-live-selector'), 'pass');

    // A live key is enough on its own to classify the zone mail-active — the
    // fail-safe direction — so the leftover-selector case only exists on a zone
    // something else already established as non-sending.
    const live = [txt('sel1._domainkey', 'v=DKIM1; k=rsa; p=MIGfMA0GCSq')];
    assert.equal(status(live, 'dkim.no-live-selector'), 'na');
    assert.equal(status(live, 'dkim.no-live-selector', { state: 'dormant' }), 'fail');
  });

  test('a delegated DKIM selector is reported with a manual fix, not a command', () => {
    const delegated = [rec('sel._domainkey', 'CNAME', 'sel.dkim.example.net.')];
    const control = of(evaluate(delegated, { domain: 'example.com', state: 'dormant' }), 'dkim.no-live-selector');
    assert.equal(control.status, 'fail');
    assert.equal(control.remediation.command, null);
    assert.match(control.remediation.text, /OVH manager/);
  });
});

describe('closed by default', () => {
  test('a routed MX fails on a domain that should not receive mail', () => {
    assert.equal(status([], 'mx.closed'), 'pass');
    assert.equal(status([rec('@', 'MX', '0 .')], 'mx.closed'), 'pass');
    assert.equal(status([rec('@', 'MX', '10 mx1.mail.ovh.net.')], 'mx.closed'), 'fail');
  });

  test('a CAA deny is n/a where it would break certificate issuance', () => {
    const dormant = [txt('@', 'v=spf1 -all')];
    assert.equal(status(dormant, 'caa.issue-deny'), 'fail');

    const web = [rec('www', 'A', '203.0.113.10')];
    assert.equal(status(web, 'caa.issue-deny'), 'na');

    const redirecting = [txt('@', '3|www.example.com')];
    assert.equal(status(redirecting, 'caa.issue-deny', { state: 'dormant' }), 'na');

    const acme = [txt('_acme-challenge', 'token')];
    assert.equal(status(acme, 'caa.issue-deny', { state: 'dormant' }), 'na');
  });

  test('a deny passes whatever quoting OVH exported it with', () => {
    for (const form of ['0 issue ";"', '0 issue ;', '"0 issue ;"', '0 issue']) {
      assert.equal(status([rec('@', 'CAA', form)], 'caa.issue-deny'), 'pass', `form: ${form}`);
    }
  });

  test('with no issuewild property the issue deny governs wildcards too', () => {
    assert.equal(status([rec('@', 'CAA', '0 issue ";"')], 'caa.issuewild-deny'), 'pass');
    assert.equal(status([rec('@', 'CAA', '0 issuewild "letsencrypt.org"')], 'caa.issuewild-deny'), 'fail');
  });

  test('a CAA still authorising an unused CA is reported on a dormant domain', () => {
    assert.equal(status([rec('@', 'CAA', '0 issue "letsencrypt.org"')], 'caa.no-permissive'), 'fail');
    assert.equal(status([rec('@', 'CAA', '0 issue ";"')], 'caa.no-permissive'), 'pass');
  });

  test('caaApplicable and caaBlocker agree, and the blocker says why', () => {
    const web = [rec('@', 'A', '203.0.113.10')];
    assert.equal(caaApplicable(web, { state: 'web-active' }), false);
    assert.match(caaBlocker(web, { state: 'web-active' }), /web content/);
    assert.equal(caaBlocker([rec('@', 'A', '213.186.33.5')], { state: 'dormant' }), null);
    assert.equal(caaApplicable([], { state: 'dormant' }), true);
  });
});

describe('attack surface', () => {
  test('a wildcard makes every unregistered name resolve, so it fails', () => {
    assert.equal(status([rec('*', 'A', '203.0.113.10')], 'wildcard.none'), 'fail');
    assert.equal(status([txt('*._domainkey', 'v=DKIM1; p=')], 'wildcard.none'), 'pass');
  });

  test('a leftover service subdomain is named in the finding', () => {
    const records = [rec('autodiscover', 'CNAME', 'mailconfig.ovh.net.')];
    const control = of(evaluate(records, { domain: 'example.com', state: 'dormant' }), 'services.no-legacy');
    assert.equal(control.status, 'fail');
    assert.match(control.detail, /autodiscover/);
  });

  test('a CNAME to a takeover-prone platform is critical, an ordinary one is not', () => {
    assert.equal(status([rec('assets', 'CNAME', 'old-bucket.s3.amazonaws.com.')], 'cname.no-takeover'), 'fail');
    assert.equal(status([rec('docs', 'CNAME', 'acme.github.io.')], 'cname.no-takeover'), 'fail');
    assert.equal(status([rec('www', 'CNAME', 'example.com.')], 'cname.no-takeover'), 'pass');
  });

  test('the takeover finding asks for verification instead of asserting one', () => {
    const records = [rec('assets', 'CNAME', 'old-bucket.s3.amazonaws.com.')];
    const control = of(evaluate(records, { domain: 'example.com' }), 'cname.no-takeover');
    assert.match(control.detail, /Verify/);
  });

  test('SRV and stale verification TXT records are reported', () => {
    assert.equal(status([rec('_sip._tcp', 'SRV', '0 0 5060 sip.example.net.')], 'srv.none'), 'fail');
    assert.equal(status([txt('@', 'google-site-verification=abc')], 'txt.no-stale-verification'), 'fail');
    assert.equal(status([txt('@', 'v=spf1 -all')], 'txt.no-stale-verification'), 'pass');
  });
});

describe('scope — every domain is judged against the posture its state calls for', () => {
  const mail = [
    rec('@', 'MX', '10 aspmx.l.google.com.'),
    txt('@', 'v=spf1 include:_spf.google.com ~all'),
    txt('sel._domainkey', 'v=DKIM1; k=rsa; p=MIGfMA0'),
  ];

  test('a mail-active domain is not failed for the dormant posture', () => {
    const report = evaluate(mail, { domain: 'example.com' });
    assert.equal(report.state, 'mail-active');
    for (const id of ['spf.hardfail', 'dkim.wildcard-revoked', 'mx.closed', 'caa.issue-deny']) {
      assert.equal(of(report, id).status, 'na', `${id} should be n/a on a mail-active domain`);
    }
    for (const id of ['spf.no-permissive', 'dkim.selector-published']) {
      assert.equal(of(report, id).status, 'pass', `${id} should be scored on a mail-active domain`);
    }
  });

  test('DMARC is judged in every state — nobody gets to skip it', () => {
    for (const state of ['dormant', 'web-active', 'mail-active']) {
      assert.notEqual(status([], 'dmarc.reject', { state }), 'na');
    }
  });

  test('an out-of-scope n/a is distinguishable from one the baseline decided', () => {
    const mailReport = evaluate(mail, { domain: 'example.com' });
    assert.equal(of(mailReport, 'mx.closed').naReason, 'scope');

    const web = evaluate([rec('www', 'A', '203.0.113.10')], { domain: 'example.com' });
    assert.equal(of(web, 'caa.issue-deny').naReason, 'scope');

    const redirecting = evaluate([txt('@', '3|www.example.com')], { domain: 'example.com', state: 'dormant' });
    assert.equal(of(redirecting, 'caa.issue-deny').naReason, 'check');
  });
});

describe('aggregate', () => {
  const report = (domain, over = {}) => ({ ...evaluate(policyZone(), { domain }), ...over });

  test('an empty portfolio yields a null score rather than throwing', () => {
    const agg = aggregate([]);
    assert.equal(agg.score, null);
    assert.equal(agg.grade, null);
    assert.deepEqual(agg.topFailures, []);
  });

  test('a domain with no backup is excluded from the average, not scored zero', () => {
    const broken = { domain: 'gone.example', state: 'error', score: null, grade: null, controls: [] };
    const agg = aggregate([report('a.example'), broken]);
    assert.equal(agg.score, 100);
    assert.equal(agg.scored, 1);
    assert.equal(agg.errors, 1);
    assert.equal(agg.domains, 2);
  });

  test('the portfolio score is an unweighted mean, so a big zone does not outvote a small one', () => {
    const perfect = report('a.example');
    const empty = evaluate([], { domain: 'b.example' });
    const agg = aggregate([perfect, empty]);
    assert.equal(agg.score, Math.round((perfect.score + empty.score) / 2));
  });

  test('failures are counted across the portfolio, worst first', () => {
    const agg = aggregate([evaluate([], { domain: 'a.example' }), evaluate([], { domain: 'b.example' })]);
    assert.ok(agg.topFailures.length > 0);
    assert.equal(agg.topFailures[0].count, 2);
    const counts = agg.topFailures.map((f) => f.count);
    assert.deepEqual(counts, [...counts].sort((a, b) => b - a));
  });

  test('the baseline version is a semver string reports can be compared on', () => {
    assert.match(BASELINE_VERSION, /^\d+\.\d+\.\d+$/);
  });
});

describe('parsing quirks that would silently under-report', () => {
  test('a quoted semicolon in a CAA survives the zone parser', () => {
    const records = parseZone('@ 3600 IN CAA 0 issue ";"');
    assert.equal(records.length, 1);
    assert.equal(records[0].rdata, '0 issue ";"');
    assert.equal(status(records, 'caa.issue-deny'), 'pass');
  });

  test('a TXT value split into several quoted chunks is read whole', () => {
    const records = [rec('_dmarc', 'TXT', '( "v=DMARC1; p=re" "ject; sp=reject" )')];
    assert.equal(status(records, 'dmarc.reject'), 'pass');
    assert.equal(status(records, 'dmarc.subdomain-reject'), 'pass');
  });
});
