// The policy file is data that decides whether DNS records get deleted, so the
// interesting tests here are the ones about REFUSING a file, not accepting one.
// A typo that loads is a deletion that happens, or fails to happen, for a
// reason nobody can see in a diff.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ACTIONS,
  CLASSIFIER_STATES,
  PolicyError,
  WRITING_ACTIONS,
  loadPolicy,
  planFromFindings,
  resolvePolicy,
  validatePolicy,
} from '../lib/policy.mjs';
import { CHECKS, CONTROLS, SCOPES, evaluate } from '../lib/baseline.mjs';
import { DISPLACERS, sameRecord, toZoneShape } from '../lib/zone.mjs';
import { planZone } from '../lib/harden.mjs';
import shipped from '../config/policy.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

/** A mutable deep copy of the shipped config. structuredClone keeps RegExps. */
const clone = () => structuredClone(shipped);

/** Validate a mutated copy and return the problems it raised. */
function problemsFrom(mutate) {
  const config = clone();
  mutate(config);
  try {
    validatePolicy(config, { path: 'test' });
  } catch (err) {
    assert.ok(err instanceof PolicyError, `expected a PolicyError, got ${err}`);
    return err.problems;
  }
  return null;
}

/** Assert that validation failed, and that one problem points at `key`. */
function refuses(mutate, key) {
  const problems = problemsFrom(mutate);
  assert.ok(problems, 'the config was accepted but should have been refused');
  const keys = problems.map((p) => p.key);
  assert.ok(keys.includes(key), `no problem reported on ${key}; got: ${keys.join(' | ')}`);
  return problems.find((p) => p.key === key);
}

let nextId = 1;
const rec = (subDomain, fieldType, target) => ({ id: nextId++, subDomain, fieldType, target, ttl: 3600 });

describe('the shipped policy', () => {
  test('loads and validates', async () => {
    const policy = await loadPolicy();
    assert.equal(policy.version, 1);
  });

  test('declares every check predicate the engine implements, in every profile', () => {
    // Rule 5, on the real file. Adding a control to lib/checks.mjs fails this
    // until somebody decides what it does on each of the three states.
    for (const [name, profile] of Object.entries(shipped.profiles)) {
      assert.deepEqual(
        Object.keys(profile.checks).sort(),
        Object.keys(CHECKS).sort(),
        `profile ${name} does not cover the catalogue`,
      );
    }
  });

  test('covers every classifier state exactly once', () => {
    const claimed = Object.values(shipped.profiles).flatMap((p) => p.states);
    assert.deepEqual(claimed.sort(), [...CLASSIFIER_STATES].sort());
  });

  test('the `off` entries reproduce the scope table exactly', () => {
    // The migration proof. `SCOPES` decided applicability in code; the profiles
    // decide it in data. If these ever drift, a control silently starts or
    // stops being scored on a whole class of domains.
    for (const [name, profile] of Object.entries(shipped.profiles)) {
      for (const state of profile.states) {
        const offInConfig = Object.entries(profile.checks)
          .filter(([, entry]) => entry.remedy.action === 'off').map(([id]) => id).sort();
        const outOfScope = CONTROLS
          .filter((c) => !SCOPES[c.scope].includes(state)).map((c) => c.id).sort();
        assert.deepEqual(offInConfig, outOfScope, `profile ${name} (${state})`);
      }
    }
  });

  test('every record template recognises itself, so nothing churns', () => {
    // Rule 9 on the real file: a template that fails to reconcile against its
    // own published value is deleted and recreated on every single run.
    for (const [id, t] of Object.entries(shipped.records)) {
      assert.ok(sameRecord({ subDomain: t.subDomain, fieldType: t.fieldType, target: t.target }, t),
        `${id} does not reconcile against itself`);
    }
  });

  test('every template names a displacer that exists', () => {
    for (const [id, t] of Object.entries(shipped.records)) {
      assert.ok(Object.hasOwn(DISPLACERS, t.displaces), `${id} names the unknown displacer ${t.displaces}`);
    }
  });

  test('the mail-active profile writes nothing at all', () => {
    // Invariant #3, second lock. The first is the refusal in `harden`, keyed on
    // the classified state; this one means even a --force that lifted the guard
    // produces an empty plan.
    for (const [id, entry] of Object.entries(shipped.profiles['mail-active'].checks)) {
      assert.ok(!WRITING_ACTIONS.has(entry.remedy.action),
        `${id} would write on a domain that sends real mail (action: ${entry.remedy.action})`);
    }
  });

  test('no profile removes a CAA record', () => {
    // Invariant #9. A bare CAA deletion LOOSENS the zone: with no CAA at all,
    // every publicly trusted CA may issue.
    for (const [name, profile] of Object.entries(shipped.profiles)) {
      for (const [id, entry] of Object.entries(profile.checks)) {
        if (entry.remedy.action !== 'remove') continue;
        assert.notEqual(shipped.records[entry.remedy.record].fieldType, 'CAA', `${name}/${id}`);
      }
    }
  });
});

describe('validatePolicy', () => {
  test('accepts the shipped file', () => {
    assert.doesNotThrow(() => validatePolicy(clone(), { path: 'test' }));
  });

  test('refuses an unknown top-level key', () => {
    // A misspelt section is otherwise silently ignored, and its contents vanish.
    refuses((c) => { c.profiless = c.profiles; }, 'profiless');
  });

  test('refuses an unsupported schema version', () => {
    refuses((c) => { c.version = 99; }, 'version');
  });

  test('refuses an unknown check id and suggests the nearest one', () => {
    const problem = refuses((c) => {
      c.profiles.dormant.checks['dmarc.presnt'] = { remedy: { action: 'report' } };
    }, 'profiles.dormant.checks["dmarc.presnt"]');
    assert.equal(problem.hint, 'did you mean "dmarc.present"?');
  });

  test('lists the catalogue when the id is too mangled to guess', () => {
    const problem = refuses((c) => {
      c.profiles.dormant.checks['dmarc.aprex.missing.entirely'] = { remedy: { action: 'report' } };
    }, 'profiles.dormant.checks["dmarc.aprex.missing.entirely"]');
    assert.match(problem.hint, /^known checks: caa\.issue-deny, /);
  });

  test('refuses a profile missing one of the checks', () => {
    refuses((c) => { delete c.profiles.dormant.checks['spf.hardfail']; },
      'profiles.dormant.checks["spf.hardfail"]');
  });

  test('refuses an action that is not in the closed set', () => {
    refuses((c) => { c.profiles.dormant.checks['spf.hardfail'].remedy = { action: 'delete' }; },
      'profiles.dormant.checks["spf.hardfail"].remedy.action');
  });

  test('refuses a remedy naming a record that does not exist, and lists the ones that do', () => {
    const problem = refuses((c) => {
      c.profiles.dormant.checks['spf.hardfail'].remedy = { action: 'enforce', record: 'spf.dney' };
    }, 'profiles.dormant.checks["spf.hardfail"].remedy.record');
    assert.match(problem.hint, /spf\.deny/);
  });

  test('refuses a record naming a displacer the code does not define', () => {
    // The load-bearing rule: config picks a predicate from a closed table, it
    // never writes one. No config edit can widen what a deletion reaches.
    refuses((c) => { c.records['spf.deny'].displaces = 'everything'; }, 'records["spf.deny"].displaces');
  });

  test('refuses removing a CAA record without publishing one', () => {
    // Invariant #9 as a load-time assertion, not a special case in planZone.
    refuses((c) => {
      c.profiles.dormant.checks['caa.no-permissive'].remedy = { action: 'remove', record: 'caa.deny-issue' };
    }, 'profiles.dormant.checks["caa.no-permissive"].remedy');
  });

  test('refuses a template that would churn the zone on every run', () => {
    // Padding and stray quotes are published verbatim, and the record never
    // matches the policy again: deleted and recreated on every single run.
    const problem = refuses((c) => { c.records['spf.deny'].target = '  v=spf1   -all  '; },
      'records["spf.deny"].target');
    assert.match(problem.message, /write "v=spf1 -all"/);
    refuses((c) => { c.records['spf.deny'].target = '"v=spf1 -all"'; }, 'records["spf.deny"].target');
  });

  test('refuses a keep pattern written as a string', () => {
    const problem = refuses((c) => { c.defaults.keep = ['site-verification']; }, 'defaults.keep[0]');
    assert.match(problem.hint, /site-verification\/i/);
  });

  test('refuses a keep pattern that matches everything', () => {
    // It looks like a narrow exception and silently disables every deletion.
    for (const universal of [/.*/, /^/, new RegExp('')]) {
      refuses((c) => { c.defaults.keep = [universal]; }, 'defaults.keep[0]');
    }
  });

  test('refuses a TTL below the OVH floor', () => {
    refuses((c) => { c.defaults.ttl = 30; }, 'defaults.ttl');
    refuses((c) => { c.defaults.ttl = 3600.5; }, 'defaults.ttl');
  });

  test('refuses a per-domain override with no written justification', () => {
    refuses((c) => {
      c.domains['client.example'] = { checks: { 'caa.issue-deny': { remedy: { action: 'off' }, reason: 'x' } } };
    }, 'domains["client.example"].reason');
  });

  test('refuses an override pinning a profile that does not exist', () => {
    refuses((c) => {
      c.domains['client.example'] = { profile: 'dormnat', reason: 'typo on purpose' };
    }, 'domains["client.example"].profile');
  });

  test('refuses an `off` with no reason — an untraceable hole in the audit', () => {
    refuses((c) => { c.profiles.dormant.checks['caa.present'] = { remedy: { action: 'off' } }; },
      'profiles.dormant.checks["caa.present"]');
  });

  test('refuses a state left uncovered by every profile', () => {
    refuses((c) => { c.profiles.dormant.states = []; }, 'profiles');
  });

  test('refuses two profiles claiming the same state', () => {
    refuses((c) => { c.profiles['web-active'].states = ['dormant']; }, 'profiles.web-active.states');
  });

  test('reports every problem in one throw', () => {
    // A 69-entry file with three typos must not cost three round trips.
    const problems = problemsFrom((c) => {
      c.version = 99;
      c.defaults.ttl = 1;
      c.profiles.dormant.checks['spf.hardfail'].remedy = { action: 'enforce', record: 'spf.dney' };
    });
    assert.ok(problems.length >= 3, `expected at least 3 problems, got ${problems.length}`);
  });

  test('the message says nothing was read or written', () => {
    // An operator who sees this mid-batch needs to know no zone was touched.
    try {
      validatePolicy({ version: 99 }, { path: 'config/policy.mjs' });
      assert.fail('should have thrown');
    } catch (err) {
      assert.match(err.message, /Nothing was read from OVH and nothing was written/);
      assert.match(err.message, /config\/policy\.mjs/);
    }
  });
});

describe('loadPolicy', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ovh-policy-'));

  test('a file that cannot be parsed is a policy error, not a stack trace', async () => {
    const path = join(tmp, 'broken.mjs');
    writeFileSync(path, 'export default {');
    await assert.rejects(() => loadPolicy(path), (err) => {
      assert.ok(err instanceof PolicyError);
      assert.match(err.message, /cannot be loaded/);
      return true;
    });
  });

  test('a file with no default export is refused', async () => {
    const path = join(tmp, 'empty.mjs');
    writeFileSync(path, 'export const nope = 1;');
    await assert.rejects(() => loadPolicy(path), PolicyError);
  });
});

describe('resolvePolicy', () => {
  test('picks the profile from the classifier state', () => {
    for (const state of CLASSIFIER_STATES) {
      assert.equal(resolvePolicy([], { state, policy: shipped }).profile, state);
    }
  });

  test('keep patterns union across the three levels, never replace', () => {
    // Invariant #7. With replacement semantics a per-domain block written to
    // add one pattern silently drops every default, and the failure — a deleted
    // `_acme-challenge` — surfaces at the next renewal on a domain nobody
    // is watching.
    const config = clone();
    config.domains['client.example'] = { keep: [/^"?bigco-verify/i], reason: 'ticket OPS-1' };
    const resolved = resolvePolicy([], { domain: 'client.example', state: 'dormant', policy: config });

    assert.equal(resolved.keep.length, config.defaults.keep.length + 1);
    for (const pattern of config.defaults.keep) {
      assert.ok(resolved.keep.some((k) => k.source === pattern.source), `lost the default ${pattern}`);
    }
    assert.ok(resolved.keep.some((k) => /bigco-verify/.test(k.source)));
  });

  test('the same pattern at two levels is not duplicated', () => {
    const config = clone();
    config.domains['client.example'] = { keep: [/_acme-challenge/i], reason: 'ticket OPS-2' };
    const resolved = resolvePolicy([], { domain: 'client.example', state: 'dormant', policy: config });
    assert.equal(resolved.keep.length, config.defaults.keep.length);
  });

  test('a per-domain override replaces one check and says where it came from', () => {
    const config = clone();
    config.domains['client.example'] = {
      checks: { 'spf.hardfail': { remedy: { action: 'off' }, reason: 'migrating senders — OPS-4412' } },
      reason: 'migration in progress',
    };
    const resolved = resolvePolicy([], { domain: 'client.example', state: 'dormant', policy: config });

    assert.equal(resolved.checks['spf.hardfail'].remedy.action, 'off');
    assert.equal(resolved.checks['spf.hardfail'].source, 'domains["client.example"]');
    // Untouched checks still come from the profile.
    assert.equal(resolved.checks['dmarc.reject'].source, 'profiles.dormant');
    assert.equal(resolved.overrideReason, 'migration in progress');
  });

  test('an override only applies to the domain it names', () => {
    const config = clone();
    config.domains['client.example'] = {
      checks: { 'spf.hardfail': { remedy: { action: 'off' }, reason: 'OPS-4412' } },
      reason: 'migration in progress',
    };
    const other = resolvePolicy([], { domain: 'other.example', state: 'dormant', policy: config });
    assert.equal(other.checks['spf.hardfail'].remedy.action, 'enforce');
  });

  test('a CAA remedy is demoted to `report` on a zone where a deny is unsafe', () => {
    // R2: one predicate, two consumers. Before this, the audit could call the
    // CAA controls `na` while the writer went ahead and published the deny.
    const config = clone();
    config.profiles.dormant.checks['caa.issue-deny'].remedy = { action: 'enforce', record: 'caa.deny-issue' };

    const live = [{ name: '@', type: 'A', rdata: '203.0.113.9' }];
    const resolved = resolvePolicy(live, { domain: 'client.example', state: 'dormant', policy: config });

    assert.equal(resolved.checks['caa.issue-deny'].remedy.action, 'report');
    assert.equal(resolved.checks['caa.issue-deny'].demotedFrom, 'enforce');
    assert.match(resolved.checks['caa.issue-deny'].demotionReason, /still resolves to a live host/);
  });

  test('the same CAA remedy survives on a zone where the deny is safe', () => {
    const config = clone();
    config.profiles.dormant.checks['caa.issue-deny'].remedy = { action: 'enforce', record: 'caa.deny-issue' };
    const parked = [{ name: '@', type: 'A', rdata: '213.186.33.5' }];
    const resolved = resolvePolicy(parked, { domain: 'client.example', state: 'dormant', policy: config });

    assert.equal(resolved.checks['caa.issue-deny'].remedy.action, 'enforce');
    assert.equal(resolved.checks['caa.issue-deny'].demotedFrom, null);
  });

  test('a non-CAA remedy is never demoted, whatever the zone looks like', () => {
    const live = [{ name: '@', type: 'A', rdata: '203.0.113.9' }];
    const resolved = resolvePolicy(live, { domain: 'client.example', state: 'dormant', policy: shipped });
    assert.equal(resolved.checks['spf.hardfail'].remedy.action, 'enforce');
  });
});

describe('planFromFindings', () => {
  /** Evaluate a zone, resolve the policy for it, and derive the plan inputs. */
  function inputs(zone, { state = 'dormant', policy = shipped } = {}) {
    const view = zone.map(toZoneShape);
    const report = evaluate(view, { domain: 'client.example', state });
    const resolved = resolvePolicy(view, { domain: 'client.example', state, policy });
    return { resolved, ...planFromFindings(report, resolved, zone) };
  }

  test('only a failing check grants anything', () => {
    // A zone already carrying the whole policy has nothing to license.
    const hardened = [
      rec('', 'TXT', '"v=spf1 -all"'),
      rec('_dmarc', 'TXT', '"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"'),
      rec('*._domainkey', 'TXT', '"v=DKIM1; p="'),
    ];
    const { wanted, licences } = inputs(hardened);
    assert.deepEqual(licences.map((l) => l.checkId), []);
    assert.deepEqual(wanted, []);
  });

  test('three checks wanting the same record produce one creation, attributed to all three', () => {
    const { wanted } = inputs([rec('', 'TXT', '"v=spf1 ~all"')]);
    const spf = wanted.filter((w) => w.record === 'spf.deny');
    assert.equal(spf.length, 1, 'the same record must not be created three times');
    assert.ok(spf[0].wantedBy.includes('spf.hardfail'));
  });

  test('every licence names the check that granted it', () => {
    const { licences } = inputs([rec('', 'TXT', '"v=spf1 ~all"'), rec('', 'MX', '10 mx1.mail.ovh.net.')]);
    for (const licence of licences) {
      assert.ok(Object.hasOwn(CHECKS, licence.checkId), `${licence.checkId} is not a check`);
      assert.ok(ACTIONS.includes(licence.action));
      assert.ok(licence.reason);
    }
  });

  test('`remove` licenses the deletion and publishes nothing', () => {
    // `mx.closed` deletes the apex MX. Publishing a null MX is a separate,
    // opt-in decision — OVH refuses the record on some zones.
    const { wanted, licences } = inputs([rec('', 'MX', '10 mx1.mail.ovh.net.')]);
    assert.ok(licences.some((l) => l.checkId === 'mx.closed' && l.action === 'remove'));
    assert.equal(wanted.filter((w) => w.fieldType === 'MX').length, 0);
  });

  test('`add` on an exclusive record refuses rather than publish a duplicate', () => {
    // dmarc.present fails at zero records AND at two. A naive `add` would
    // publish a third, and receivers discard the policy entirely past one
    // (RFC 7489 §6.6.3) — strictly worse than what was already there.
    const config = clone();
    config.profiles.dormant.checks['dmarc.present'].remedy = { action: 'add', record: 'dmarc.reject' };
    // Isolate the `add`: the other DMARC checks enforce the same template, and
    // an enforce publishes regardless because it removes the competitor first.
    for (const id of ['dmarc.reject', 'dmarc.subdomain-reject', 'dmarc.strict-alignment']) {
      config.profiles.dormant.checks[id].remedy = { action: 'report' };
    }

    const zone = [rec('_dmarc', 'TXT', '"v=DMARC1; p=none"'), rec('_dmarc', 'TXT', '"v=DMARC1; p=quarantine"')];
    const { wanted, conflicts } = inputs(zone, { policy: config });

    assert.equal(wanted.filter((w) => w.subDomain === '_dmarc').length, 0);
    assert.ok(conflicts.some((c) => c.checkId === 'dmarc.present'));
    assert.equal(conflicts.find((c) => c.checkId === 'dmarc.present').competing.length, 2);
  });

  test('`add` on a non-exclusive record publishes alongside what is there', () => {
    // The DKIM wildcard revocation coexists with named selectors on purpose:
    // removing those is dkim.no-live-selector's job, and it is a `critical`.
    const { wanted, conflicts } = inputs([rec('sel1._domainkey', 'TXT', '"v=DKIM1; p=MIGfMA0G"')]);
    assert.ok(wanted.some((w) => w.record === 'dkim.revoke'));
    assert.deepEqual(conflicts, []);
  });

  test('a mail-active zone yields no licence and nothing to publish', () => {
    // Invariant #3. Even if --force lifted the refusal, there is nothing to do.
    const zone = [rec('', 'MX', '10 mx1.mail.ovh.net.'), rec('', 'TXT', '"v=spf1 include:spf.ovh.net ~all"')];
    const { wanted, licences } = inputs(zone, { state: 'mail-active' });
    assert.deepEqual(wanted, []);
    assert.deepEqual(licences, []);
  });
});

describe('the findings-driven plan', () => {
  /** The full path: evaluate -> resolve -> derive -> plan. */
  function planFor(zone, { state = 'dormant', policy = shipped, domain = 'client.example' } = {}) {
    const view = zone.map(toZoneShape);
    const report = evaluate(view, { domain, state });
    const resolved = resolvePolicy(view, { domain, state, policy });
    const { wanted, licences } = planFromFindings(report, resolved, zone);
    return planZone(zone, {
      wanted,
      licences,
      keepPatterns: resolved.keep,
      dropCnames: resolved.dropCnames,
      dropRedirect: resolved.dropRedirect,
    });
  }

  const asFetched = (r) => rec(r.subDomain, r.fieldType, r.target);

  test('every deletion names the finding that licensed it', () => {
    const plan = planFor([rec('', 'TXT', '"v=spf1 ~all"'), rec('', 'MX', '10 mx1.mail.ovh.net.')]);
    for (const deleted of plan.delete) {
      assert.ok(deleted.checkId, `${deleted.label} was deleted without naming a check`);
      assert.match(deleted.reason, new RegExp(`^${deleted.checkId} \\(`));
    }
  });

  test('a domain-verification TXT survives the hardening that used to delete it', () => {
    // The contradiction this refactor resolves: `txt.no-stale-verification`
    // told you to keep these records while `harden` deleted every apex TXT.
    // The tool advised protecting the zone from itself.
    const plan = planFor([rec('', 'TXT', '"v=spf1 ~all"'), rec('', 'TXT', '"MS=ms12345678"')]);
    const labels = plan.delete.map((r) => r.label);
    assert.ok(!labels.some((l) => l.includes('MS=ms12345678')), `deleted: ${labels.join(' | ')}`);
    assert.ok(labels.some((l) => l.includes('v=spf1 ~all')));
  });

  test('a delegated sending subdomain survives every remedy', () => {
    // Invariant #10, end to end rather than at the displacer.
    const mg = [
      rec('mg', 'MX', '10 mxa.eu.mailgun.org.'),
      rec('mg', 'TXT', '"v=spf1 include:mailgun.org ~all"'),
      rec('_dmarc.mg', 'TXT', '"v=DMARC1; p=none"'),
      rec('email._domainkey.mg', 'TXT', '"k=rsa; p=MIGfMA0G"'),
    ];
    const plan = planFor([...mg, rec('', 'MX', '10 mx1.mail.ovh.net.')]);
    assert.deepEqual(plan.delete.map((r) => r.subDomain || '@'), ['@']);
  });

  test('an existing CAA survives a profile with no CAA remedy', () => {
    // Invariant #9, structurally: no CAA in `wanted` means no CAA licence,
    // which means nothing can reach a CAA record.
    const plan = planFor([rec('', 'CAA', '0 issue "letsencrypt.org"'), rec('', 'TXT', '"v=spf1 ~all"')]);
    assert.ok(!plan.delete.some((r) => r.fieldType === 'CAA'));
  });

  test('a CAA deny never removes the tag it is not replacing', () => {
    // R3: a profile publishing only `issue` must not take a permissive
    // `issuewild` down with it and leave nothing in its place.
    const config = clone();
    config.profiles.dormant.checks['caa.issue-deny'].remedy = { action: 'enforce', record: 'caa.deny-issue' };

    const zone = [
      rec('', 'CAA', '0 issue "letsencrypt.org"'),
      rec('', 'CAA', '0 issuewild "letsencrypt.org"'),
    ];
    const plan = planFor(zone, { policy: config });
    assert.deepEqual(plan.delete.map((r) => r.label), ['@ CAA 0 issue "letsencrypt.org"']);
  });

  test('a keep pattern wins over a licence', () => {
    // Invariant #7. The record stays, and the plan still shows it.
    const config = clone();
    config.defaults.keep = [...config.defaults.keep, /v=spf1 ~all/];
    const plan = planFor([rec('', 'TXT', '"v=spf1 ~all"')], { policy: config });
    assert.deepEqual(plan.delete, []);
    assert.ok(plan.keep.some((r) => r.reason === 'protected by --keep'));
  });

  test('a mail-active zone produces an empty plan', () => {
    const zone = [rec('', 'MX', '10 mx1.mail.ovh.net.'), rec('', 'TXT', '"v=spf1 include:spf.ovh.net ~all"')];
    const plan = planFor(zone, { state: 'mail-active' });
    assert.deepEqual([plan.delete, plan.create], [[], []]);
  });

  const FIXTURES = {
    empty: [],
    'permissive mail records': [
      rec('', 'TXT', '"v=spf1 ~all"'),
      rec('_dmarc', 'TXT', '"v=DMARC1; p=none"'),
      rec('sel1._domainkey', 'TXT', '"v=DKIM1; p=MIGfMA0G"'),
      rec('', 'MX', '10 mx1.mail.ovh.net.'),
    ],
    'parked with a redirect': [
      rec('', 'A', '213.186.33.5'),
      rec('www', 'TXT', '"3|www.client.example"'),
      rec('ftp', 'CNAME', 'client.example.'),
    ],
    'delegated sending subdomain': [
      rec('mg', 'MX', '10 mxa.eu.mailgun.org.'),
      rec('email._domainkey.mg', 'TXT', '"k=rsa; p=MIGfMA0G"'),
    ],
    'verification records': [
      rec('', 'TXT', '"MS=ms12345678"'),
      rec('', 'TXT', '"google-site-verification=abc"'),
      rec('_acme-challenge', 'TXT', '"token"'),
    ],
  };

  test('applying a plan and re-planning changes nothing', () => {
    // Invariant #4, across the fixture table. This is the one that breaks
    // silently: a check that still fails keeps its licence, and that licence
    // matches the record the policy has just published. The reconciliation
    // phase is what catches the self-match — without it every run would churn
    // the zone and reset every TTL.
    for (const [name, zone] of Object.entries(FIXTURES)) {
      for (const state of ['dormant', 'web-active']) {
        const first = planFor(zone, { state });
        const after = [
          ...first.keep.filter((r) => r.reason !== 'already compliant'),
          ...first.create,
        ].map(asFetched);
        const second = planFor(after, { state });
        assert.deepEqual([second.delete.map((r) => r.label), second.create.map((r) => r.target)], [[], []],
          `${name} / ${state} still churns`);
      }
    }
  });

  test('a fully hardened dormant zone leaves exactly these checks failing', () => {
    // Pinned literally so any drift shows up in a diff. All four are deliberate
    // opt-ins the shipped config leaves as `report`: publishing a null MX and
    // denying certificate issuance are decisions an operator makes per domain,
    // not defaults a batch run applies at 3am.
    const plan = planFor([]);
    const published = plan.create.map(asFetched).map(toZoneShape);
    const failing = evaluate(published, { domain: 'client.example', state: 'dormant' })
      .controls.filter((c) => c.status === 'fail').map((c) => c.id).sort();

    assert.deepEqual(failing, ['caa.issue-deny', 'caa.issuewild-deny', 'caa.present', 'mx.null-explicit']);
  });

  test('the records a profile publishes never make a hardened zone stop being dormant', () => {
    // Invariant #5, structurally rather than as three frozen cases. Otherwise
    // somebody adds a template to the config and every hardened zone in the
    // portfolio re-enters the worklist for ever.
    for (const state of ['dormant', 'web-active']) {
      const plan = planFor([], { state });
      const published = plan.create.map(asFetched).map(toZoneShape);
      const report = evaluate(published, { domain: 'client.example' });
      assert.equal(report.state, 'dormant', `the ${state} profile publishes records that re-classify the zone`);
    }
  });

  test('the two zone views agree on every fixture', () => {
    // evaluate() reads the parseZone shape and planZone the OVH API shape. Now
    // that a deletion is licensed by a finding, a disagreement between the two
    // means a record deleted on the strength of a verdict computed about a
    // different rendering of that same record.
    for (const [name, zone] of Object.entries(FIXTURES)) {
      const viaApi = evaluate(zone.map(toZoneShape), { domain: 'client.example', state: 'dormant' });
      const viaZoneFile = evaluate(
        zone.map((r) => ({ name: r.subDomain || '@', type: r.fieldType, rdata: r.target })),
        { domain: 'client.example', state: 'dormant' },
      );
      assert.deepEqual(
        viaApi.controls.map((c) => [c.id, c.status]),
        viaZoneFile.controls.map((c) => [c.id, c.status]),
        `the two views disagree on ${name}`,
      );
    }
  });
});
