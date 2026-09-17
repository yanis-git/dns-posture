// The bridge between the policy file and the engine.
//
// `config/policy.mjs` is data: it says, per check, what to do when that check
// fails. This module loads it, refuses it if it is wrong, resolves it against
// one domain, and turns a compliance report into the two inputs `planZone`
// needs — the records to publish and the licences to delete.
//
// The division of responsibility is the whole point of the refactor:
//
//   the config decides WHETHER a deletion happens (which checks get a remedy)
//   the code decides HOW FAR it reaches (DISPLACERS, in ./zone.mjs)
//
// A config names a displacer key; it cannot write a predicate. `validatePolicy`
// refuses an unknown key, so no edit to the policy file can widen what a
// deletion touches — the worst an operator can do is enable or disable one of
// the predicates that were reviewed when they were written.

import { pathToFileURL } from 'node:url';
import { policyFile } from './config.mjs';
import { CHECKS } from './checks.mjs';
import { DISPLACERS, caaBlocker, isTextual, normalize, parseCaa, recordLabel, sameRecord } from './zone.mjs';

/** The classifier states a profile may claim. `error` is a CLI artefact, not a posture. */
export const CLASSIFIER_STATES = ['dormant', 'web-active', 'mail-active'];

export const ACTIONS = ['add', 'enforce', 'remove', 'manual', 'report', 'off'];

/** The three actions that touch DNS. Greppable in two words, on purpose. */
export const WRITING_ACTIONS = new Set(['add', 'enforce', 'remove']);

const TOP_LEVEL = ['version', 'defaults', 'records', 'checks', 'profiles', 'domains'];
const DEFAULT_KEYS = ['ttl', 'keep', 'dropCnames', 'dropRedirect'];
const SUPPORTED_VERSIONS = [1];

/** OVH's floor. A shorter TTL is rejected by the API, per record, mid-run. */
const MIN_TTL = 60;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Every problem in the file, in one throw.
 *
 * A 69-entry config with three typos must not cost three round trips, and a
 * typo must never be a warning: a remedy silently ignored is a deletion that
 * happens, or does not happen, for a reason nobody can see.
 */
export class PolicyError extends Error {
  constructor(path, problems) {
    const body = problems.map(({ key, message, hint }) => {
      const lines = [`  ${key || '(root)'}`, `      ${message}`];
      if (hint) lines.push(`      ${hint}`);
      return lines.join('\n');
    }).join('\n');
    super(`policy: ${problems.length} problem${problems.length === 1 ? '' : 's'} in ${path}\n\n${body}\n\n`
      + '  Nothing was read from OVH and nothing was written. Fix the file and re-run.');
    this.name = 'PolicyError';
    this.problems = problems;
    this.path = path;
  }
}

// Nearest-neighbour suggestion: a wrong check id is almost always a typo, and
// the catalogue is two dozen entries nobody has memorised.
function distance(a, b) {
  const rows = [...Array(b.length + 1).keys()].map((i) => [i]);
  for (let j = 0; j <= a.length; j++) rows[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + (a[j - 1] === b[i - 1] ? 0 : 1),
      );
    }
  }
  return rows[b.length][a.length];
}

function nearest(needle, haystack) {
  let best = null;
  let bestScore = Infinity;
  for (const candidate of haystack) {
    const d = distance(needle, candidate);
    if (d < bestScore) { best = candidate; bestScore = d; }
  }
  // Beyond a third of the length the "suggestion" is noise dressed as help.
  return bestScore <= Math.max(3, Math.ceil(needle.length / 3)) ? best : null;
}

const listOf = (keys) => [...keys].sort().join(', ');

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Refuse a policy file that cannot mean what it says. Throws a PolicyError
 * carrying every problem found; returns nothing when the file is sound.
 *
 * Runs before any client is built and before any credential is read, so a bad
 * file costs an error message and nothing else.
 */
export function validatePolicy(config, { checks = CHECKS, displacers = DISPLACERS, path = '(inline)' } = {}) {
  const problems = [];
  const bad = (key, message, hint) => problems.push({ key, message, hint });
  const stop = () => { throw new PolicyError(path, problems); };

  if (!config || typeof config !== 'object') {
    bad('', 'the policy file must export a configuration object as its default export');
    stop();
  }

  // 1. Unknown top-level key. The typo catcher: a misspelt section is silently
  //    ignored by every "read what I know" loader, and its contents vanish.
  for (const key of Object.keys(config)) {
    if (!TOP_LEVEL.includes(key)) {
      bad(key, 'unknown top-level key', `known keys: ${TOP_LEVEL.join(', ')}`);
    }
  }

  // 2. Schema version.
  if (!SUPPORTED_VERSIONS.includes(config.version)) {
    bad('version', `unsupported schema version ${JSON.stringify(config.version)}`,
      `supported: ${SUPPORTED_VERSIONS.join(', ')}`);
  }

  const defaults = config.defaults ?? {};
  for (const key of Object.keys(defaults)) {
    if (!DEFAULT_KEYS.includes(key)) {
      bad(`defaults.${key}`, 'unknown key', `known keys: ${DEFAULT_KEYS.join(', ')}`);
    }
  }

  // 11. TTL floor. 10. `keep` patterns.
  validateTtl(defaults.ttl, 'defaults.ttl', bad);
  validateKeep(defaults.keep, 'defaults.keep', bad);

  const records = config.records ?? {};
  const recordIds = Object.keys(records);

  for (const [id, template] of Object.entries(records)) {
    const at = `records["${id}"]`;
    if (typeof template.subDomain !== 'string' || typeof template.fieldType !== 'string'
        || typeof template.target !== 'string') {
      bad(at, 'a record needs a string subDomain, fieldType and target');
      continue;
    }

    // 7. The displacer must be one of the code's own.
    if (!Object.hasOwn(displacers, template.displaces)) {
      bad(`${at}.displaces`, `"${template.displaces}" is not a known displacer`,
        `known displacers: ${listOf(Object.keys(displacers))}`);
      continue;
    }

    // 9. Anti-churn. A template is compared against what is already published
    //    through `sameRecord`, so it has to survive the round trip through OVH
    //    in every form OVH might hand it back. When it does not, every run
    //    reads the record it published last time as "different from the
    //    policy", deletes it and republishes it — on every zone, for ever. The
    //    sixtieth domain is a bad place to discover that.
    //
    //    Textual first: the target must already be in canonical form. Writing
    //    `"v=spf1 -all"` with the quotes, or with padding, sends those bytes to
    //    OVH, which quotes what it stores — so the zone ends up carrying a
    //    record the policy no longer recognises.
    if (isTextual(template.fieldType) && normalize(template.target) !== template.target) {
      bad(`${at}.target`, `is not in canonical form: write ${JSON.stringify(normalize(template.target))}`,
        'OVH quotes what it stores, so the extra quoting or padding is published verbatim and never matches again');
    }

    //    CAA second: its stored and exported forms are undocumented, and a zone
    //    export loses the `;` of an unquoted `0 issue ;` to the comment
    //    stripper before it is ever parsed.
    for (const variant of quotingVariants(template)) {
      const asStored = { subDomain: template.subDomain, fieldType: template.fieldType, target: variant };
      if (!sameRecord(asStored, template)) {
        bad(`${at}.target`, `does not reconcile against its own value stored as ${JSON.stringify(variant)}`,
          'the plan would delete and republish this record on every single run');
      }
    }
  }

  // The catalogue must be the catalogue the engine implements: a check with no
  // predicate is never evaluated, and a predicate with no entry is unscored.
  const declared = Object.keys(config.checks ?? {});
  for (const id of declared) {
    if (!Object.hasOwn(checks, id)) {
      const guess = nearest(id, Object.keys(checks));
      bad(`checks["${id}"]`, 'no check predicate has this id',
        guess ? `did you mean "${guess}"?` : `known checks: ${listOf(Object.keys(checks))}`);
    }
  }
  for (const id of Object.keys(checks)) {
    if (!declared.includes(id)) {
      bad(`checks["${id}"]`, 'missing from the catalogue — every check predicate needs its audit metadata');
    }
  }

  const profiles = config.profiles ?? {};
  const profileNames = Object.keys(profiles);
  const claimed = new Map();

  for (const [name, profile] of Object.entries(profiles)) {
    const at = `profiles.${name}`;
    const states = profile.states ?? [];
    if (!Array.isArray(states)) {
      bad(`${at}.states`, 'must be an array of classifier states');
    } else {
      for (const state of states) {
        if (!CLASSIFIER_STATES.includes(state)) {
          const guess = nearest(String(state), CLASSIFIER_STATES);
          bad(`${at}.states`, `"${state}" is not a classifier state`,
            guess ? `did you mean "${guess}"?` : `states: ${CLASSIFIER_STATES.join(', ')}`);
          continue;
        }
        // Two profiles claiming one state makes the iteration order decide the
        // policy, and the order of object keys is not a decision anyone made.
        if (claimed.has(state)) bad(`${at}.states`, `"${state}" is already claimed by profiles.${claimed.get(state)}`);
        else claimed.set(state, name);
      }
    }

    validateTtl(profile.ttl, `${at}.ttl`, bad);
    validateKeep(profile.keep, `${at}.keep`, bad);
    validateChecks(profile.checks ?? {}, at, { checks, records, recordIds, displacers, bad, requireComplete: true });
  }

  // 3. Every classifier state must reach a profile, or a domain in that state
  //    has no policy at all and the run fails at the worst possible moment.
  for (const state of CLASSIFIER_STATES) {
    if (!claimed.has(state)) {
      bad('profiles', `no profile covers the classifier state "${state}"`,
        `profiles must cover: ${CLASSIFIER_STATES.join(', ')}`);
    }
  }

  for (const [domain, override] of Object.entries(config.domains ?? {})) {
    const at = `domains["${domain}"]`;
    // 12. An exception to a tool that deletes DNS needs a written reason.
    //     Requiring one at load time is free, and it is what turns a gap in the
    //     audit into a documented decision.
    if (typeof override.reason !== 'string' || !override.reason.trim()) {
      bad(`${at}.reason`, 'a per-domain override needs a written justification',
        'e.g. reason: "LE certificate live until 2027 — ticket OPS-4412"');
    }
    if (override.profile !== undefined && !profileNames.includes(override.profile)) {
      const guess = nearest(String(override.profile), profileNames);
      bad(`${at}.profile`, `"${override.profile}" is not a defined profile`,
        guess ? `did you mean "${guess}"?` : `profiles: ${listOf(profileNames)}`);
    }
    validateTtl(override.ttl, `${at}.ttl`, bad);
    validateKeep(override.keep, `${at}.keep`, bad);
    validateChecks(override.checks ?? {}, at, { checks, records, recordIds, displacers, bad, requireComplete: false });
  }

  if (problems.length) stop();
}

function validateTtl(ttl, key, bad) {
  if (ttl === undefined) return;
  if (!Number.isInteger(ttl) || ttl < MIN_TTL) {
    bad(key, `must be an integer of at least ${MIN_TTL} seconds, got ${JSON.stringify(ttl)}`,
      'OVH rejects a shorter TTL, and it would be rejected per record, mid-run');
  }
}

function validateKeep(keep, key, bad) {
  if (keep === undefined) return;
  if (!Array.isArray(keep)) { bad(key, 'must be an array of regular expressions'); return; }
  for (const [i, pattern] of keep.entries()) {
    if (!(pattern instanceof RegExp)) {
      bad(`${key}[${i}]`, `must be a RegExp, got ${JSON.stringify(pattern)}`,
        'write /site-verification/i, not \'site-verification\'');
      continue;
    }
    // A pattern that matches the empty string matches every record, which
    // disables every deletion while looking like a narrow exception.
    if (pattern.test('')) {
      bad(`${key}[${i}]`, `${pattern} matches everything, which silently disables every deletion`,
        'anchor it — or if nothing should be written here, use a profile with no write remedies');
    }
  }
}

function validateChecks(entries, at, { checks, records, recordIds, displacers, bad, requireComplete }) {
  for (const [id, entry] of Object.entries(entries)) {
    const key = `${at}.checks["${id}"]`;

    // 4. Unknown check id, with a suggestion.
    if (!Object.hasOwn(checks, id)) {
      const guess = nearest(id, Object.keys(checks));
      bad(key, 'unknown check id',
        guess ? `did you mean "${guess}"?` : `known checks: ${listOf(Object.keys(checks))}`);
      continue;
    }

    const remedy = entry?.remedy;
    if (!remedy || typeof remedy !== 'object') { bad(key, 'needs a `remedy: { action: ... }`'); continue; }

    // 6. Closed action set.
    if (!ACTIONS.includes(remedy.action)) {
      const guess = nearest(String(remedy.action), ACTIONS);
      bad(`${key}.remedy.action`, `"${remedy.action}" is not an action`,
        guess ? `did you mean "${guess}"?` : `actions: ${ACTIONS.join(', ')}`);
      continue;
    }

    if (!WRITING_ACTIONS.has(remedy.action)) {
      if (remedy.record !== undefined) {
        bad(`${key}.remedy`, `action "${remedy.action}" writes nothing, so it must not name a record`);
      }
      // `off` takes a check out of the score. Saying why is the difference
      // between a documented exception and a hole in the audit.
      if (remedy.action === 'off' && !String(entry.reason ?? '').trim()) {
        bad(key, 'an `off` check needs a `reason` — it is excluded from the score, and the report shows why');
      }
      continue;
    }

    if (!recordIds.includes(remedy.record)) {
      const guess = nearest(String(remedy.record), recordIds);
      bad(`${key}.remedy.record`, `"${remedy.record}" is not defined`,
        guess ? `did you mean "${guess}"?` : `known records: ${listOf(recordIds)}`);
      continue;
    }

    // 8. Invariant #9 as a load-time assertion. Deleting a CAA without
    //    publishing one LOOSENS the zone: with no CAA at all, every publicly
    //    trusted CA on earth may issue for the name. `enforce` republishes, so
    //    it is fine; `remove` does not, so it is refused here rather than
    //    discovered on somebody's zone.
    const template = records[remedy.record];
    if (remedy.action === 'remove' && template?.fieldType === 'CAA') {
      bad(`${key}.remedy`, 'a CAA record may not be removed without publishing one in its place',
        'deleting the last CAA lets every CA issue for this domain — use "enforce"');
    }
    if (remedy.action === 'remove' && template && !Object.hasOwn(displacers, template.displaces)) {
      bad(`${key}.remedy.record`, `"${remedy.record}" has no usable displacer, so "remove" has nothing to delete`);
    }
  }

  // 5. Explicit profiles: every check, in every profile. Adding a control then
  //    fails validation until someone decides what it does on a dormant, a
  //    web-active and a mail-active domain — at review time, which is the only
  //    time anyone is thinking about it.
  if (requireComplete) {
    for (const id of Object.keys(checks)) {
      if (!Object.hasOwn(entries, id)) {
        bad(`${at}.checks["${id}"]`, 'missing — every check must be declared in every profile',
          'give it a remedy, or `{ remedy: { action: \'off\' }, reason: \'…\' }` if it does not apply here');
      }
    }
  }
}

/**
 * The quoting variants a template must still recognise as itself.
 *
 * Only CAA needs this: OVH's stored and exported forms are undocumented, and a
 * zone export loses the `;` of an unquoted `0 issue ;` to the comment stripper
 * before it is ever parsed.
 */
function quotingVariants(template) {
  const forms = [template.target];
  if (template.fieldType !== 'CAA') return forms;
  const caa = parseCaa(template.target);
  if (!caa) return forms;
  forms.push(
    `${caa.flags} ${caa.tag} "${caa.value}"`,
    `${caa.flags} ${caa.tag} ${caa.value}`,
    `"${caa.flags} ${caa.tag} ${caa.value}"`,
    `${caa.flags} "${caa.tag}" "${caa.value}"`,
  );
  return forms;
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/**
 * Read and validate the policy file.
 *
 * SECURITY: this is a dynamic import, so the policy file is EXECUTED. That is
 * the price of a config holding real regular expressions with no parser
 * dependency; OVH_POLICY_FILE should point only at a file you would run.
 */
export async function loadPolicy(path = policyFile()) {
  let mod;
  try {
    mod = await import(pathToFileURL(path).href);
  } catch (err) {
    throw new PolicyError(path, [{ key: '', message: `cannot be loaded: ${err.message}` }]);
  }
  validatePolicy(mod.default, { path });
  return mod.default;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/**
 * `keep` patterns merge as a UNION across defaults, profile and domain.
 *
 * Never as a replacement. A `keep` pattern is a safety assertion, so the merge
 * has to be monotone on the safe side: with replacement semantics, a per-domain
 * block written to add one pattern would silently drop all the defaults, and
 * the failure — a deleted `_acme-challenge` — surfaces at the next renewal, on
 * a domain nobody is looking at. Invariant #7.
 */
function unionKeep(...levels) {
  const seen = new Set();
  const out = [];
  for (const level of levels) {
    for (const pattern of level ?? []) {
      const key = JSON.stringify([pattern.source, pattern.flags]);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(pattern);
    }
  }
  return out;
}

function profileFor(policy, state) {
  for (const [name, profile] of Object.entries(policy.profiles)) {
    if ((profile.states ?? []).includes(state)) return name;
  }
  return null;
}

/**
 * The effective policy for one domain: which profile applies, what it protects,
 * and what each of the 24 checks does when it fails.
 *
 * `records` is the zone in the {name, type, rdata} shape. It is read for one
 * thing only: deciding whether a certificate-issuance deny is safe here.
 */
export function resolvePolicy(records, { domain = null, state = 'dormant', policy }) {
  const override = (domain && policy.domains?.[domain]) || null;
  const profileName = override?.profile ?? profileFor(policy, state);
  const profile = policy.profiles[profileName];
  if (!profile) throw new Error(`no profile covers the state "${state}" and no override names one`);

  // R2: the same predicate that makes the CAA controls `na` also demotes their
  // remedies. Before 0.3.0 the audit and the writer each held their own copy of
  // this decision and could disagree; now they cannot.
  const blocker = caaBlocker(records, { state });

  const checks = {};
  for (const [id, meta] of Object.entries(policy.checks)) {
    const fromDomain = override?.checks?.[id];
    const entry = fromDomain ?? profile.checks[id];
    const template = entry.remedy.record ? policy.records[entry.remedy.record] : null;

    let remedy = entry.remedy;
    let demotedFrom = null;
    if (template?.fieldType === 'CAA' && WRITING_ACTIONS.has(remedy.action) && blocker) {
      demotedFrom = remedy.action;
      remedy = { action: 'report' };
    }

    checks[id] = {
      id,
      ...meta,
      remedy,
      template,
      reason: entry.reason ?? null,
      // Where this decision came from, so `policy <domain>` can show an
      // override as an override rather than as the way things are.
      source: fromDomain ? `domains["${domain}"]` : `profiles.${profileName}`,
      demotedFrom,
      demotionReason: demotedFrom ? blocker : null,
    };
  }

  return {
    domain,
    state,
    profile: profileName,
    keep: unionKeep(policy.defaults.keep, profile.keep, override?.keep),
    ttl: override?.ttl ?? profile.ttl ?? policy.defaults.ttl,
    // The most specific level WINS here, and does not merge — the opposite of
    // `keep`, on purpose. Both rules are monotone towards safety, and safety
    // points in opposite directions for the two: a `keep` pattern protects, so
    // a level may only add protection; `dropCnames` deletes, so a level must be
    // able to take a deletion away. Union semantics would make it impossible
    // for the mail-active profile, or for a per-domain exception, to say "touch
    // nothing on this zone".
    dropCnames: [...(override?.dropCnames ?? profile.dropCnames ?? policy.defaults.dropCnames ?? [])],
    dropRedirect: override?.dropRedirect ?? profile.dropRedirect ?? policy.defaults.dropRedirect ?? false,
    checks,
    templates: policy.records,
    overrideReason: override?.reason ?? null,
    caaBlocked: blocker,
  };
}

// ---------------------------------------------------------------------------
// Findings -> plan inputs
// ---------------------------------------------------------------------------

/**
 * Turn a compliance report into what `planZone` needs.
 *
 * Only a check that FAILED grants anything. `wanted` is what gets published,
 * `licences` is the permission to delete, and every licence names the check
 * that granted it — which is what puts a finding next to every DELETE line.
 *
 * `records` is the zone in the OVH {subDomain, fieldType, target} shape, read
 * only to decide whether an exclusive `add` would collide.
 */
export function planFromFindings(report, resolved, records = []) {
  const wanted = [];
  const byTarget = new Map();
  const licences = [];
  const conflicts = [];

  for (const control of report.controls) {
    if (control.status !== 'fail') continue;
    const entry = resolved.checks[control.id];
    if (!entry || !WRITING_ACTIONS.has(entry.remedy.action)) continue;

    const { action } = entry.remedy;
    const template = entry.template;
    const displaces = DISPLACERS[template.displaces];

    if (action === 'enforce' || action === 'remove') {
      licences.push({
        checkId: control.id,
        action,
        record: entry.remedy.record,
        reason: action === 'remove'
          ? 'removed, with nothing published in its place'
          : `replaced by ${recordLabel(template)}`,
        displaces,
      });
    }

    if (action === 'remove') continue;

    // An `add` on an exclusive record is a REFUSAL, not a no-op. `dmarc.present`
    // fails at zero records and at two; adding a third would make receivers
    // discard the policy entirely (RFC 7489 §6.6.3), so the zone would end up
    // strictly worse than it started. Same for SPF (PermError, RFC 7208 §4.5)
    // and MX (RFC 7505 §3).
    if (action === 'add' && template.exclusive) {
      const competing = records.filter((r) => displaces(r) && !sameRecord(r, template));
      if (competing.length) {
        conflicts.push({
          checkId: control.id,
          record: entry.remedy.record,
          wanted: recordLabel(template),
          competing: competing.map((r) => recordLabel(r)),
        });
        continue;
      }
    }

    // Deduplicated on the value: spf.present, spf.single and spf.hardfail all
    // want `v=spf1 -all`, and the plan shows one creation attributed to three
    // checks rather than three creations of the same record.
    const key = JSON.stringify([template.subDomain, template.fieldType, template.target]);
    const already = byTarget.get(key);
    if (already) { already.wantedBy.push(control.id); continue; }

    const record = {
      subDomain: template.subDomain,
      fieldType: template.fieldType,
      target: template.target,
      ttl: resolved.ttl,
      why: template.why,
      record: entry.remedy.record,
      wantedBy: [control.id],
    };
    byTarget.set(key, record);
    wanted.push(record);
  }

  return { wanted, licences, conflicts };
}
