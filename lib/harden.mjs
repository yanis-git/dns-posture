// Anti-spoofing hardening policy for dormant domains.
// Goal: the domain can no longer send mail, and nothing is left lying around.
//
// The record vocabulary lives in ./zone.mjs — the shapes, the value readers and
// the safety predicates are shared with the classifier and the check
// predicates, and the three only agree because there is one copy.

import { TEXTUAL_TYPES, isApexPolicyName, recordLabel, sameRecord } from './zone.mjs';

// Re-exported for callers that already import these from here.
export { TEXTUAL_TYPES, recordLabel, sameRecord, isApexPolicyName };
export { parseCaa, normalizeCaa } from './zone.mjs';

export const DEFAULT_CNAMES_TO_DROP = ['ftp'];

export function buildPolicy({ rua = null, nullMx = false, caa = false, iodef = null, ttl = 3600 } = {}) {
  const dmarc = ['v=DMARC1', 'p=reject', 'sp=reject', 'adkim=s', 'aspf=s'];
  if (rua) dmarc.push(`rua=${rua}`);

  // Append only, never insert: callers and tests index into this array.
  const records = [
    { subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all', ttl, why: 'SPF: no authorised sender' },
    { subDomain: '_dmarc', fieldType: 'TXT', target: dmarc.join('; '), ttl, why: 'DMARC: strict reject, subdomains included' },
    { subDomain: '*._domainkey', fieldType: 'TXT', target: 'v=DKIM1; p=', ttl, why: 'DKIM: every key revoked' },
  ];
  if (caa) {
    // Kept for legacy planning only. OvhProvider rejects every CAA write
    // until its target encoding has been verified on a disposable live zone.
    records.push(
      { subDomain: '', fieldType: 'CAA', target: '0 issue ";"', ttl, why: 'CAA: no CA may issue for this domain' },
      { subDomain: '', fieldType: 'CAA', target: '0 issuewild ";"', ttl, why: 'CAA: no wildcard certificate either' },
    );
    if (iodef) {
      records.push({ subDomain: '', fieldType: 'CAA', target: `0 iodef "${iodef}"`, ttl, why: 'CAA: report policy violations' });
    }
  }
  if (nullMx) {
    records.push({ subDomain: '', fieldType: 'MX', target: '0 .', ttl, why: 'Null MX (RFC 7505): the domain receives no mail' });
  }
  return records;
}

/**
 * Fetch every relevant record of a zone.
 */
export async function fetchRecords(ovh, zone) {
  const ids = await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record`);
  if (!Array.isArray(ids) || new Set(ids).size !== ids.length) throw new Error('Incomplete record list');
  const records = [];
  for (const id of ids) records.push(await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record/${id}`));
  return records;
}

/**
 * A record no failing check claimed. The default answer of the new engine is
 * "leave it alone": a deletion has to be licensed, it is never the fallthrough.
 */
export const UNLICENSED = 'no failing check licenses its deletion';

/**
 * Build the plan: what we delete, what we create, what we leave alone.
 *
 *   wanted    records the policy publishes  [{ subDomain, fieldType, target, ttl, why }]
 *   licences  permission to delete          [{ checkId, action, reason, displaces }]
 *
 * A licence is granted by a check that FAILED. `displaces` is one of the
 * closed DISPLACERS predicates in zone.mjs — the config picks which of them
 * apply, it cannot write a new one. Every deletion in the returned plan
 * therefore names the finding that justified it.
 *
 * The order of the rules below is itself an invariant, and the tests pin it:
 *
 *   1. keepPatterns   wins over everything, deletions included
 *   2. redirect marker, before the apex gate so --drop-redirect reaches `www`
 *   3. dropCnames,     before the apex gate: `ftp` is not an apex policy name
 *   4. the apex gate,  unreachable from the config
 *   5. licences
 *   6. keep, unlicensed
 */
export function planZone(records, opts = {}) {
  // Compatibility shim for the flag-driven buildPolicy() shape. Dropped with
  // the flags themselves; see legacyPlan below.
  if (opts.policy) return legacyPlan(records, opts);

  const {
    wanted = [],
    licences = [],
    keepPatterns = [],
    dropCnames = DEFAULT_CNAMES_TO_DROP,
    dropRedirect = false,
  } = opts;

  const del = [];
  const keep = [];

  for (const rec of records) {
    const sub = rec.subDomain || '@';
    const label = recordLabel(rec);

    if (keepPatterns.some((re) => { re.lastIndex = 0; const target = re.test(rec.target); re.lastIndex = 0; return target || re.test(sub); })) {
      keep.push({ ...rec, reason: 'protected by --keep' });
      continue;
    }

    // "1|www.example.com": plumbing of the OVH web redirection service, with
    // nothing to do with mail. Deleting it breaks the redirect: explicit opt-in.
    // Handled before the apex gate — the marker is an OVH mechanism wherever it
    // sits, and --drop-redirect must keep reaching it on www.
    if (TEXTUAL_TYPES.includes(rec.fieldType) && /^"?\d+\|/.test(String(rec.target))) {
      if (!dropRedirect) {
        keep.push({ ...rec, reason: 'OVH redirection marker' });
        continue;
      }
      del.push({ ...rec, label, reason: 'OVH redirection marker (--drop-redirect: the web redirect will break)' });
      continue;
    }
    // A CNAME named on the command line (or `ftp` by default) is a deliberate
    // target, so it is honoured before the apex gate too.
    if (rec.fieldType === 'CNAME' && dropCnames.includes((rec.subDomain || '').toLowerCase())) {
      del.push({ ...rec, label, reason: `useless ${rec.subDomain} CNAME` });
      continue;
    }

    // The apex gate. A licence below deletes a record because it competes with
    // what the policy publishes, which only holds for names the policy owns.
    // Nothing a config can say reaches past this line.
    if (!isApexPolicyName(sub)) {
      // Spell it out for the types that USED to be deleted here: that is the
      // case an operator needs to see explained rather than silently kept.
      const shadowed = rec.fieldType === 'MX' || rec.fieldType === 'CAA' || TEXTUAL_TYPES.includes(rec.fieldType);
      keep.push({ ...rec, reason: shadowed ? `out of scope: ${sub} is not an apex policy name` : 'out of scope' });
      continue;
    }

    if (rec.fieldType === 'CAA' && !wanted.some((r) => r.fieldType === 'CAA')) {
      keep.push({ ...rec, reason: 'CAA retained: no replacement published' });
      continue;
    }
    const licence = licences.find((l) => l.displaces(rec));
    if (licence) {
      del.push({
        ...rec,
        label,
        checkId: licence.checkId,
        action: licence.action,
        reason: `${licence.checkId} (${licence.action}): ${licence.reason}`,
      });
      continue;
    }

    keep.push({ ...rec, reason: UNLICENSED });
  }

  // A record already compliant is neither deleted nor recreated.
  //
  // This loop is load-bearing for idempotence, and it is not obvious why. A
  // check that still fails keeps its licence, and a licence matches the record
  // the policy just published — `apex-spf` matches `v=spf1 -all` as readily as
  // the `v=spf1 ~all` it replaced. That self-match lands in `del`, and this is
  // what catches it. Two tempting "cleanups" both reintroduce churn on every
  // run: filtering `del` before reconciling, and excluding a wanted record from
  // its own displacer. Do neither.
  const create = [];
  const matched = new Set();
  for (const want of wanted) {
    // !r.skip: two policy entries of the same type must not both reconcile
    // against the same existing record.
    const already = del.find((r) => !r.skip && sameRecord(r, want));
    if (already) {
      already.skip = true;
      keep.push({ ...already, reason: 'already compliant' });
      continue;
    }
    const kept = keep.find((r) => !matched.has(r) && sameRecord(r, want));
    if (kept) { matched.add(kept); continue; }
    create.push(want);
  }

  return { delete: del.filter((r) => !r.skip), create, keep };
}

/**
 * TEMPORARY. Translates the flag-driven buildPolicy() array into licences, so
 * the whole existing harden suite keeps passing — unedited — while the engine
 * underneath it is replaced. That the old assertions still hold is the evidence
 * that the licence machinery preserves today's behaviour.
 *
 * Deleted together with buildPolicy and the policy flags.
 */
function legacyPlan(records, { policy, keepPatterns = [], cnamesToDrop = DEFAULT_CNAMES_TO_DROP, dropRedirect = false }) {
  // The old engine deleted by type at the apex, unconditionally. Reproduced
  // here as licences, deliberately broader than the DISPLACERS the config will
  // use: narrowing them is a behaviour change and belongs in its own commit.
  const licences = [
    { checkId: 'legacy.mx', action: 'enforce', reason: 'MX at the apex',
      displaces: (r) => r.fieldType === 'MX' },
    { checkId: 'legacy.textual', action: 'enforce', reason: 'superfluous TXT/SPF/DKIM/DMARC (replaced by the policy)',
      displaces: (r) => TEXTUAL_TYPES.includes(r.fieldType) },
  ];
  // Invariant #9, as the old engine spelled it: a CAA is only ever touched when
  // the policy republishes one.
  if (policy.some((w) => w.fieldType === 'CAA')) {
    licences.push({ checkId: 'legacy.caa', action: 'enforce', reason: 'CAA replaced by the closed-by-default policy',
      displaces: (r) => r.fieldType === 'CAA' });
  }

  const plan = planZone(records, { wanted: policy, licences, keepPatterns, dropCnames: cnamesToDrop, dropRedirect });

  // Restore the old wording, so this commit changes no output at all.
  for (const rec of plan.delete) {
    if (rec.checkId?.startsWith('legacy.')) rec.reason = rec.reason.replace(/^legacy\.\w+ \(enforce\): /, '');
  }
  for (const rec of plan.keep) {
    if (rec.reason !== UNLICENSED) continue;
    rec.reason = rec.fieldType === 'CAA' ? 'CAA out of scope (pass --caa)' : 'out of scope';
  }
  return plan;
}

/** Removed unsafe public write boundary: callers must provide backup and identity. */
export async function applyPlan() {
  throw new Error('Use applyTransaction with a complete snapshot, provider identity and storage directory');
}
