// Anti-spoofing hardening policy for dormant domains.
// Goal: the domain can no longer send mail, and nothing is left lying around.

// OVH types that carry text (OVH has dedicated fieldTypes on top of TXT).
export const TEXTUAL_TYPES = ['TXT', 'SPF', 'DKIM', 'DMARC'];

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
    // UNVERIFIED AGAINST THE OVH API. Neither the OVH documentation nor the
    // Terraform provider states the `target` syntax for fieldType CAA, so this
    // is the zone-file form. Confirm it on a throwaway zone before the first
    // --apply: if OVH rejects it, applyPlan reports the creation error and the
    // zone is left with no CAA at all — looser, not broken, and `restore`
    // puts it back. This is why --caa is opt-in.
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
 * Display form of a record. OVH returns TXT targets already wrapped in quotes,
 * so quoting the raw value would print ""v=spf1 -all"".
 *
 * Only textual types get quotes. A structured target carries its own quoting —
 * `0 issue ";"` would otherwise print as `@ CAA "0 issue ";""` — and `@ MX 0 .`
 * reads the way it does in a zone file.
 */
export function recordLabel({ subDomain, fieldType, target }) {
  const value = String(target ?? '').replace(/^"([\s\S]*)"$/, '$1');
  if (!TEXTUAL_TYPES.includes(fieldType)) return `${subDomain || '@'} ${fieldType} ${value}`;
  return `${subDomain || '@'} ${fieldType} "${value}"`;
}

function sameRecord(existing, wanted) {
  // OVH has dedicated SPF/DKIM/DMARC fieldTypes, but they come out as TXT in
  // the zone: a record already at the right value is compliant whatever its type.
  const sameType = existing.fieldType === wanted.fieldType
    || (wanted.fieldType === 'TXT' && TEXTUAL_TYPES.includes(existing.fieldType));
  const canon = wanted.fieldType === 'CAA' ? normalizeCaa : normalize;
  return sameType
    && (existing.subDomain || '') === wanted.subDomain
    && canon(existing.target) === canon(wanted.target);
}

function normalize(target) {
  return String(target ?? '').trim().replace(/^"|"$/g, '').replace(/"\s+"/g, '').replace(/\s+/g, ' ');
}

/**
 * Split a CAA rdata into { flags, tag, value }, whatever the quoting.
 *
 * OVH's stored and exported forms for CAA are not documented and not verified,
 * and a zone export drops the `;` of an unquoted `0 issue ;` to the comment
 * stripper before it is ever parsed. So every plausible shape is accepted:
 *
 *   0 issue ";"        0 issue ;        "0 issue ;"
 *   "0 issue \";\""     0 "issue" ";"    0 issue          (value lost)
 *
 * Being tolerant here is what keeps `planZone` idempotent: a form we fail to
 * recognise reads as "different from the policy" and churns the zone on every
 * single run.
 */
export function parseCaa(target) {
  const attempt = (s) => {
    const m = /^(\d+)\s+"?([a-z0-9]+)"?(?:\s+"?(.*?)"?)?\s*$/i.exec(s.trim());
    return m ? { flags: Number(m[1]), tag: m[2].toLowerCase(), value: (m[3] ?? '').trim() } : null;
  };
  const raw = String(target ?? '').trim();
  const direct = attempt(raw);
  if (direct) return direct;
  // Wrapped whole, with the inner quotes escaped.
  if (/^"[\s\S]*"$/.test(raw)) return attempt(raw.slice(1, -1).replace(/\\"/g, '"'));
  return null;
}

// CAA needs its own canonicaliser. `normalize` anchors both quote strips in one
// alternation with the /g flag, so on `0 issue ";"` it removes the trailing
// quote only and yields `0 issue ";` — deterministic, asymmetric, and wrong the
// moment OVH stores or exports the value unquoted.
function normalizeCaa(target) {
  const caa = parseCaa(target);
  return caa ? `${caa.flags} ${caa.tag} "${caa.value}"` : String(target ?? '').trim();
}

/**
 * Fetch every relevant record of a zone.
 */
export async function fetchRecords(ovh, zone) {
  const types = [...TEXTUAL_TYPES, 'MX', 'CNAME', 'CAA'];
  const records = [];
  for (const fieldType of types) {
    let ids;
    try {
      ids = await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record?fieldType=${fieldType}`);
    } catch (err) {
      // 404: the zone has no record of that type. 400: the account's API
      // version does not know the fieldType at all — seen on CAA, and a reason
      // to skip the type rather than abort a whole batch over it.
      if (err.status === 404 || err.status === 400) continue;
      throw err;
    }
    for (const id of ids) {
      records.push(await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/record/${id}`));
    }
  }
  return records;
}

/**
 * Does this name belong to the apex policy `buildPolicy` publishes?
 *
 * `harden` publishes at the apex, so it may only remove what competes with
 * what it publishes. The record TYPE cannot decide that on its own: `mg MX`
 * and `@ MX` are both MX, but only the second is ours — the first is a
 * Mailgun sending subdomain, and deleting it takes the customer's mail with
 * it. That is not hypothetical; it is what a dry-run on a real zone proposed.
 *
 *   @                       the apex itself
 *   _dmarc                  the apex DMARC policy
 *   <selector>._domainkey   an apex DKIM selector, wildcard included
 *
 * The suffix test is what separates the two families: `sel._domainkey` ends in
 * `._domainkey` and is ours, while `email._domainkey.mg` ends in `.mg` and is
 * the sending subdomain's own key. Same for `_dmarc` against `_dmarc.mg`.
 */
function isApexPolicyName(sub) {
  const name = String(sub || '@').toLowerCase();
  return name === '@' || name === '_dmarc' || /(^|\.)_domainkey$/.test(name);
}

/**
 * Build the plan: what we delete, what we create, what we leave alone.
 */
export function planZone(records, { policy, keepPatterns = [], cnamesToDrop = DEFAULT_CNAMES_TO_DROP, dropRedirect = false }) {
  const del = [];
  const keep = [];

  for (const rec of records) {
    const sub = rec.subDomain || '@';
    const label = recordLabel(rec);

    if (keepPatterns.some((re) => re.test(rec.target) || re.test(sub))) {
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
    if (rec.fieldType === 'CNAME' && cnamesToDrop.includes((rec.subDomain || '').toLowerCase())) {
      del.push({ ...rec, label, reason: `useless ${rec.subDomain} CNAME` });
      continue;
    }

    // The apex gate. Every rule below deletes a record because its type
    // competes with the policy, which only holds for names the policy owns.
    if (!isApexPolicyName(sub)) {
      // Spell it out for the types that USED to be deleted here: that is the
      // case an operator needs to see explained rather than silently kept.
      const shadowed = rec.fieldType === 'MX' || rec.fieldType === 'CAA' || TEXTUAL_TYPES.includes(rec.fieldType);
      keep.push({ ...rec, reason: shadowed ? `out of scope: ${sub} is not an apex policy name` : 'out of scope' });
      continue;
    }

    if (rec.fieldType === 'MX') {
      del.push({ ...rec, label, reason: 'MX at the apex' });
      continue;
    }
    if (TEXTUAL_TYPES.includes(rec.fieldType)) {
      del.push({ ...rec, label, reason: 'superfluous TXT/SPF/DKIM/DMARC (replaced by the policy)' });
      continue;
    }
    if (rec.fieldType === 'CAA') {
      // Deleting a CAA without publishing one LOOSENS the zone: no CAA at all
      // means every CA in the world may issue. So an existing CAA is only ever
      // touched when the policy replaces it.
      if (!policy.some((w) => w.fieldType === 'CAA')) {
        keep.push({ ...rec, reason: 'CAA out of scope (pass --caa)' });
        continue;
      }
      del.push({ ...rec, label, reason: 'CAA replaced by the closed-by-default policy' });
      continue;
    }
    keep.push({ ...rec, reason: 'out of scope' });
  }

  // A record already compliant is neither deleted nor recreated.
  const create = [];
  for (const wanted of policy) {
    // !r.skip: two policy entries of the same type must not both reconcile
    // against the same existing record.
    const already = del.find((r) => !r.skip && sameRecord(r, wanted));
    if (already) {
      already.skip = true;
      keep.push({ ...already, reason: 'already compliant' });
      continue;
    }
    create.push(wanted);
  }

  return { delete: del.filter((r) => !r.skip), create, keep };
}

/**
 * Apply the plan. Individual failures are collected, not fatal.
 */
export async function applyPlan(ovh, zone, plan) {
  const z = encodeURIComponent(zone);
  const done = { deleted: [], created: [], errors: [] };

  for (const rec of plan.delete) {
    try {
      await ovh.delete(`/domain/zone/${z}/record/${rec.id}`);
      done.deleted.push(rec.label);
    } catch (err) {
      done.errors.push(`DELETE ${rec.label}: ${err.message}`);
    }
  }

  for (const rec of plan.create) {
    try {
      const created = await ovh.post(`/domain/zone/${z}/record`, {
        subDomain: rec.subDomain,
        fieldType: rec.fieldType,
        target: rec.target,
        ttl: rec.ttl,
      });
      done.created.push(recordLabel({ ...rec, target: created.target }));
    } catch (err) {
      done.errors.push(`CREATE ${recordLabel(rec)}: ${err.message}`);
    }
  }

  try {
    await ovh.post(`/domain/zone/${z}/refresh`);
  } catch (err) {
    done.errors.push(`REFRESH: ${err.message}`);
  }

  return done;
}
