// Shared vocabulary for DNS records: the two shapes a zone comes in, the
// helpers that read a record's value, and the safety predicates that decide
// what a policy may displace.
//
// This is the LEAF module. It imports nothing, and everything else imports it:
// the classifier, the check predicates, the policy resolver and the write
// path all have to agree on what "the same record" means, and that agreement
// only holds if there is one copy of the rules.
//
// Two record shapes exist, and both appear here:
//
//   zone-file shape   { name, type, rdata }               parseZone / the export
//   OVH API shape     { subDomain, fieldType, target, id } fetchRecords
//
// `toZoneShape` converts the second into the first. Helpers that read a value
// take the value itself, not a record, so they serve both.

// OVH types that carry text (OVH has dedicated fieldTypes on top of TXT).
export const TEXTUAL_TYPES = ['TXT', 'SPF', 'DKIM', 'DMARC'];

const TEXTUAL = new Set(TEXTUAL_TYPES);

/** Internal marker of the OVH web redirection service: `1|www.example.com`. */
export const OVH_REDIRECT_TXT = /^"?\d+\|/;

/** OVH's parking range — an address here means "nothing is served". */
export const OVH_PARKING_IP = /^213\.186\.33\.\d+$/;

export const lower = (s) => String(s ?? '').trim().toLowerCase();

export const fqdn = (s) => lower(s).replace(/"/g, '').replace(/\.$/, '');

export const isTextual = (type) => TEXTUAL.has(type);

/**
 * Fetched-record shape -> zone-file shape.
 *
 * `evaluate` reads the zone-file shape and `planZone` the API shape. Once the
 * plan is derived from the findings, a deletion is executed against one view
 * because a check failed against the other — so the write path converts and
 * evaluates the records it is about to modify, not a second copy fetched by a
 * different endpoint a few seconds earlier.
 */
export const toZoneShape = (r) => ({
  name: r.subDomain || '@',
  type: r.fieldType,
  rdata: r.target,
});

/**
 * Value of a textual record. OVH exports quote them, splits long values into
 * several quoted chunks, and wraps the whole thing in parentheses; DNS
 * concatenates the chunks, so we do too.
 */
export function txtValue(rdata) {
  const s = String(rdata ?? '').trim().replace(/^\(\s*/, '').replace(/\s*\)\s*$/, '');
  const chunks = s.match(/"(?:[^"\\]|\\.)*"/g);
  return chunks ? chunks.map((c) => c.slice(1, -1)).join('') : s;
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
  if (!TEXTUAL.has(fieldType)) return `${subDomain || '@'} ${fieldType} ${value}`;
  return `${subDomain || '@'} ${fieldType} "${value}"`;
}

/** Display label for a zone-file-shaped record. */
export function zoneLabel(rec) {
  return recordLabel({
    subDomain: rec.name === '@' ? '' : rec.name,
    fieldType: rec.type,
    target: rec.rdata,
  });
}

export function normalize(target) {
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
export function normalizeCaa(target) {
  const caa = parseCaa(target);
  return caa ? `${caa.flags} ${caa.tag} "${caa.value}"` : String(target ?? '').trim();
}

// An empty value reads as deny alongside a literal `;`: an unquoted
// `@ IN CAA 0 issue ;` loses its `;` to the zone-file comment stripper, so the
// truncated form has to mean what the record meant.
export const isDeny = (caa) => caa.value === ';' || caa.value === '';

/** Is an existing record already at the value a policy record wants? */
export function sameRecord(existing, wanted) {
  // OVH has dedicated SPF/DKIM/DMARC fieldTypes, but they come out as TXT in
  // the zone: a record already at the right value is compliant whatever its type.
  const sameType = existing.fieldType === wanted.fieldType
    || (wanted.fieldType === 'TXT' && TEXTUAL.has(existing.fieldType));
  const canon = wanted.fieldType === 'CAA' ? normalizeCaa : normalize;
  return sameType
    && (existing.subDomain || '') === wanted.subDomain
    && canon(existing.target) === canon(wanted.target);
}

/**
 * Does this name belong to the apex policy?
 *
 * The policy publishes at the apex, so it may only remove what competes with
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
export function isApexPolicyName(sub) {
  const name = String(sub || '@').toLowerCase();
  return name === '@' || name === '_dmarc' || /(^|\.)_domainkey$/.test(name);
}

/**
 * Terminal qualifier of an SPF record: '-', '~', '?' or '+'. null when the
 * record has no `all` mechanism at all.
 */
export function spfAll(value) {
  const found = [...String(value).matchAll(/(?:^|\s)([-~?+]?)all(?=\s|$)/gi)];
  return found.length ? (found[found.length - 1][1] || '+') : null;
}

/**
 * DNS lookups an SPF record costs. A static lower bound: nested `include:`
 * chains are not followed, so a record that passes here can still blow the
 * budget in a resolver. The detail says so rather than claiming a proof.
 */
export function spfLookups(value) {
  let n = 0;
  for (const raw of String(value).trim().split(/\s+/).slice(1)) {
    const term = lower(raw).replace(/^[-~?+]/, '');
    if (/^(include:|exists:|redirect=)/.test(term)) n++;
    else if (term === 'a' || term === 'mx' || term === 'ptr') n++;
    else if (/^(a|mx|ptr)[:/]/.test(term)) n++;
  }
  return n;
}

/** DMARC tag map, lowercased keys, values left as published. */
export function dmarcTags(value) {
  const tags = {};
  for (const part of String(value).split(';')) {
    const m = /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(part);
    if (m) tags[lower(m[1])] = m[2].trim();
  }
  return tags;
}

/**
 * Why a CAA deny would be unsafe on this zone, or null when it is safe.
 *
 * A CAA record at the apex is inherited by every subdomain (RFC 8659 §3), so
 * denying issuance on a zone that still serves web content breaks the next
 * certificate renewal — 60 to 90 days later, long after the change is
 * forgotten. One predicate, three consumers: the `na` of the CAA controls, the
 * write refusal in `harden`, and the policy resolver, which demotes a CAA
 * remedy to `report` rather than let a profile publish a deny the audit would
 * have withheld.
 *
 * Takes the zone-file shape.
 */
export function caaBlocker(records, { state = null } = {}) {
  if (state === 'web-active') return 'the zone serves web content';

  const textual = records.filter((r) => TEXTUAL.has(r.type));
  if (textual.some((r) => OVH_REDIRECT_TXT.test(String(r.rdata).trim()))) {
    return 'the zone carries an OVH web redirection';
  }
  if (textual.some((r) => /_acme-challenge/i.test(r.name))) {
    return 'an ACME challenge is in flight (certificate issuance in progress)';
  }

  const live = records.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type)
    && ['@', 'www'].includes(lower(r.name))
    && !OVH_PARKING_IP.test(String(r.rdata).trim()));
  if (live.length) return 'the apex or www still resolves to a live host';

  return null;
}

/** True when publishing a CAA deny on this zone is safe. */
export function caaApplicable(records, ctx = {}) {
  return caaBlocker(records, ctx) === null;
}

// ---------------------------------------------------------------------------
// Displacers — the competition relation. Critical, and NOT configurable.
// ---------------------------------------------------------------------------

const apex = (r) => (r.subDomain || '@') === '@';
const nameOf = (r) => String(r.subDomain || '@').toLowerCase();

/**
 * What a published record competes with, keyed by name.
 *
 * The policy config decides WHETHER a deletion is licensed; this table decides
 * HOW FAR that licence reaches. It is a closed map in code, and the validator
 * refuses a config naming a key that is not here, so no combination of config
 * syntax can produce a new predicate — an operator can turn a deletion on and
 * off, never widen one.
 *
 * Every predicate restates the apex condition even though `planZone` applies
 * `isApexPolicyName` as an unconditional pre-filter. That is deliberate
 * redundancy: these run against production zones, and the cost of the second
 * check is nothing next to the cost of the first one being refactored away.
 *
 * Note the two CAA entries are per-tag. A policy that publishes an `issue`
 * deny may not remove an `issuewild` it is not replacing — that is invariant
 * #9 holding structurally rather than as a special case.
 *
 * Takes the OVH API shape.
 */
export const DISPLACERS = Object.freeze({
  'none': () => false,

  'apex-spf': (r) => apex(r) && isTextual(r.fieldType)
    && /^v=spf1(\s|$)/i.test(txtValue(r.target)),

  'apex-dmarc': (r) => nameOf(r) === '_dmarc' && isTextual(r.fieldType)
    && /^v=dmarc1(\s*;|$)/i.test(txtValue(r.target)),

  // Every selector, not just the wildcard: a revocation that leaves a live
  // selector published has revoked nothing.
  'apex-dkim': (r) => /(^|\.)_domainkey$/.test(nameOf(r)) && isTextual(r.fieldType),

  'apex-mx': (r) => apex(r) && r.fieldType === 'MX',

  'apex-caa-issue': (r) => apex(r) && r.fieldType === 'CAA' && parseCaa(r.target)?.tag === 'issue',
  'apex-caa-issuewild': (r) => apex(r) && r.fieldType === 'CAA' && parseCaa(r.target)?.tag === 'issuewild',
  'apex-caa-iodef': (r) => apex(r) && r.fieldType === 'CAA' && parseCaa(r.target)?.tag === 'iodef',
});

/**
 * Zone-file shape -> fetched-record shape, for reading a backup the way the
 * write path sees a zone.
 *
 * The inverse of `toZoneShape`, and deliberately lossy: a backup carries no OVH
 * record id, so a plan built from these records can be printed but never
 * applied. `applyPlan` would have nothing to DELETE. Offline previews only.
 */
export const toApiShape = (r) => ({
  subDomain: r.name === '@' ? '' : r.name,
  fieldType: r.type,
  target: r.rdata,
});
