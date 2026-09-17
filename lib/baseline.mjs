// A declarative control baseline for DNS posture: anti-spoofing, closed by
// default, and residual attack surface.
//
// Pure and offline. It reads the { name, type, rdata } shape produced by
// parseZone, so it scores the on-disk backups without touching the network —
// the same source `inventory` rebuilds from.
//
// Two rules govern `na`:
//
//   1. A control returns `na` because the zone's USE makes the question
//      meaningless — a mail-active domain is not expected to revoke its DKIM
//      keys — never as a softer `fail` for a missing record.
//   2. `na` is excluded from the numerator AND the denominator of the score,
//      and is always rendered with its reason, never silently dropped.
//
// A missing record is therefore a `fail`. One distinction decides several
// checks below: whether absence satisfies the property. A control that ASSERTS
// something ("the domain must declare a hard fail") fails when the record is
// absent — with no SPF at all, forged mail is not rejected, so spf.hardfail
// fails; the alternative would let a wide-open domain outscore one publishing
// `~all`. A control that BOUNDS something ("at most 10 DNS lookups", "not
// permissive") is satisfied vacuously, since a record that does not exist
// cannot exceed a budget or authorise anyone. A missing record costs every
// control whose property it leaves unsatisfied, and no others.
//
// Control ids are a PUBLIC INTERFACE: they are written to compliance.json and
// compliance.csv and end up in someone's remediation plan. Renaming one is a
// breaking change.

import { classify } from './inventory.mjs';
import { recordLabel, parseCaa } from './harden.mjs';

export const BASELINE_VERSION = '1.0.0';

export const AXES = ['spoofing', 'closed', 'surface'];

export const AXIS_TITLES = {
  spoofing: 'Anti-spoofing',
  closed: 'Closed by default',
  surface: 'Attack surface',
};

export const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1 };

export const GRADE_BANDS = [[95, 'A'], [85, 'B'], [70, 'C'], [50, 'D'], [0, 'F']];

// Which classifier states a control applies to. Everything else is `na`: an
// audit that covers the whole portfolio has to score each domain against the
// posture expected of *its* state, or every mail-active domain reads as F.
export const SCOPES = {
  'all': ['dormant', 'web-active', 'mail-active'],
  'non-sending': ['dormant', 'web-active'],
  'sending': ['mail-active'],
  'dormant': ['dormant'],
};

const HARDEN = 'node ovh.mjs harden <domain> --apply';
const HARDEN_CAA = 'node ovh.mjs harden <domain> --caa --apply';

// ---------------------------------------------------------------------------
// Rule data. One constant per rule, in the style of REAL_MAIL in inventory.mjs,
// so a list can be corrected without reading the checks that consume it.
// ---------------------------------------------------------------------------

// Service subdomains left behind by a decommissioned mail or hosting setup.
// Harmless on their own; they advertise what used to run, and an attacker
// reads them as a map.
const LEGACY_SERVICES = new Set([
  'autodiscover', 'autoconfig', 'webmail', 'mail', 'smtp', 'imap', 'pop',
  'msoid', 'lyncdiscover', 'sip', '_sip', '_sipfederationtls', '_autodiscover',
  'enterpriseregistration', 'enterpriseenrollment', 'cpanel', 'whm', 'webdisk',
]);

// CNAME targets on platforms where an unclaimed name can be registered by
// anyone — the classic subdomain takeover. DNS alone cannot prove the target
// is unclaimed, so the finding says "verify", it does not assert a takeover.
// REVIEWED 2026-09 — cross-check against the can-i-take-over-xyz catalogue.
const TAKEOVER_TARGETS = [
  { re: /(^|\.)s3[.-][a-z0-9-]*\.?amazonaws\.com$/i, label: 'Amazon S3' },
  { re: /(^|\.)cloudfront\.net$/i, label: 'Amazon CloudFront' },
  { re: /(^|\.)github\.io$/i, label: 'GitHub Pages' },
  { re: /(^|\.)herokuapp\.com$/i, label: 'Heroku' },
  { re: /(^|\.)azurewebsites\.net$/i, label: 'Azure App Service' },
  { re: /(^|\.)trafficmanager\.net$/i, label: 'Azure Traffic Manager' },
  { re: /(^|\.)cloudapp\.(net|azure\.com)$/i, label: 'Azure Cloud Service' },
  { re: /(^|\.)blob\.core\.windows\.net$/i, label: 'Azure Blob Storage' },
  { re: /(^|\.)wpengine\.com$/i, label: 'WP Engine' },
  { re: /(^|\.)pantheonsite\.io$/i, label: 'Pantheon' },
  { re: /(^|\.)netlify\.(app|com)$/i, label: 'Netlify' },
  { re: /(^|\.)ghost\.io$/i, label: 'Ghost' },
  { re: /(^|\.)readthedocs\.io$/i, label: 'Read the Docs' },
  { re: /(^|\.)surge\.sh$/i, label: 'Surge' },
  { re: /(^|\.)fastly\.net$/i, label: 'Fastly' },
  { re: /(^|\.)bitbucket\.io$/i, label: 'Bitbucket Cloud' },
  { re: /(^|\.)zendesk\.com$/i, label: 'Zendesk' },
  { re: /(^|\.)statuspage\.io$/i, label: 'Statuspage' },
];

// Third-party domain-verification TXT records. Each one is a live attachment
// to an external account that nobody remembers owning.
const VERIFICATION_TXT = /site-verification|^MS=|facebook-domain|apple-domain|stripe-verification|atlassian-domain|have-i-been-pwned/i;

// Internal marker of the OVH web redirection service (duplicated from
// inventory.mjs on purpose: it is a shared OVH quirk, not a shared symbol).
const OVH_REDIRECT_TXT = /^"?\d+\|/;

const OVH_PARKING_IP = /^213\.186\.33\.\d+$/;

const TEXTUAL = new Set(['TXT', 'SPF', 'DKIM', 'DMARC']);

// ---------------------------------------------------------------------------
// Record helpers
// ---------------------------------------------------------------------------

const lower = (s) => String(s ?? '').trim().toLowerCase();
const fqdn = (s) => lower(s).replace(/"/g, '').replace(/\.$/, '');

/**
 * Value of a textual record. OVH exports quote them, splits long values into
 * several quoted chunks, and wraps the whole thing in parentheses; DNS
 * concatenates the chunks, so we do too.
 */
function txtValue(rdata) {
  const s = String(rdata ?? '').trim().replace(/^\(\s*/, '').replace(/\s*\)\s*$/, '');
  const chunks = s.match(/"(?:[^"\\]|\\.)*"/g);
  return chunks ? chunks.map((c) => c.slice(1, -1)).join('') : s;
}

/** Display label for a parsed record, reusing the CLI's record formatting. */
function label(rec) {
  return recordLabel({
    subDomain: rec.name === '@' ? '' : rec.name,
    fieldType: rec.type,
    target: rec.rdata,
  });
}

/** Cap the evidence list: a finding is a pointer, not a zone dump. */
function evidence(list, cap = 5) {
  const out = list.slice(0, cap);
  if (list.length > cap) out.push(`... +${list.length - cap} more`);
  return out;
}

/**
 * Terminal qualifier of an SPF record: '-', '~', '?' or '+'. null when the
 * record has no `all` mechanism at all.
 */
function spfAll(value) {
  const found = [...String(value).matchAll(/(?:^|\s)([-~?+]?)all(?=\s|$)/gi)];
  return found.length ? (found[found.length - 1][1] || '+') : null;
}

/**
 * DNS lookups an SPF record costs. A static lower bound: nested `include:`
 * chains are not followed, so a record that passes here can still blow the
 * budget in a resolver. The detail says so rather than claiming a proof.
 */
function spfLookups(value) {
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
function dmarcTags(value) {
  const tags = {};
  for (const part of String(value).split(';')) {
    const m = /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(part);
    if (m) tags[lower(m[1])] = m[2].trim();
  }
  return tags;
}

// An empty value reads as deny alongside a literal `;`: an unquoted
// `@ IN CAA 0 issue ;` loses its `;` to the zone-file comment stripper, so the
// truncated form has to mean what the record meant.

const isDeny = (caa) => caa.value === ';' || caa.value === '';

/**
 * Why a CAA deny would be unsafe on this zone, or null when it is safe.
 *
 * A CAA record at the apex is inherited by every subdomain (RFC 8659 §3), so
 * denying issuance on a zone that still serves web content breaks the next
 * certificate renewal — 60 to 90 days later, long after the change is
 * forgotten. One predicate, two consumers: the `na` of the CAA controls and
 * the write refusal in `harden`.
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
// The control catalogue
// ---------------------------------------------------------------------------

const pass = (detail, ev = []) => ({ status: 'pass', detail, evidence: ev });
const na = (detail) => ({ status: 'na', detail, evidence: [] });
const fail = (detail, ev = [], remediation = null) => ({ status: 'fail', detail, evidence: ev, remediation });

export const CONTROLS = [
  // --- Anti-spoofing: can anyone send mail in this domain's name? ----------
  {
    id: 'spf.present',
    title: 'SPF published at the apex',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'all',
    refs: ['RFC 7208 §3', 'ISO/IEC 27001:2022 A.5.14', 'NIS2 Art. 21(2)(g)'],
    check(_records, ctx) {
      if (!ctx.spf.length) {
        // The right record depends on the use: a dormant domain authorises
        // nobody, a sending one authorises its senders. Telling a mail-active
        // domain to publish `-all` would break every message it sends.
        return fail('no TXT `v=spf1` at the apex: receivers have no basis on which to reject forged mail.', [],
          ctx.state === 'mail-active'
            ? { text: 'Publish an SPF record listing the authorised senders and ending in `-all`.', command: null }
            : { text: 'Publish `v=spf1 -all` at the apex.', command: HARDEN });
      }
      return pass('SPF published.', ctx.spf.map((r) => label(r)));
    },
  },
  {
    id: 'spf.single',
    title: 'No conflicting SPF record at the apex',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'all',
    refs: ['RFC 7208 §4.5'],
    check(_records, ctx) {
      if (ctx.spf.length > 1) {
        return fail(`${ctx.spf.length} SPF records at the apex: evaluation returns PermError and the policy is ignored entirely.`,
          evidence(ctx.spf.map((r) => label(r))),
          { text: 'Merge them into a single record, or let the policy replace them.', command: HARDEN });
      }
      return pass(ctx.spf.length ? 'exactly one SPF record.' : 'no duplicate SPF record.');
    },
  },
  {
    id: 'spf.hardfail',
    title: 'SPF ends in a hard fail',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'non-sending',
    refs: ['RFC 7208 §5.1', 'ISO/IEC 27001:2022 A.5.14'],
    check(_records, ctx) {
      const q = ctx.spf.length ? spfAll(txtValue(ctx.spf[0].rdata)) : null;
      if (q === '-') return pass('SPF ends in `-all`.', [label(ctx.spf[0])]);
      const seen = q === null ? (ctx.spf.length ? 'no `all` mechanism' : 'no SPF record') : `\`${q}all\``;
      return fail(`the domain sends no mail but does not say so: ${seen} instead of \`-all\`.`,
        ctx.spf.map((r) => label(r)),
        { text: 'Publish `v=spf1 -all`: no authorised sender, hard fail.', command: HARDEN });
    },
  },
  {
    id: 'spf.no-permissive',
    title: 'SPF does not authorise the whole internet',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'sending',
    refs: ['RFC 7208 §5.1'],
    check(_records, ctx) {
      // Vacuous: a record that does not exist authorises nobody. The absence is
      // a failure of `spf.present`, and counting it here too would penalise one
      // missing record twice. See the `na` doctrine in the module header.
      if (!ctx.spf.length) return pass('no SPF record to be permissive.', []);
      const q = spfAll(txtValue(ctx.spf[0].rdata));
      if (q === '-' || q === '~') return pass(`SPF ends in \`${q}all\`.`, [label(ctx.spf[0])]);
      return fail(`SPF ends in \`${q === null ? 'nothing' : q + 'all'}\`: anyone may send for this domain.`,
        [label(ctx.spf[0])],
        { text: 'End the record in `-all` (or `~all` while you observe reports).', command: null });
    },
  },
  {
    id: 'spf.lookup-budget',
    title: 'SPF stays within the DNS lookup budget',
    axis: 'spoofing',
    severity: 'medium',
    scope: 'sending',
    refs: ['RFC 7208 §4.6.4'],
    check(_records, ctx) {
      if (!ctx.spf.length) return pass('no SPF record, no lookup.');
      const n = spfLookups(txtValue(ctx.spf[0].rdata));
      if (n > 10) {
        return fail(`at least ${n} DNS lookups in the SPF record (limit 10): evaluation returns PermError and SPF stops protecting anything.`,
          [label(ctx.spf[0])],
          { text: 'Flatten or drop `include:` mechanisms until the count is 10 or fewer.', command: null });
      }
      return pass(`${n} direct DNS lookup(s); nested includes are not counted, so this is a lower bound.`);
    },
  },
  {
    id: 'dmarc.present',
    title: 'A single DMARC record on `_dmarc`',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'all',
    refs: ['RFC 7489 §6.1', 'ISO/IEC 27001:2022 A.5.14', 'NIS2 Art. 21(2)(g)'],
    check(_records, ctx) {
      if (!ctx.dmarc.length) {
        return fail('no DMARC record: nothing ties the visible `From:` header to SPF or DKIM.', [],
          { text: 'Publish a DMARC record on `_dmarc`.', command: HARDEN });
      }
      if (ctx.dmarc.length > 1) {
        return fail(`${ctx.dmarc.length} DMARC records: receivers discard the policy entirely when more than one is published.`,
          evidence(ctx.dmarc.map((r) => label(r))),
          { text: 'Keep exactly one record on `_dmarc`.', command: HARDEN });
      }
      return pass('one DMARC record published.', [label(ctx.dmarc[0])]);
    },
  },
  {
    id: 'dmarc.reject',
    title: 'DMARC policy is `p=reject`',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'all',
    refs: ['RFC 7489 §6.3', 'ISO/IEC 27001:2022 A.5.14'],
    check(_records, ctx) {
      const p = lower(ctx.dmarcTags.p ?? '');
      if (p === 'reject') return pass('`p=reject`.', [label(ctx.dmarc[0])]);
      const seen = p ? `\`p=${p}\`` : 'no DMARC policy';
      return fail(`${seen}: forged mail is delivered or filed as spam rather than refused.`,
        ctx.dmarc.map((r) => label(r)),
        { text: 'Move the policy to `p=reject` once reports confirm nothing legitimate fails.', command: HARDEN });
    },
  },
  {
    id: 'dmarc.subdomain-reject',
    title: 'Subdomain policy stated explicitly',
    axis: 'spoofing',
    severity: 'high',
    scope: 'all',
    refs: ['RFC 7489 §6.3'],
    check(_records, ctx) {
      const sp = lower(ctx.dmarcTags.sp ?? '');
      if (sp === 'reject') return pass('`sp=reject`.', [label(ctx.dmarc[0])]);
      const seen = sp ? `\`sp=${sp}\`` : 'no `sp=` tag';
      return fail(`${seen}: an attacker forges \`billing.<domain>\` instead of the apex.`,
        ctx.dmarc.map((r) => label(r)),
        { text: 'Add `sp=reject` — inheriting `p` is not the same as stating the subdomain policy.', command: HARDEN });
    },
  },
  {
    id: 'dmarc.strict-alignment',
    title: 'Strict DMARC alignment',
    axis: 'spoofing',
    severity: 'medium',
    scope: 'all',
    refs: ['RFC 7489 §3.1'],
    check(_records, ctx) {
      const { adkim, aspf } = ctx.dmarcTags;
      if (lower(adkim) === 's' && lower(aspf) === 's') {
        return pass('`adkim=s` and `aspf=s`.', [label(ctx.dmarc[0])]);
      }
      return fail('relaxed alignment (the default): any subdomain of the organisational domain passes DMARC for the apex.',
        ctx.dmarc.map((r) => label(r)),
        { text: 'Add `adkim=s; aspf=s`.', command: HARDEN });
    },
  },
  {
    id: 'dkim.wildcard-revoked',
    title: 'Wildcard DKIM revocation published',
    axis: 'spoofing',
    severity: 'high',
    scope: 'non-sending',
    refs: ['RFC 6376 §3.6.1'],
    check(_records, ctx) {
      const hit = ctx.dkimTxt.find((r) => lower(r.name) === '*._domainkey' && /^v=dkim1/i.test(txtValue(r.rdata)) && !ctx.dkimLive.includes(r));
      if (hit) return pass('`*._domainkey` revokes every selector.', [label(hit)]);
      return fail('no `*._domainkey` revocation: a selector left behind by a former provider is still usable by whoever holds the private key.', [],
        { text: 'Publish `v=DKIM1; p=` on `*._domainkey` — an empty `p=` revokes every selector at once.', command: HARDEN });
    },
  },
  {
    id: 'dkim.no-live-selector',
    title: 'No residual DKIM selector',
    axis: 'spoofing',
    severity: 'critical',
    scope: 'non-sending',
    refs: ['RFC 6376 §3.6.1', 'ISO/IEC 27001:2022 A.5.14'],
    check(_records, ctx) {
      const live = [...ctx.dkimLive, ...ctx.dkimCname];
      if (!live.length) return pass('no publishable DKIM key left.');
      const manual = ctx.dkimCname.length > 0;
      return fail(`${live.length} DKIM selector(s) still publish a key: signed mail from the old provider still validates.`,
        evidence(live.map((r) => label(r))),
        {
          text: manual
            ? 'Delete the `_domainkey` CNAMEs in the OVH manager — the policy cannot remove a delegated selector.'
            : 'Remove the selectors and publish the wildcard revocation.',
          command: manual ? null : HARDEN,
        });
    },
  },
  {
    id: 'dkim.selector-published',
    title: 'At least one DKIM selector published',
    axis: 'spoofing',
    severity: 'high',
    scope: 'sending',
    refs: ['RFC 6376 §3.6.1'],
    check(_records, ctx) {
      const live = [...ctx.dkimLive, ...ctx.dkimCname];
      if (live.length) return pass(`${live.length} selector(s) published.`, evidence(live.map((r) => label(r))));
      return fail('the domain sends mail but signs nothing: DMARC then rests on SPF alone, which breaks on every forward.', [],
        { text: 'Enable DKIM signing at the mail provider and publish the selector.', command: null });
    },
  },

  // --- Closed by default: what the zone refuses without being asked --------
  {
    id: 'mx.closed',
    title: 'No inbound mail route',
    axis: 'closed',
    severity: 'high',
    scope: 'non-sending',
    refs: ['RFC 7505', 'ISO/IEC 27001:2022 A.8.20'],
    check(_records, ctx) {
      const routed = ctx.mx.filter((r) => !/(^|\s)\.$/.test(String(r.rdata).trim()));
      if (!routed.length) return pass(ctx.mx.length ? 'null MX only.' : 'no MX record.');
      return fail(`${routed.length} MX record(s) still route mail to a mailbox nobody reads.`,
        evidence(routed.map((r) => label(r))),
        { text: 'Remove the MX records, or publish a null MX.', command: HARDEN });
    },
  },
  {
    id: 'mx.null-explicit',
    title: 'Null MX published rather than merely absent',
    axis: 'closed',
    severity: 'low',
    scope: 'dormant',
    refs: ['RFC 7505 §3'],
    check(_records, ctx) {
      const nullMx = ctx.mx.find((r) => /(^|\s)\.$/.test(String(r.rdata).trim()));
      if (nullMx) return pass('null MX published.', [label(nullMx)]);
      return fail('no null MX: senders retry for days instead of failing immediately, and backscatter keeps arriving.', [],
        { text: 'Publish `MX 0 .` (RFC 7505).', command: 'node ovh.mjs harden <domain> --null-mx --apply' });
    },
  },
  {
    id: 'caa.issue-deny',
    title: 'CAA denies certificate issuance',
    axis: 'closed',
    severity: 'high',
    scope: 'dormant',
    refs: ['RFC 8659 §4.2', 'ISO/IEC 27001:2022 A.8.21'],
    check(_records, ctx) {
      if (ctx.caaBlockedBy) return na(`a CAA deny would be unsafe here: ${ctx.caaBlockedBy}.`);
      const issue = ctx.caa.filter((c) => c.parts.tag === 'issue');
      if (issue.length && issue.every((c) => isDeny(c.parts))) {
        return pass('`0 issue ";"`: no CA may issue.', issue.map((c) => label(c.rec)));
      }
      const detail = issue.length
        ? 'a CAA authorises a certificate authority on a domain that needs no certificate.'
        : 'no CAA record: any certificate authority in the world may issue for this domain.';
      return fail(detail, issue.map((c) => label(c.rec)),
        { text: 'Publish `0 issue ";"` at the apex.', command: HARDEN_CAA });
    },
  },
  {
    id: 'caa.issuewild-deny',
    title: 'CAA denies wildcard certificates',
    axis: 'closed',
    severity: 'medium',
    scope: 'dormant',
    refs: ['RFC 8659 §4.3'],
    check(_records, ctx) {
      if (ctx.caaBlockedBy) return na(`a CAA deny would be unsafe here: ${ctx.caaBlockedBy}.`);
      const wild = ctx.caa.filter((c) => c.parts.tag === 'issuewild');
      if (wild.length) {
        return wild.every((c) => isDeny(c.parts))
          ? pass('`0 issuewild ";"`: no wildcard certificate.', wild.map((c) => label(c.rec)))
          : fail('a CAA authorises wildcard issuance on a dormant domain.', wild.map((c) => label(c.rec)),
            { text: 'Replace it with `0 issuewild ";"`.', command: HARDEN_CAA });
      }
      // With no issuewild property, `issue` governs wildcards too (RFC 8659
      // §4.3) — a zone that publishes only the issue deny is already closed.
      const issue = ctx.caa.filter((c) => c.parts.tag === 'issue');
      if (issue.length && issue.every((c) => isDeny(c.parts))) {
        return pass('no `issuewild` property, so the `issue` deny governs wildcards as well.');
      }
      return fail('nothing denies wildcard issuance.', [],
        { text: 'Publish `0 issuewild ";"` alongside the issue deny.', command: HARDEN_CAA });
    },
  },
  {
    id: 'caa.present',
    title: 'A CAA record restricts the authorised CAs',
    axis: 'closed',
    severity: 'medium',
    scope: 'all',
    refs: ['RFC 8659 §4.2', 'ISO/IEC 27001:2022 A.8.21'],
    check(_records, ctx) {
      if (ctx.caa.length) {
        return pass(`${ctx.caa.length} CAA record(s) published.`, evidence(ctx.caa.map((c) => label(c.rec))));
      }
      return fail('no CAA record: any certificate authority may issue a valid certificate for this name.', [],
        { text: 'Publish a CAA record naming the CAs you actually use, or `0 issue ";"` on a domain that needs none.', command: null });
    },
  },
  {
    id: 'caa.no-permissive',
    title: 'No CAA authorising an unused CA',
    axis: 'closed',
    severity: 'medium',
    scope: 'dormant',
    refs: ['RFC 8659 §4.2'],
    check(_records, ctx) {
      const permissive = ctx.caa.filter((c) => ['issue', 'issuewild'].includes(c.parts.tag) && !isDeny(c.parts));
      if (!permissive.length) return pass('no CAA authorises a certificate authority.');
      return fail('the zone still authorises a CA it no longer uses: issuance stays possible for whoever controls that account.',
        evidence(permissive.map((c) => label(c.rec))),
        { text: 'Remove the permissive entries, or replace them with the deny pair.', command: HARDEN_CAA });
    },
  },

  // --- Attack surface: what the zone still advertises ----------------------
  {
    id: 'wildcard.none',
    title: 'No DNS wildcard',
    axis: 'surface',
    severity: 'high',
    scope: 'all',
    refs: ['RFC 4592', 'ISO/IEC 27001:2022 A.8.20'],
    check(records) {
      const wild = records.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type)
        && (lower(r.name) === '*' || lower(r.name).startsWith('*.')));
      if (!wild.length) return pass('no wildcard A/AAAA/CNAME.');
      return fail('a wildcard makes every name that was never created resolve, which is what makes phishing subdomains free.',
        evidence(wild.map((r) => label(r))),
        { text: 'Delete the wildcard and declare the names you actually serve.', command: null });
    },
  },
  {
    id: 'services.no-legacy',
    title: 'No residual service subdomain',
    axis: 'surface',
    severity: 'medium',
    scope: 'non-sending',
    refs: ['ISO/IEC 27001:2022 A.5.9'],
    check(records) {
      const stale = records.filter((r) => ['A', 'AAAA', 'CNAME'].includes(r.type)
        && (LEGACY_SERVICES.has(lower(r.name)) || LEGACY_SERVICES.has(lower(r.name).split('.')[0])));
      if (!stale.length) return pass('no leftover service subdomain.');
      return fail(`${stale.length} subdomain(s) still advertise a decommissioned mail or hosting setup: ${[...new Set(stale.map((r) => r.name))].join(', ')}.`,
        evidence(stale.map((r) => label(r))),
        { text: 'Delete them in the OVH manager — they are outside the hardening policy on purpose.', command: null });
    },
  },
  {
    id: 'srv.none',
    title: 'No residual SRV record',
    axis: 'surface',
    severity: 'low',
    scope: 'non-sending',
    refs: ['RFC 2782'],
    check(records) {
      const srv = records.filter((r) => r.type === 'SRV');
      if (!srv.length) return pass('no SRV record.');
      return fail(`${srv.length} SRV record(s) still point clients at a service this domain no longer runs.`,
        evidence(srv.map((r) => label(r))),
        { text: 'Delete them in the OVH manager.', command: null });
    },
  },
  {
    id: 'cname.no-takeover',
    title: 'No CNAME towards a takeover-prone platform',
    axis: 'surface',
    severity: 'critical',
    scope: 'all',
    refs: ['ISO/IEC 27001:2022 A.5.9', 'NIS2 Art. 21(2)(a)'],
    check(records) {
      const risky = [];
      for (const rec of records.filter((r) => r.type === 'CNAME')) {
        const hit = TAKEOVER_TARGETS.find((t) => t.re.test(fqdn(rec.rdata)));
        if (hit) risky.push({ rec, hit });
      }
      if (!risky.length) return pass('no CNAME towards a known takeover-prone platform.');
      const names = [...new Set(risky.map((r) => `${r.rec.name} -> ${r.hit.label}`))];
      return fail(`${risky.length} CNAME(s) point at a platform where an unclaimed name can be registered by anyone: ${names.join(', ')}. Verify each target is still claimed — DNS alone cannot prove it.`,
        evidence(risky.map((r) => label(r.rec))),
        { text: 'Confirm the target is still owned by you; delete the CNAME otherwise.', command: null });
    },
  },
  {
    id: 'txt.no-stale-verification',
    title: 'No residual third-party verification TXT',
    axis: 'surface',
    severity: 'low',
    scope: 'non-sending',
    refs: ['ISO/IEC 27001:2022 A.5.9'],
    check(_records, ctx) {
      const verif = ctx.textual.filter((r) => VERIFICATION_TXT.test(txtValue(r.rdata)));
      if (!verif.length) return pass('no third-party verification TXT.');
      return fail(`${verif.length} verification TXT record(s): the domain is still attached to an external account nobody owns any more.`,
        evidence(verif.map((r) => label(r))),
        { text: 'Detach the services, then remove the records (`--keep` protects them until then).', command: null });
    },
  },
];

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

function context(records, { domain, state, signals, counts }) {
  const textual = records.filter((r) => TEXTUAL.has(r.type));
  const apexTextual = textual.filter((r) => lower(r.name) === '@');
  const spf = apexTextual.filter((r) => /^v=spf1(\s|$)/i.test(txtValue(r.rdata)));
  const dmarc = textual.filter((r) => lower(r.name) === '_dmarc' && /^v=dmarc1(\s*;|$)/i.test(txtValue(r.rdata)));
  const dkimTxt = textual.filter((r) => /_domainkey/i.test(r.name));

  const caa = [];
  for (const rec of records.filter((r) => r.type === 'CAA')) {
    const parts = parseCaa(rec.rdata);
    if (parts) caa.push({ rec, parts });
  }

  return {
    domain,
    state,
    signals,
    counts,
    textual,
    spf,
    dmarc,
    dmarcTags: dmarc.length === 1 ? dmarcTags(txtValue(dmarc[0].rdata)) : {},
    dkimTxt,
    // A key is live when `p=` carries something. An empty `p=` is the RFC 6376
    // revocation form, which is the opposite of a live key.
    dkimLive: dkimTxt.filter((r) => /(^|;)\s*p\s*=\s*[^;\s]/i.test(txtValue(r.rdata))),
    dkimCname: records.filter((r) => r.type === 'CNAME' && /_domainkey/i.test(r.name)),
    mx: records.filter((r) => r.type === 'MX'),
    caa,
    caaBlockedBy: caaBlocker(records, { state }),
  };
}

function scoreOf(controls) {
  let num = 0;
  let den = 0;
  for (const c of controls) {
    if (c.status === 'na') continue;
    const weight = SEVERITY_WEIGHT[c.severity] ?? 0;
    den += weight;
    if (c.status === 'pass') num += weight;
  }
  return den === 0 ? null : Math.round((100 * num) / den);
}

/**
 * Grade from the score, capped at C when a critical control fails.
 *
 * The cap is the one non-linear rule, and it earns its place: without it a zone
 * with no SPF at all still reads "A" because the twenty other controls pass.
 */
function gradeOf(score, controls) {
  if (score === null) return null;
  const band = GRADE_BANDS.find(([min]) => score >= min);
  const grade = band ? band[1] : 'F';
  const criticalFail = controls.some((c) => c.status === 'fail' && c.severity === 'critical');
  return criticalFail && (grade === 'A' || grade === 'B') ? 'C' : grade;
}

function axisBreakdown(controls) {
  const axes = {};
  for (const axis of AXES) {
    const subset = controls.filter((c) => c.axis === axis);
    axes[axis] = {
      score: scoreOf(subset),
      pass: subset.filter((c) => c.status === 'pass').length,
      fail: subset.filter((c) => c.status === 'fail').length,
      na: subset.filter((c) => c.status === 'na').length,
    };
  }
  return axes;
}

/**
 * Score one zone against the baseline.
 *
 * `state` overrides the classifier — used by tests and by callers that already
 * classified. `classify` is called either way: the report carries the signals
 * and counts so a reader never has to open two files.
 */
export function evaluate(records, { domain = null, state = null } = {}) {
  const cls = classify(records, { domain });
  const effective = state ?? cls.state;
  const ctx = context(records, { domain, state: effective, signals: cls.signals, counts: cls.counts });

  const hardenable = effective !== 'mail-active';

  const controls = CONTROLS.map((control) => {
    const inScope = SCOPES[control.scope].includes(effective);
    const result = inScope
      ? control.check(records, ctx)
      : na(`out of scope for a ${effective} domain (control applies to: ${SCOPES[control.scope].join(', ')}).`);

    const remediation = result.status === 'fail' ? (result.remediation ?? null) : null;
    return {
      id: control.id,
      title: control.title,
      axis: control.axis,
      severity: control.severity,
      scope: control.scope,
      refs: control.refs,
      status: result.status,
      // Why a control is `na`. 'scope' is mechanical — it follows from the
      // state and says nothing a reader does not already know. 'check' is a
      // judgement the baseline made about this zone, and is worth reading.
      naReason: result.status !== 'na' ? null : (inScope ? 'check' : 'scope'),
      detail: result.detail,
      evidence: result.evidence ?? [],
      remediation: remediation && {
        text: remediation.text,
        // `harden` publishes `v=spf1 -all` and refuses a mail-active zone
        // anyway. Printing the command next to a finding on a domain that
        // legitimately sends mail is advice that would break that mail, so the
        // fix stays manual there.
        command: hardenable && remediation.command && domain
          ? remediation.command.replace('<domain>', domain)
          : (hardenable ? remediation.command ?? null : null),
      },
    };
  });

  const score = scoreOf(controls);
  return {
    domain,
    state: effective,
    signals: cls.signals,
    counts: cls.counts,
    score,
    grade: gradeOf(score, controls),
    tally: {
      pass: controls.filter((c) => c.status === 'pass').length,
      fail: controls.filter((c) => c.status === 'fail').length,
      na: controls.filter((c) => c.status === 'na').length,
    },
    axes: axisBreakdown(controls),
    controls,
  };
}

const mean = (values) => (values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : null);

/**
 * Roll per-domain reports up into a portfolio summary.
 *
 * The portfolio score is the unweighted mean of the per-domain scores, not a
 * pooled sum of weights: otherwise one zone with forty records would outvote
 * forty empty ones, and the number would stop meaning "how is the portfolio".
 * Domains with no backup are counted apart, never scored 0.
 */
export function aggregate(reports) {
  const scored = reports.filter((r) => typeof r.score === 'number');
  const errors = reports.filter((r) => r.state === 'error');

  const byState = {};
  const byGrade = {};
  for (const r of reports) byState[r.state] = (byState[r.state] ?? 0) + 1;
  for (const r of scored) byGrade[r.grade] = (byGrade[r.grade] ?? 0) + 1;

  const axes = {};
  for (const axis of AXES) {
    axes[axis] = mean(scored.map((r) => r.axes[axis].score).filter((s) => typeof s === 'number'));
  }

  const counters = new Map();
  for (const r of scored) {
    for (const c of r.controls) {
      if (c.status !== 'fail') continue;
      const entry = counters.get(c.id)
        ?? { id: c.id, title: c.title, axis: c.axis, severity: c.severity, refs: c.refs, count: 0 };
      entry.count++;
      counters.set(c.id, entry);
    }
  }
  const topFailures = [...counters.values()].sort((a, b) => b.count - a.count
    || (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0)
    || a.id.localeCompare(b.id));

  const score = mean(scored.map((r) => r.score));
  return {
    domains: reports.length,
    scored: scored.length,
    errors: errors.length,
    score,
    grade: score === null ? null : (GRADE_BANDS.find(([min]) => score >= min)?.[1] ?? 'F'),
    axes,
    byState,
    byGrade,
    topFailures,
  };
}
