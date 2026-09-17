// The twenty-three check predicates, and the context they read.
//
// A check answers one question about one zone and returns pass / na / fail
// with its evidence. It knows nothing about scoring, about which profile
// selected it, or about what gets written afterwards: the catalogue metadata
// (title, axis, severity, references) and the remedy live in the policy
// config, and the scoring lives in baseline.mjs. This module is the part that
// has to be JavaScript, because a predicate over a zone is code.
//
// Check ids are a PUBLIC INTERFACE. They are written to compliance.json and
// compliance.csv, they are the keys of config/policy.mjs, and they end up in
// someone's remediation plan. Renaming one is a breaking change; add a new
// check instead.
//
// Two rules govern `na`:
//
//   1. A check returns `na` because the zone's USE makes the question
//      meaningless — a mail-active domain is not expected to revoke its DKIM
//      keys — never as a softer `fail` for a missing record.
//   2. `na` is excluded from the numerator AND the denominator of the score,
//      and is always rendered with its reason, never silently dropped.
//
// A missing record is therefore a `fail`. One distinction decides several
// checks below: whether absence satisfies the property. A check that ASSERTS
// something ("the domain must declare a hard fail") fails when the record is
// absent — with no SPF at all, forged mail is not rejected, so spf.hardfail
// fails; the alternative would let a wide-open domain outscore one publishing
// `~all`. A check that BOUNDS something ("at most 10 DNS lookups", "not
// permissive") is satisfied vacuously, since a record that does not exist
// cannot exceed a budget or authorise anyone. A missing record costs every
// check whose property it leaves unsatisfied, and no others.

import {
  caaBlocker,
  dmarcTags,
  fqdn,
  isDeny,
  isTextual,
  lower,
  parseCaa,
  spfAll,
  spfLookups,
  txtValue,
  zoneLabel as label,
} from './zone.mjs';

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

/** Cap the evidence list: a finding is a pointer, not a zone dump. */
function evidence(list, cap = 5) {
  const out = list.slice(0, cap);
  if (list.length > cap) out.push(`... +${list.length - cap} more`);
  return out;
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
  const textual = records.filter((r) => isTextual(r.type));
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
/** The same catalogue keyed by id, which is how the policy config names them. */
export const CHECKS = Object.freeze(Object.fromEntries(CONTROLS.map((c) => [c.id, c])));

export { context };

// `na` crosses the module boundary: baseline.mjs builds the out-of-scope
// result, which is the one `na` a check never produces itself.
export { na };
