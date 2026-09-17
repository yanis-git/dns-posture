// THE POLICY. Data, not code.
//
// Not to be confused with `lib/config.mjs`, which resolves paths and loads
// credentials. This file answers a different question: for each compliance
// check, what does `harden` do when it fails?
//
// It is plain frozen data with no imports, and it is the only file an operator
// needs to edit to change what the tool publishes or deletes. The engine holds
// the check predicates and the displacement rules; everything below is a
// decision, and every decision is reviewable in a diff.
//
// Three things live here:
//
//   records   what may be published, each naming the displacer that says what
//             it competes with (the displacers themselves are a closed table
//             in lib/zone.mjs — a config can turn one on, never widen one)
//   checks    the audit metadata of the 23 controls: title, axis, severity, refs
//   profiles  per classifier state, what each of the 23 checks does on failure
//
// Every check is declared in every profile, on purpose. Adding a control makes
// this file fail validation until someone decides what it should do on a
// dormant, a web-active and a mail-active domain — at review time, which is the
// only time anyone is thinking about it.
//
// The six actions:
//
//   add      publish the record, but only if nothing competes with it
//   enforce  publish the record and delete what competes (= remove + add)
//   remove   delete what competes and publish nothing
//   manual   no DNS change; the check's own remediation prose stands
//   report   scored, no remedy — a finding an operator acts on deliberately
//   off      not evaluated; `na` with the stated reason, shown in the report
//
// `manual` takes an optional `text:` to override the check's prose. Without it
// the check keeps the wording it already produces, which is usually better —
// it has the evidence.
//
// See docs/POLICY.md for the reasoning behind each published record, and
// `node ovh.mjs policy <domain>` for the effective policy on one domain.

export default Object.freeze({
  version: 1,

  defaults: {
    ttl: 3600,

    // A `keep` pattern is a safety assertion, so the three levels (defaults,
    // profile, domain) are UNIONED, never replaced. Matched against both the
    // record's target and its subdomain.
    //
    // Deleting an `_acme-challenge` breaks a certificate renewal; deleting a
    // verification TXT silently detaches a Search Console property or an M365
    // tenant. These are exactly the records `txt.no-stale-verification` reports
    // rather than removes.
    keep: [/_acme-challenge/i, /site-verification/i, /^"?MS=/i],

    // Legacy hosting plumbing, deleted whatever the findings say. Known wart:
    // this is the one deletion that is not licensed by a failing check, and
    // `services.no-legacy` still describes the `ftp` family as deliberately out
    // of the hardening policy. Moving it to a remedy would change every score.
    dropCnames: ['ftp'],

    // OVH web-redirection markers (`3|www.example.com`). Not mail records, and
    // deleting one breaks a live redirect.
    dropRedirect: false,
  },

  // -------------------------------------------------------------------------
  // Records the policy may publish
  // -------------------------------------------------------------------------
  //
  // `displaces` names a key of DISPLACERS in lib/zone.mjs. `exclusive` marks a
  // record type that does not tolerate a second one at the same name: an `add`
  // then refuses rather than publish a duplicate, because two SPF records are a
  // PermError (RFC 7208 §4.5) and two DMARC records make receivers discard the
  // policy entirely (RFC 7489 §6.6.3) — strictly worse than the one that was
  // already there.
  //
  // To publish DMARC aggregate reports, append `; rua=mailto:you@example.com`
  // to the dmarc.reject target. To ask CAs to report violations, add a record
  // here with `displaces: 'apex-caa-iodef'` and a remedy pointing at it. Both
  // were CLI flags before 0.3.0.
  records: Object.freeze({
    'spf.deny': {
      subDomain: '', fieldType: 'TXT', target: 'v=spf1 -all',
      displaces: 'apex-spf', exclusive: true,
      why: 'SPF: no authorised sender',
    },
    'dmarc.reject': {
      subDomain: '_dmarc', fieldType: 'TXT',
      target: 'v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s',
      displaces: 'apex-dmarc', exclusive: true,
      why: 'DMARC: strict reject, subdomains included',
    },
    'dkim.revoke': {
      // Deliberately NOT exclusive: the wildcard coexists with named selectors,
      // and revoking every key is `dkim.no-live-selector`'s job, not this one's.
      subDomain: '*._domainkey', fieldType: 'TXT', target: 'v=DKIM1; p=',
      displaces: 'apex-dkim', exclusive: false,
      why: 'DKIM: every key revoked',
    },
    'mx.null': {
      subDomain: '', fieldType: 'MX', target: '0 .',
      displaces: 'apex-mx', exclusive: true,
      why: 'Null MX (RFC 7505): the domain receives no mail',
    },
    'caa.deny-issue': {
      // UNVERIFIED AGAINST THE OVH API. Neither the OVH documentation nor the
      // Terraform provider states the `target` syntax for fieldType CAA, so
      // this is the zone-file form. Confirm it on a throwaway zone before the
      // first --apply that publishes one.
      subDomain: '', fieldType: 'CAA', target: '0 issue ";"',
      displaces: 'apex-caa-issue', exclusive: true,
      why: 'CAA: no CA may issue for this domain',
    },
    'caa.deny-issuewild': {
      subDomain: '', fieldType: 'CAA', target: '0 issuewild ";"',
      displaces: 'apex-caa-issuewild', exclusive: true,
      why: 'CAA: no wildcard certificate either',
    },
  }),

  // -------------------------------------------------------------------------
  // The catalogue: audit metadata, shared by every profile
  // -------------------------------------------------------------------------
  //
  // The ids are a PUBLIC INTERFACE. They are written into compliance.json and
  // compliance.csv and end up in other people's spreadsheets and remediation
  // plans. Renaming one is a breaking change; add a new check instead.
  //
  // Changing a severity changes every score without a single DNS record
  // changing, so bump BASELINE_VERSION when you touch one.
  checks: Object.freeze({
    'spf.present': {
      title: 'SPF published at the apex',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7208 §3', 'ISO/IEC 27001:2022 A.5.14', 'NIS2 Art. 21(2)(g)'],
    },
    'spf.single': {
      title: 'No conflicting SPF record at the apex',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7208 §4.5'],
    },
    'spf.hardfail': {
      title: 'SPF ends in a hard fail',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7208 §5.1', 'ISO/IEC 27001:2022 A.5.14'],
    },
    'spf.no-permissive': {
      title: 'SPF does not authorise the whole internet',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7208 §5.1'],
    },
    'spf.lookup-budget': {
      title: 'SPF stays within the DNS lookup budget',
      axis: 'spoofing', severity: 'medium',
      refs: ['RFC 7208 §4.6.4'],
    },
    'dmarc.present': {
      title: 'A single DMARC record on `_dmarc`',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7489 §6.1', 'ISO/IEC 27001:2022 A.5.14', 'NIS2 Art. 21(2)(g)'],
    },
    'dmarc.reject': {
      title: 'DMARC policy is `p=reject`',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 7489 §6.3', 'ISO/IEC 27001:2022 A.5.14'],
    },
    'dmarc.subdomain-reject': {
      title: 'Subdomain policy stated explicitly',
      axis: 'spoofing', severity: 'high',
      refs: ['RFC 7489 §6.3'],
    },
    'dmarc.strict-alignment': {
      title: 'Strict DMARC alignment',
      axis: 'spoofing', severity: 'medium',
      refs: ['RFC 7489 §3.1'],
    },
    'dkim.wildcard-revoked': {
      title: 'Wildcard DKIM revocation published',
      axis: 'spoofing', severity: 'high',
      refs: ['RFC 6376 §3.6.1'],
    },
    'dkim.no-live-selector': {
      title: 'No residual DKIM selector',
      axis: 'spoofing', severity: 'critical',
      refs: ['RFC 6376 §3.6.1', 'ISO/IEC 27001:2022 A.5.14'],
    },
    'dkim.selector-published': {
      title: 'At least one DKIM selector published',
      axis: 'spoofing', severity: 'high',
      refs: ['RFC 6376 §3.6.1'],
    },
    'mx.closed': {
      title: 'No inbound mail route',
      axis: 'closed', severity: 'high',
      refs: ['RFC 7505', 'ISO/IEC 27001:2022 A.8.20'],
    },
    'mx.null-explicit': {
      title: 'Null MX published rather than merely absent',
      axis: 'closed', severity: 'low',
      refs: ['RFC 7505 §3'],
    },
    'caa.issue-deny': {
      title: 'CAA denies certificate issuance',
      axis: 'closed', severity: 'high',
      refs: ['RFC 8659 §4.2', 'ISO/IEC 27001:2022 A.8.21'],
    },
    'caa.issuewild-deny': {
      title: 'CAA denies wildcard certificates',
      axis: 'closed', severity: 'medium',
      refs: ['RFC 8659 §4.3'],
    },
    'caa.present': {
      title: 'A CAA record restricts the authorised CAs',
      axis: 'closed', severity: 'medium',
      refs: ['RFC 8659 §4.2', 'ISO/IEC 27001:2022 A.8.21'],
    },
    'caa.no-permissive': {
      title: 'No CAA authorising an unused CA',
      axis: 'closed', severity: 'medium',
      refs: ['RFC 8659 §4.2'],
    },
    'wildcard.none': {
      title: 'No DNS wildcard',
      axis: 'surface', severity: 'high',
      refs: ['RFC 4592', 'ISO/IEC 27001:2022 A.8.20'],
    },
    'services.no-legacy': {
      title: 'No residual service subdomain',
      axis: 'surface', severity: 'medium',
      refs: ['ISO/IEC 27001:2022 A.5.9'],
    },
    'srv.none': {
      title: 'No residual SRV record',
      axis: 'surface', severity: 'low',
      refs: ['RFC 2782'],
    },
    'cname.no-takeover': {
      title: 'No CNAME towards a takeover-prone platform',
      axis: 'surface', severity: 'critical',
      refs: ['ISO/IEC 27001:2022 A.5.9', 'NIS2 Art. 21(2)(a)'],
    },
    'txt.no-stale-verification': {
      title: 'No residual third-party verification TXT',
      axis: 'surface', severity: 'low',
      refs: ['ISO/IEC 27001:2022 A.5.9'],
    },
  }),

  // -------------------------------------------------------------------------
  // Profiles: one per classifier state
  // -------------------------------------------------------------------------
  //
  // The state comes from the classifier, and nothing in this file can change
  // it. In particular, the `mail-active` refusal in `harden` is keyed on the
  // classified state, not on the profile — an override below cannot reach it.
  profiles: Object.freeze({

    // A domain nobody uses. The whole point of the tool: it should send no
    // mail, receive no mail, and say so loudly enough that receivers act on it.
    dormant: {
      states: ['dormant'],
      checks: {
        'spf.present': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.single': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.hardfail': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.no-permissive': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },
        'spf.lookup-budget': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },

        'dmarc.present': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.reject': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.subdomain-reject': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.strict-alignment': { remedy: { action: 'enforce', record: 'dmarc.reject' } },

        // `add`, not `enforce`: publishing the wildcard revocation is closure
        // by default and removes nothing. Deleting the leftover selectors is
        // the next check's job, and it is a `critical` for a reason.
        'dkim.wildcard-revoked': { remedy: { action: 'add', record: 'dkim.revoke' } },
        'dkim.no-live-selector': { remedy: { action: 'enforce', record: 'dkim.revoke' } },
        'dkim.selector-published': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },

        // `remove`, not `enforce`: delete the inbound route, publish nothing.
        // A null MX is a separate, opt-in decision — OVH refuses the record on
        // some zones, which is why `mx.null-explicit` below stays a `report`
        // and keeps failing on a hardened zone. That is the pre-0.3.0
        // behaviour of `harden` without `--null-mx`, preserved deliberately.
        'mx.closed': { remedy: { action: 'remove', record: 'mx.null' } },
        'mx.null-explicit': { remedy: { action: 'report' } },

        // The old `--caa` opt-in, preserved as data. Switching these to
        // `enforce` with `caa.deny-issue` / `caa.deny-issuewild` publishes an
        // issuance deny — read docs/POLICY.md first: a CAA at the apex governs
        // every subdomain, and the failure surfaces 60 to 90 days later at the
        // next renewal. The resolver demotes these to `report` anyway on any
        // zone `caaBlocker` considers unsafe, so the audit and the writer
        // cannot disagree about it.
        'caa.issue-deny': { remedy: { action: 'report' } },
        'caa.issuewild-deny': { remedy: { action: 'report' } },
        'caa.present': { remedy: { action: 'report' } },
        'caa.no-permissive': { remedy: { action: 'report' } },

        // Attack surface: real findings, but the fix is a judgement call about
        // something the domain owner put there on purpose.
        'wildcard.none': { remedy: { action: 'manual' } },
        'services.no-legacy': { remedy: { action: 'manual' } },
        'srv.none': { remedy: { action: 'manual' } },
        'cname.no-takeover': { remedy: { action: 'manual' } },

        // Reported, never deleted: these are the records `keep` protects, and
        // removing one silently detaches a live third-party integration.
        'txt.no-stale-verification': { remedy: { action: 'report' } },
      },
    },

    // Serves web content but sends no mail. Same mail posture as a dormant
    // domain — the mail checks do not care that a web server answers — but the
    // certificate checks are out of scope, because a live site needs renewals.
    'web-active': {
      states: ['web-active'],
      checks: {
        'spf.present': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.single': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.hardfail': { remedy: { action: 'enforce', record: 'spf.deny' } },
        'spf.no-permissive': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },
        'spf.lookup-budget': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },

        'dmarc.present': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.reject': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.subdomain-reject': { remedy: { action: 'enforce', record: 'dmarc.reject' } },
        'dmarc.strict-alignment': { remedy: { action: 'enforce', record: 'dmarc.reject' } },

        'dkim.wildcard-revoked': { remedy: { action: 'add', record: 'dkim.revoke' } },
        'dkim.no-live-selector': { remedy: { action: 'enforce', record: 'dkim.revoke' } },
        'dkim.selector-published': { remedy: { action: 'off' }, reason: 'scope: applies to sending domains' },

        'mx.closed': { remedy: { action: 'remove', record: 'mx.null' } },
        'mx.null-explicit': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },

        // Off by scope, and it would be wrong anyway: the site needs a
        // certificate, so denying issuance breaks the next renewal.
        'caa.issue-deny': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.issuewild-deny': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.no-permissive': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.present': { remedy: { action: 'report' } },

        'wildcard.none': { remedy: { action: 'manual' } },
        'services.no-legacy': { remedy: { action: 'manual' } },
        'srv.none': { remedy: { action: 'manual' } },
        'cname.no-takeover': { remedy: { action: 'manual' } },
        'txt.no-stale-verification': { remedy: { action: 'report' } },
      },
    },

    // The domain sends or receives real mail. NOTHING is written here: every
    // remedy is `manual` or `report`, so the plan is empty even under --force.
    // That is the second lock on invariant #3 — the first is the refusal in
    // `harden`, keyed on the classified state.
    //
    // The findings still matter. They are just a conversation with whoever
    // runs that mail, not something a batch job applies at 3am.
    'mail-active': {
      states: ['mail-active'],
      // Nothing on a live sending zone is ours to delete — not even the legacy
      // `ftp` CNAME the defaults drop elsewhere. Emptying the list here is what
      // makes "this profile writes nothing" true of the whole plan and not just
      // of the 23 remedies; a --force that lifts the guard still finds nothing
      // to do.
      dropCnames: [],
      checks: {
        'spf.present': { remedy: { action: 'manual' } },
        'spf.single': { remedy: { action: 'manual' } },
        'spf.hardfail': { remedy: { action: 'off' }, reason: 'scope: a sending domain must not publish `-all`' },
        'spf.no-permissive': { remedy: { action: 'manual' } },
        'spf.lookup-budget': { remedy: { action: 'manual' } },

        'dmarc.present': { remedy: { action: 'manual' } },
        'dmarc.reject': { remedy: { action: 'manual' } },
        'dmarc.subdomain-reject': { remedy: { action: 'manual' } },
        'dmarc.strict-alignment': { remedy: { action: 'manual' } },

        'dkim.wildcard-revoked': { remedy: { action: 'off' }, reason: 'scope: revoking every key would break this domain\'s mail' },
        'dkim.no-live-selector': { remedy: { action: 'off' }, reason: 'scope: a sending domain needs its selectors' },
        'dkim.selector-published': { remedy: { action: 'manual' } },

        'mx.closed': { remedy: { action: 'off' }, reason: 'scope: the domain receives mail' },
        'mx.null-explicit': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },

        'caa.issue-deny': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.issuewild-deny': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.no-permissive': { remedy: { action: 'off' }, reason: 'scope: applies to dormant domains' },
        'caa.present': { remedy: { action: 'manual' } },

        'wildcard.none': { remedy: { action: 'manual' } },
        'services.no-legacy': { remedy: { action: 'off' }, reason: 'scope: applies to non-sending domains' },
        'srv.none': { remedy: { action: 'off' }, reason: 'scope: applies to non-sending domains' },
        'cname.no-takeover': { remedy: { action: 'manual' } },
        'txt.no-stale-verification': { remedy: { action: 'off' }, reason: 'scope: applies to non-sending domains' },
      },
    },
  }),

  // -------------------------------------------------------------------------
  // Per-domain overrides
  // -------------------------------------------------------------------------
  //
  // `reason` is MANDATORY. This tool deletes DNS records; an exception to it
  // needs a written justification, and requiring one at load time is free.
  // The reason is rendered in the compliance report, so an `off` here is an
  // exception an auditor can see rather than a silent gap.
  //
  //   'client.example': {
  //     keep: [/^"?bigco-verify/i],
  //     checks: { 'caa.issue-deny': { remedy: { action: 'off' } } },
  //     reason: "Let's Encrypt certificate live until 2027 — ticket OPS-4412",
  //   },
  //
  // `profile:` pins a named profile regardless of the classified state. It does
  // NOT lift the mail-active refusal: that guard reads the state directly.
  domains: Object.freeze({}),
});
