# Compliance baseline

The control baseline behind `node ovh.mjs compliance`. Twenty-four checks, each one identified,
weighted, and mapped to a published reference, evaluated offline against the zone backups in
`storage/backups/`.

This document is the catalogue. For the French-language mapping to ISO/IEC 27001:2022, NIS2 and
the ANSSI guides, see [CONFORMITE.md](CONFORMITE.md). For the reasoning behind the records the
tool *publishes*, see [POLICY.md](POLICY.md).

---

## What it is for

The classifier answers *"is this domain safe to harden?"*. The baseline answers a different
question: *"what is the security posture of this portfolio, and what is the shortest path to
improving it?"* — with an answer you can hand to an auditor.

```bash
node ovh.mjs compliance                  # the whole portfolio
node ovh.mjs compliance example.com      # one domain
```

No network, no credentials. It reads the backups already on disk, so it is reproducible: the same
backups produce the same score, and two runs a month apart are comparable if the baseline version
has not changed.

Three artefacts are written to `storage/`:

| File | For |
|---|---|
| `compliance.md` | A human. Failures and judgement calls only — at sixty domains a full dump is unreadable. |
| `compliance.json` | A machine. Every control result, including passes, plus the weights used. |
| `compliance.csv` | An auditor. One row per (domain, control), passes included — evidence of what was checked. |

---

## The three axes

Every control belongs to exactly one axis, and each axis is scored on its own so a portfolio that
is strong on one and weak on another cannot hide behind a single average.

| Axis | Question it answers |
|---|---|
| **Anti-spoofing** | Can someone send mail that appears to come from this domain? |
| **Closed by default** | Does the domain permit, by omission, things nobody asked for — inbound mail, certificate issuance? |
| **Attack surface** | What is still reachable, still delegated, or still advertised that nobody uses any more? |

---

## Scope — every domain judged against the posture its own state calls for

`compliance` audits the **whole portfolio**, whatever the state of each domain. That is only
honest if a domain that legitimately sends mail is not marked down for publishing a DKIM key. So
every control declares a scope, and a control outside its scope returns `n/a`.

| Scope | Applies to | Idea |
|---|---|---|
| `all` | every state | True whatever the use: strict DMARC, no wildcard, no dangling CNAME. |
| `non-sending` | `dormant`, `web-active` | The domain must **not** be able to send: `-all`, DKIM revoked, no MX. |
| `sending` | `mail-active` | The domain sends legitimately: SPF not permissive, DKIM published, budget respected. |
| `dormant` | `dormant` only | The fully closed posture, including the CAA deny. |

Domains with no usable backup are reported as `error`, listed separately, and **excluded from
every average**. They are never scored zero: "not measured" and "measured badly" are different
facts, and conflating them would quietly drag a portfolio score down.

---

## The `n/a` doctrine

`n/a` is the part of a scoring model that is easiest to abuse, so it has exactly one rule:

> **A control returns `n/a` because the zone's *use* makes the question meaningless — never
> because a record is missing.** A missing record is a `fail`.

The distinction that makes this work is whether absence satisfies the property. A control that
**asserts** a security property fails when the record is absent: with no SPF at all, forged mail is
not rejected, so `spf.hardfail` fails — otherwise a wide-open domain would outscore one publishing
`~all`, which is perverse. A control that **bounds** something is satisfied vacuously: a record
that does not exist cannot be permissive, so `spf.no-permissive` and `spf.lookup-budget` pass.

A missing record therefore costs every control whose property it leaves unsatisfied, and no
others. That is deliberate: publishing no SPF is a worse posture than publishing a weak one, and
the score should say so.

`n/a` is excluded from the numerator **and** the denominator, and is always rendered with its
reason. The report distinguishes two:

- **`scope`** — mechanical. It follows from the state and tells a reader nothing they do not
  already know. Not shown in the markdown.
- **`check`** — a judgement the baseline made about *this* zone, and worth reading. Shown.

The CAA controls are the only ones that currently produce a `check`. A deny is withheld when
issuing a certificate is plausibly still needed — see below.

---

## Scoring

```
score = round(100 × Σ weight(pass) / Σ weight(pass ∪ fail))
```

| Severity | Weight |
|---|---:|
| `critical` | 10 |
| `high` | 6 |
| `medium` | 3 |
| `low` | 1 |

Grades: **A** ≥ 95, **B** ≥ 85, **C** ≥ 70, **D** ≥ 50, **F** below.

One non-linear rule: **a grade is capped at `C` if any `critical` control fails.** Without it a
zone with no SPF at all would show an A because the twenty other controls pass, which is exactly
the kind of number that gets a compliance tool distrusted.

The axis score is the same formula restricted to one axis. The **portfolio score is the
unweighted mean of the per-domain scores** — not a pooled weight sum — so one forty-record zone
cannot outvote forty empty ones.

A score is `null`, never `0`, when every applicable control is `n/a`.

---

## The controls

Control ids are a **public interface**: they appear in `compliance.json` and in anyone's
spreadsheet. Renaming one is a breaking change.

### Anti-spoofing

| id | Checks | Severity | Scope | References |
|---|---|---|---|---|
| `spf.present` | A `v=spf1` TXT exists at the apex. | critical | all | RFC 7208 §3 · ISO 27001 A.5.14 · NIS2 21(2)(g) |
| `spf.single` | Exactly one. Two SPF records are a `PermError` and receivers ignore **both** — a second SPF is worse than none. | critical | all | RFC 7208 §4.5 |
| `spf.hardfail` | The record ends in `-all`. Only the terminal qualifier counts; the mechanisms before it are `spf.no-senders`' business. | critical | non-sending | RFC 7208 §5.1 · ISO 27001 A.5.14 |
| `spf.no-senders` | The record carries no mechanism at all, only `all`. `v=spf1 include:mx.ovh.com -all` ends in a hard fail and still lets every host in a shared provider's SPF send as the domain: mechanisms are read left to right and the first match wins, so `-all` only covers what is left over. | high | non-sending | RFC 7208 §4.6.2 · ISO 27001 A.5.14 |
| `spf.no-permissive` | The record does not end in `+all` or `?all`, which authorise the whole internet. | critical | sending | RFC 7208 §5.1 |
| `spf.lookup-budget` | At most 10 DNS-resolving mechanisms. Over budget, evaluation returns `PermError` and the policy stops being applied. | medium | sending | RFC 7208 §4.6.4 |
| `dmarc.present` | Exactly one DMARC record on `_dmarc`. Duplicates are ignored by receivers. | critical | all | RFC 7489 §6.1 · ISO 27001 A.5.14 · NIS2 21(2)(g) |
| `dmarc.reject` | `p=reject`. Neither `p=none` (monitoring only) nor `p=quarantine` stops delivery. | critical | all | RFC 7489 §6.3 · ISO 27001 A.5.14 |
| `dmarc.subdomain-reject` | `sp=reject` stated explicitly, so a forged `invoices.example.com` is covered without relying on inheritance. | high | all | RFC 7489 §6.3 |
| `dmarc.strict-alignment` | `adkim=s` and `aspf=s`. Relaxed alignment lets any subdomain of an authorised organisational domain align. | medium | all | RFC 7489 §3.1 |
| `dkim.wildcard-revoked` | `*._domainkey` publishes `v=DKIM1; p=`, declaring every selector keyless. | high | non-sending | RFC 6376 §3.6.1 |
| `dkim.no-live-selector` | No selector still carries a usable key — neither a TXT with a non-empty `p=`, nor a `_domainkey` CNAME delegating to a provider. | critical | non-sending | RFC 6376 §3.6.1 · ISO 27001 A.5.14 |
| `dkim.selector-published` | At least one valid selector exists, so DMARC can pass on DKIM rather than on SPF alone. | high | sending | RFC 6376 §3.6.1 |

### Closed by default

| id | Checks | Severity | Scope | References |
|---|---|---|---|---|
| `mx.closed` | No MX routing mail to a real host. A null MX counts as closed. | high | non-sending | RFC 7505 · ISO 27001 A.8.20 |
| `mx.null-explicit` | The null MX is **published**, not merely absent. Absence is ambiguous; `0 .` is a statement. | low | dormant | RFC 7505 §3 |
| `caa.issue-deny` | A CAA record denies issuance: `0 issue ";"`. | high | dormant | RFC 8659 §4.2 · ISO 27001 A.8.21 |
| `caa.issuewild-deny` | Wildcard issuance denied too. With no `issuewild` property present the `issue` deny governs wildcards, and the control passes. | medium | dormant | RFC 8659 §4.3 |
| `caa.present` | Some CAA record exists, restricting which CAs may issue. Scored on every state — even a live web host benefits from naming its CA. | medium | all | RFC 8659 §4.2 · ISO 27001 A.8.21 |
| `caa.no-permissive` | No CAA still authorising a CA that nothing uses — a stale `letsencrypt.org` entry on a parked domain is an open door. | medium | dormant | RFC 8659 §4.2 |

**When the CAA controls return `n/a`.** A CAA deny at the apex is inherited by every subdomain
(RFC 8659) and will stop a certificate renewing. The baseline withholds the deny — and the tool
refuses to publish one — when any of these is true:

- the zone is `web-active`;
- it carries an OVH web-redirection marker;
- an `_acme-challenge` TXT is present, meaning issuance is in flight;
- the apex or `www` still resolves to a live host outside OVH's parking range.

One predicate, two consumers: the same `caaBlocker()` produces the `n/a` here and the
`caa : skipped — …` line in `harden --caa`.

### Attack surface

| id | Checks | Severity | Scope | References |
|---|---|---|---|---|
| `wildcard.none` | No `*` A/AAAA/CNAME. A wildcard makes every name anyone invents resolve, which is a phishing convenience and an inventory hole. `*._domainkey` is not a host wildcard and does not count. | high | all | RFC 4592 · ISO 27001 A.8.20 |
| `services.no-legacy` | No leftover service subdomain — `autodiscover`, `autoconfig`, `webmail`, `smtp`, `lyncdiscover`, `enterpriseregistration` and friends — advertising a mail platform the domain no longer uses. | medium | non-sending | ISO 27001 A.5.9 |
| `srv.none` | No residual SRV record advertising a service endpoint. | low | non-sending | RFC 2782 |
| `cname.no-takeover` | No CNAME pointing at a platform where an unclaimed target can be registered by someone else — object storage, pages hosting, PaaS. | critical | all | ISO 27001 A.5.9 · NIS2 21(2)(a) |
| `txt.no-stale-verification` | No third-party domain-verification TXT left behind after the service was dropped. Each one is a standing authorisation for a service nobody monitors. | low | non-sending | ISO 27001 A.5.9 |

> **What `cname.no-takeover` does and does not claim.** Offline DNS cannot prove a target is
> unclaimed — that needs an HTTP request to the platform. The finding says *verify that this
> target is still claimed*; it does not assert a takeover. The platform list is a constant in
> `lib/baseline.mjs` carrying a `REVIEWED` date, and it goes stale: treat it as a prompt to look,
> not as an exhaustive catalogue.

---

## Reading a report

```markdown
### other.example — 31/100 (F)

dormant · 5 pass · 9 fail · 2 n/a · source `backups/other.example/2026-09-16T10-02-11-004Z.zone`

- **!! `spf.present` (critical)** — no `v=spf1` TXT record at the apex.
  refs: RFC 7208 §3 · ISO/IEC 27001:2022 A.5.14 · NIS2 Art. 21(2)(g)
  fix: publish the anti-spoofing policy `node ovh.mjs harden other.example --apply`
- `n/a` `caa.issue-deny` — not evaluated: the apex or www still resolves to a live host.
```

`!!` marks a critical failure. A `fix` line with a command means the tool can do it; without one
the fix is manual — a `_domainkey` CNAME, for instance, is a CNAME and the policy does not remove
CNAMEs it did not put there.

---

## Versioning

| version | change |
|---|---|
| 1.1.0 | `spf.no-senders` added (high, non-sending). No zone in the portfolio failed it, but the extra passing weight moves every non-sending score a point or two. |
| 1.0.0 | The first catalogue: 23 controls. |

`BASELINE_VERSION` is stamped into every report. Adding a control, changing a weight or changing a
scope changes a score without anything changing in DNS, so **compare two reports only when the
version matches.** Bump it whenever the catalogue or the scoring model changes; control ids, being
a public interface, are not renamed in place.

The `refs` field is data, not code: correcting or enriching a reference never requires touching
the evaluation logic.
