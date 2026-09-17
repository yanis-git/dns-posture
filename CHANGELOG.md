# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-16

A compliance baseline, a portfolio-wide offline audit, and an optional default-deny CAA record.

### Added

- **`compliance` command.** Scores the whole portfolio against a baseline of 23 identified,
  weighted controls across three axes — anti-spoofing, closed by default, attack surface — and
  writes `storage/compliance.{md,json,csv}`. Runs entirely offline from the zone backups already on
  disk: no credentials, no network, and the same backups always produce the same score.
- **`lib/baseline.mjs`** — the control catalogue and scoring model, pure and free of I/O. Each
  control carries an id, a severity weight, a scope, references (RFC, ISO/IEC 27001:2022, NIS2) and
  a remediation. Control ids are a public interface.
- **Every domain is audited, each against the posture its own state calls for.** A `mail-active`
  domain is not marked down for publishing a DKIM key. Domains with no backup are reported as
  errors and excluded from every average, never scored zero.
- **`--caa` / `--iodef`.** Optionally publishes `CAA 0 issue ";"` and `0 issuewild ";"` (RFC 8659),
  denying certificate issuance on a dormant domain. Opt-in, because a CAA deny at the apex is
  inherited by every subdomain and surfaces as a failed renewal 60-90 days later. `harden` refuses
  to publish one on a zone that still serves web content, carries an OVH redirect, still resolves,
  or has an ACME challenge in flight.
- **An existing CAA is never deleted unless the policy republishes one** — a bare deletion loosens
  the zone, since no CAA means every CA may issue.
- `README.fr.md`, `docs/BASELINE.md` (the control catalogue) and `docs/CONFORMITE.md` (the French
  control-to-requirement mapping for ISO/IEC 27001:2022, NIS2 and the ANSSI guides).
- `parseCaa()`, exported from `lib/harden.mjs`: a tolerant CAA parser shared by the policy engine
  and the baseline, so both read the same value whatever quoting OVH stored it with.

### Changed

- **`recordLabel` no longer quotes non-textual targets.** A CAA printed as `@ CAA "0 issue ";""`
  was unreadable. `MX` now prints as `@ MX 0 .` rather than `@ MX "0 ."`; only TXT/SPF/DKIM/DMARC
  are quoted. This changes plan output.
- `renderInventory` accepts an optional third `scores` argument. Omitting it — which every current
  caller does — produces byte-identical output.
- `fetchRecords` also queries `CAA`, and skips a field type the account's API rejects with a 400
  rather than aborting the run.
- **A CAA, MX or verification TXT on a subdomain is now kept, not deleted** — a consequence of the
  apex fix above. An `_acme-challenge` TXT left mid-validation survives a `harden` for the same
  reason. The MX deletion reason changed from `MX on a dormant domain` to `MX at the apex`, which
  is what it always meant.
- `classify` returns an additional `apexSends` boolean. Anything asserting on the whole return
  object rather than a field needs updating.

### Fixed

- **`planZone` no longer treats a subdomain record as if it were the apex's.** It deleted any MX,
  CAA or textual record whose *type* competed with the policy, wherever that record sat in the
  zone. On a domain delegating its mail to an ESP subdomain, a dry-run proposed deleting
  `mg MX`, `mg TXT "v=spf1 include:…"`, `_dmarc.mg` and `email._domainkey.mg` — the entire sending
  configuration — while the apex it was actually hardening stayed untouched. Applied, that takes
  the customer's mail with it.

  The policy publishes at the apex, so it may only remove what competes with what it publishes:
  `@`, `_dmarc`, and `<selector>._domainkey`. Everything else is kept with a reason naming why.
  A suffix test separates the two families — `sel._domainkey` is ours, `email._domainkey.mg`
  belongs to the sending subdomain. Same for `_dmarc` against `_dmarc.mg`.
- **`classify` reports where the mail lives, not just that it exists.** A new `apexSends` field
  distinguishes a domain that sends from its own apex from one that only sends through a delegated
  subdomain, and MX signals name the subdomain they were found on. The `state` is unchanged and
  stays deliberately conservative — the fail-safe direction is still "assume it is in use" — so
  the `mail-active` guard is not weakened. `apexSends` answers the narrower question the guard
  cannot: is `v=spf1 -all` at the apex safe to publish?

### Known limitations

- **The OVH `target` syntax for `fieldType: CAA` is not documented and has not been verified
  against a live account.** The published value is the zone-file form. Confirm it on a throwaway
  zone before the first `--apply --caa`: if OVH rejects it, the run reports a creation error and
  the zone is left with no CAA — looser, not broken, and `restore` puts it back.
- ANSSI recommendation numbers (`R1`, `R2`, …) are deliberately **not** cited. The guides
  themselves are referenced by title and reference; the individual numbers were not verified, and
  a compliance artefact citing a wrong reference is worse than one citing none.

## [0.1.0] — 2026-09-10

First public release. The tool had been in private use against a real portfolio before this;
this release packages it, translates it to English, and adds a test suite around the parts where
a mistake is destructive.

### Added

- `auth`, `whoami`, `snapshot`, `inventory`, `audit`, `harden`, `harden-batch`, `restore`.
- Dormant / web-active / mail-active classification with an explicit fail-safe on unrecognised
  mail hosts.
- Zone backup before every mutation, and `restore` to put a zone back.
- Consolidated batch reports in Markdown and JSON.
- `--help` and `--version`.
- `OVH_STORAGE_DIR` to relocate the data directory, and `OVH_ENV_FILE` to point at a different
  credentials file.
- 118 tests (`node --test`) covering the parser, classifier, policy engine, signed client,
  inventory rendering, argument parsing and the CLI end to end. No test touches the network.
- CI: lint and tests on Node 20.12 / 22 / 24, a secret scan, and a job that fails the build if a
  zone dump, CSV export or credentials file is ever committed.

### Fixed

- **Records named after a record type were misparsed.** `mx 3600 IN A 1.2.3.4` was read as an MX
  record with the *previous* line's name, because the parser matched the first RR-type token
  anywhere on the line. A domain with an `mx`, `ns`, `a`, `srv`, `ptr` or `caa` subdomain could
  therefore be classified `mail-active` and skipped for ever.
- **A null MX classified as mail-active.** `MX 0 .` (RFC 7505) matched no known provider and fell
  into the unknown-host fail-safe, so a domain hardened with `--null-mx` came back as
  `mail-active` on the next inventory and was skipped by subsequent batch runs.
- **A missing `.env` crashed the CLI before it could print anything**, including `--help`, on a
  fresh clone.
