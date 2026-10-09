# AGENTS.md

Guidance for coding agents and contributors working in this repository.

## What this is

A zero-dependency Node CLI that inventories OVH and Cloudflare domains, scores them against a compliance
baseline, and publishes an anti-spoofing DNS policy on the dormant ones. It deletes DNS records in
production. Treat every change to `lib/harden.mjs` and `lib/inventory.mjs` as safety-critical.

## Layout

```
dns-posture.mjs       Primary executable (ovh.mjs / ovh-domain-manager remain aliases)
lib/live.mjs         Provider orchestration and shared snapshot boundary
lib/engine.mjs       Shared classification / evaluation / resolution / planning
lib/transaction.mjs  Backups, integrity, locks, operations and verification
lib/providers/       OVH and Cloudflare native adapters
ovh.mjs              CLI entrypoint: subcommand dispatch, orchestration, reports
lib/ovh-client.mjs    Signed OVH v1 API client (bounded read retries, no write retries)
lib/inventory.mjs     Zone-file parser + dormant/web-active/mail-active classifier
lib/harden.mjs        Policy engine: buildPolicy / planZone / applyPlan
lib/baseline.mjs      Compliance control catalogue + scoring (pure, offline, no I/O)
lib/report.mjs        Inventory markdown rendering + the backup store
lib/cli.mjs           Argument parsing, CSV and batch-file readers
lib/config.mjs        Path resolution and credential loading
test/                 node --test, one file per lib + an end-to-end CLI smoke suite
```

## Data flow

```
snapshotDomain(ovh, domain)
  GET /domain/zone/<d>/export  ->  saveBackup()  ->  parseZone()  ->  classify()
                                                                        |
                       state === 'mail-active' ? refuse (or --force)  <-+
                                                                        |
  fetchRecords()  ->  planZone(records, buildPolicy())  ->  print  ->  applyPlan() if --apply
                                                                        |
                                                     tickDomain() + report to storage/reports/
```

`snapshotDomain` in `lib/live.mjs` is the shared composition point for `snapshot`, `harden`, `harden-batch` and `restore`. Every path that mutates a zone goes through it and `applyTransaction` first, which is what guarantees a
backup exists before any deletion.

`inventory` and `compliance` share a second, offline path that never opens a socket:

```
latestBackup()  ->  readFileSync()  ->  parseZone()  ->  classify()          ->  renderInventory()
                                                     ->  evaluate()/aggregate()  ->  renderCompliance()
```

Neither builds a client, so both run with no credentials and no network — which is also what makes
them testable end-to-end in the smoke suite. Module direction is
`report -> baseline -> {inventory, harden}`, and it must stay acyclic.

## Invariants — do not weaken these

1. **Dry-run is the default.** No command writes to OVH without an explicit `--apply`.
2. **A backup precedes every mutation.** Never add a write path that skips `snapshotDomain`.
3. **The `mail-active` guard stays.** `harden` refuses a mail-active zone unless `--force`;
   `harden-batch` skips them and refuses `--force` entirely. An unrecognised MX must keep
   classifying as `mail-active` — the fail-safe direction is "assume it is in use".
4. **`planZone` is idempotent.** A record already at the policy value is neither deleted nor
   recreated. Breaking this causes needless zone churn and DNS propagation delays on every run.
5. **A hardened zone still classifies as `dormant`.** Otherwise domains re-enter the worklist for
   ever and batch runs start skipping them. Covered by the round-trip tests in
   `test/inventory.test.mjs`.
6. **OVH redirect markers (`^\d+\|`) are preserved** unless `--drop-redirect` is passed. They are
   not mail records; deleting them breaks a live web redirect.
7. **`--keep` wins over every deletion rule**, including MX.
8. **No runtime dependencies.** Node builtins and global `fetch` only. Dev dependencies (ESLint)
   are fine.
9. **A CAA record is never deleted unless the policy republishes one.** A bare deletion *loosens*
   the zone — no CAA at all means every CA may issue. `planZone` keeps an existing CAA when the
   policy carries none.
10. **`planZone` only deletes records the apex policy owns.** The policy publishes at the apex, so
   the names it may remove are `@`, `_dmarc` and `<selector>._domainkey` — and no others. The
   record *type* cannot decide this: `mg MX` and `@ MX` are both MX, but only the second competes
   with the policy; the first is a delegated sending subdomain, and deleting it takes the
   customer's mail with it. That is not hypothetical — a dry-run on a real zone proposed exactly
   that. `isApexPolicyName` in `lib/harden.mjs` is the gate; keep its suffix test, which is what
   separates `sel._domainkey` (ours) from `email._domainkey.mg` (the subdomain's).
11. **A control returns `na` because of the zone's use, never because a record is missing.** A
   missing record is a `fail`. The test is whether absence satisfies the property: a control that
   *asserts* one fails when the record is absent (no SPF means forged mail is not rejected, so
   `spf.hardfail` fails); a control that *bounds* one is satisfied vacuously (a record that does
   not exist cannot be permissive, so `spf.no-permissive` passes). Never use `na` as a softer
   `fail`.
12. **Nothing from `storage/` or `.env` is ever committed.** `storage/` holds real DNS zone dumps,
   registrant CSV exports and generated reports. CI fails the build if any is tracked.

## Testing rules

- `npm test` must pass with **no network access and no credentials**.
- Unit tests stub `globalThis.fetch` so any accidental call throws.
- The CLI smoke tests set `OVH_ENV_FILE` to a non-existent path and `OVH_ENDPOINT` to an invalid
  value, so a developer's real `.env` can never be picked up. **Never remove those two.** Without
  them the suite authenticates against a live OVH account — this happened once during development.
- Fixtures use `example.com` / `*.example` only. Never copy a real zone into `test/`.
- Test names state the behaviour being protected, not the function being called.

## Conventions

- ESM `.mjs`, 2-space indent, single quotes, semicolons, trailing commas in multiline literals.
  `npm run lint` is authoritative.
- All user-facing strings and code comments in English.
- Comments explain *why*, especially where a rule looks arbitrary — most of them encode an OVH
  quirk (dedicated `SPF`/`DKIM`/`DMARC` fieldTypes, MX Plan sharing the default MX hosts, the
  redirect marker format).
- **Control ids are a public interface.** They are written into `compliance.json` and
  `compliance.csv` and end up in other people's spreadsheets and remediation plans. Renaming one
  is a breaking change; add a new control instead. Changing a weight, a scope or the catalogue
  changes every score without any DNS changing, so bump `BASELINE_VERSION` when you do.
- Classifier state keys are `dormant` / `web-active` / `mail-active` / `error`. They are written
  into `inventory.json` and consumed by `lib/report.mjs`; renaming one means migrating both.

## Common tasks

| Task | Where |
|---|---|
| Add a mail provider to detect | `REAL_MAIL` in `lib/inventory.mjs` |
| Change what the policy publishes | `buildPolicy` in `lib/harden.mjs` |
| Change what gets deleted | `planZone` in `lib/harden.mjs` |
| Add a compliance control | `CONTROLS` in `lib/baseline.mjs`, a case in `test/baseline.test.mjs`, a row in `docs/BASELINE.md` |
| Change the scoring | `SEVERITY_WEIGHT` / `GRADE_BANDS` in `lib/baseline.mjs` — then bump `BASELINE_VERSION` |
| Add a CLI flag | `parseArgs` in `lib/cli.mjs`, then the `HELP` text and the README option table |
| Add a subcommand | a `cmdX` function in `ovh.mjs`, the dispatch in `main`, `HELP`, the README |

## Manual verification against a real account

Read-only, safe to run: `node ovh.mjs whoami`, `node ovh.mjs audit <domain>`,
`node ovh.mjs snapshot <domain>`, `node ovh.mjs inventory`, `node ovh.mjs compliance`.

`--caa` remains opt-in. Every OVH CAA mutation is blocked in the adapter until the target
encoding is verified on a disposable owned zone. Do not remove this block using mocked evidence.

Never run `--apply` against someone's account to check a change. Use a domain you own and can
restore, and confirm `node ovh.mjs restore <domain>` shows a usable backup first.

## Version 1.0 release invariants

All runtime writes use `applyTransaction`. Backup failure and changed snapshots block writing.
Stop after the first write error, never retry uncertain writes, and require final readback before
reporting success or ticking inventory. Exit codes are 0 success, 1 refusal/error, 2 partial/uncertain.
Native backups identify provider, account and zone. Legacy exports remain offline-readable only.
Do not reintroduce the old raw import or `applyPlan` write path. npm ships only the generic policy,
never a custom operational policy. Test the actual tarball with `npm run test:pack`.
