# AGENTS.md

Guidance for coding agents and contributors working in this repository.

## What this is

A zero-dependency Node CLI that inventories OVH domains and publishes an anti-spoofing DNS policy
on the dormant ones. It deletes DNS records in production. Treat every change to `lib/harden.mjs`
and `lib/inventory.mjs` as safety-critical.

## Layout

```
ovh.mjs               CLI entrypoint: subcommand dispatch, orchestration, reports
lib/ovh-client.mjs    Signed OVH v1 API client (no retry, no backoff — callers pace themselves)
lib/inventory.mjs     Zone-file parser + dormant/web-active/mail-active classifier
lib/harden.mjs        Policy engine: buildPolicy / planZone / applyPlan
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

`snapshotDomain` in `ovh.mjs` is the shared composition point for `snapshot`, `harden` and
`harden-batch`. Every path that mutates a zone goes through it first, which is what guarantees a
backup exists before any deletion.

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
9. **Nothing from `storage/` or `.env` is ever committed.** `storage/` holds real DNS zone dumps,
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
- Classifier state keys are `dormant` / `web-active` / `mail-active` / `error`. They are written
  into `inventory.json` and consumed by `lib/report.mjs`; renaming one means migrating both.

## Common tasks

| Task | Where |
|---|---|
| Add a mail provider to detect | `REAL_MAIL` in `lib/inventory.mjs` |
| Change what the policy publishes | `buildPolicy` in `lib/harden.mjs` |
| Change what gets deleted | `planZone` in `lib/harden.mjs` |
| Add a CLI flag | `parseArgs` in `lib/cli.mjs`, then the `HELP` text and the README option table |
| Add a subcommand | a `cmdX` function in `ovh.mjs`, the dispatch in `main`, `HELP`, the README |

## Manual verification against a real account

Read-only, safe to run: `node ovh.mjs whoami`, `node ovh.mjs audit <domain>`,
`node ovh.mjs snapshot <domain>`, `node ovh.mjs inventory`.

Never run `--apply` against someone's account to check a change. Use a domain you own and can
restore, and confirm `node ovh.mjs restore <domain>` shows a usable backup first.
