# dns-posture 1.0 safety audit

Date: 2026-10-09. Scope: local source, simulated OVH/Cloudflare APIs, packaged CLI and CI. No production DNS mutation was used for validation. Baseline before changes: 323 tests.

| Finding | Severity | Correction | Evidence |
|---|---|---|---|
| Restore imported without a current backup | Critical | All new-format restores use the same snapshot and transaction boundary as hardening | `live-cli.test.mjs`, `transaction.test.mjs` |
| Deletes preceded creates and errors did not stop a zone | Critical | Updates preferred, creates before deletes, first error stops writing, uncertain outcomes exit 2 | transaction and CLI failure scenarios |
| Success could tick inventory without readback | Critical | Complete final-state comparison before `verified` and ticking | divergent final-state scenarios |
| Preview and writer used different policy engines | High | Shared `posture()` classification, baseline, resolution and plan | engine idempotence and simulated CLI |
| Incomplete type reads silently skipped 400/404 | High | Unfiltered complete OVH inventory, strict Cloudflare pagination, malformed reads refused | provider contracts and complete-read tests |
| No concurrency protection | High | Exclusive per-zone local lock, full record fingerprint before and after backup | lock and concurrent-change tests |
| Backups lacked provider identity, native metadata and integrity | High | Versioned SHA-256 envelope with provider/account/zone, native records and readable export | integrity, identity and restoration tests |
| Domains and options could reach paths/API unchecked | High | Domain/IDNA and option validation, missing values and ambiguous inputs rejected | CLI and validation tests |
| OVH CAA encoding unverified | High | All OVH CAA mutations blocked at preflight | provider refusal test |
| Package storage depended on installation directory | Medium | Caller-relative storage and DNS_POSTURE_* variables, historical aliases retained | unpacked artifact smoke |
| npm publication was private and unbounded | Medium | Explicit files allowlist, generic policy, tag/version gates, secret scan, artifact smoke, OIDC release workflow | `verify-pack.mjs`, `release.yml` |

## Deliberate limits

- Legacy OVH `.zone` exports remain available to offline inventory, scoring and preview. They lack authenticated provider/account identity and native metadata. Their direct `restore --apply` path is refused. Use a versioned JSON snapshot for automated restoration. A manual provider import remains an operator decision outside this CLI.
- A local lock coordinates processes sharing the same storage directory. It cannot lock a provider dashboard or another machine. Pre-write fingerprints detect changes observed before the first write, not every possible race between API calls.
- A backup hash detects corruption, not malicious replacement by someone able to rewrite both data and hash.
- Final verification compares provider API records, not authoritative DNS propagation or DNSSEC. There is no atomic multi-record DNS transaction. A failed or timed-out write is not replayed, even if it might have succeeded remotely.
- Provider-managed SOA, account settings, DNSSEC, mail services and external integrations are outside restore scope. An unmanageable changed record fails preflight.
- OVH CAA writing remains blocked. Cloudflare behavior is tested through documented API contracts and simulation, not production writes.
- Baseline version, public control IDs and classifier states are unchanged. `off` disables remediation, never baseline evaluation.
- Historical operational aggregates are supplied evidence for the articles only. They do not prove current DNS state, absence of incidents, time saved or savings.

## Release evidence

Run `npm test`, `npm run lint` and `npm run test:pack`. CI runs Node 22.14, 24 and 26. The archive checker extracts the actual npm tarball into a separate temporary directory and checks help, version, offline policy/inventory/compliance and caller-relative persistent storage with fetch disabled. Test subprocesses retain `OVH_ENV_FILE` pointing to a missing file and `OVH_ENDPOINT=ovh-nowhere`.

The release workflow checks its tag against `package.json`, scans secrets, verifies the archive, publishes that archive with OIDC/provenance and creates a GitHub release. Its npm trusted-publisher association is an external installation step, not something a green local test proves.
