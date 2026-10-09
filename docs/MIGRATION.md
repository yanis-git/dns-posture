# Migrating to dns-posture 1.0

The npm package and primary executable are now `dns-posture`. The `ovh-domain-manager` binary and `node ovh.mjs` entrypoint remain available. Node 22.14 or later is required; CI covers 22.14, 24 and 26. There are no runtime dependencies.

Storage now defaults to `./storage` in the calling directory. Set `DNS_POSTURE_STORAGE_DIR` to the absolute path of an existing store to keep using it. `OVH_STORAGE_DIR`, `OVH_ENV_FILE` and `OVH_POLICY_FILE` remain fallback aliases. `.env` is loaded from the calling directory, not the package installation. The bundled policy is generic; keep operational exceptions in a separate trusted JavaScript module selected by `DNS_POSTURE_POLICY_FILE`.

New snapshots live in `storage/providers/<provider>/<account-hash>/<zone>/backups/`. Each JSON snapshot contains native records, a readable zone export, identity, format version and integrity hash. Companion `.zone` files are readable exports. Old `storage/backups/<zone>/*.zone` files are read in place for OVH offline commands and never moved. Multiple matching accounts require `--account <id>`.

`restore --apply` accepts only versioned JSON backups. Old exports do not identify the account or retain provider metadata, so they cannot support verified automated restoration. Inspect them with `restore` without `--apply` or restore manually through the provider after independent review.

`policy`, `harden` and `harden-batch` now use one engine. Custom policy changes affect live plans. The default keeps verification TXT records and active-mail profiles do nothing even with `--force`; this intentionally differs from the old broad TXT deletion. Legacy policy flags remain overrides with a deprecation warning; `--keep` is cumulative and remains supported. Disabling a remedy does not change the compliance score.

Exit codes: 0 means successful read/dry-run or verified application; 1 means refusal/error before DNS writing; 2 means partial or uncertain application. A batch continues other zones and returns its worst status. No failed write is retried. Inspect the journal and read current records before planning again.

CAA writes on OVH are blocked pending validation of its API encoding. Null MX and CAA deny remain opt-in. A CAA deny is suppressed where web use or certificate activity makes it unsafe. The lock is local, and final verification observes API state, not DNS propagation.
