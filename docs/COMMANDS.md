# Command reference

Every command accepts `--provider ovh|cloudflare` (default OVH). `--account <id>` disambiguates offline backups or filters Cloudflare zones. No cross-provider migration is supported.

| Command | Input/output |
|---|---|
| `auth` | OVH only: request and validate a consumer key |
| `whoami` | OVH identity or Cloudflare accessible zones/accounts |
| `zones [--json]` | Discover accessible zones without a CSV |
| `snapshot <domain>...` | Full native snapshots and run report; no arguments reads `--csv` or the newest CSV |
| `audit <domain>` | Read current records and save a complete snapshot |
| `inventory <domain>...` | Offline classification from backups; no arguments reads CSV |
| `compliance <domain>...` | Offline baseline scores and Markdown/JSON/CSV output |
| `policy [domain] [--json]` | Offline catalogue or resolved preview from backup |
| `harden <domain> [--apply]` | Live plan, backup, explicit application and verification |
| `harden-batch <domains>... [--apply]` | Continue through zones, refuse active mail and return worst status |
| `harden-batch --list <file> [--apply]` | One domain per line, `#` comments allowed |
| `restore <domain> [backup.json] [--apply]` | Diff against a same-provider/account/zone snapshot, then backup and restore manageable records |

| Option | Meaning |
|---|---|
| `--apply` | Explicitly authorize provider writes |
| `--force` | Lift the single-domain active-mail refusal; does not turn on the default mail profile; prohibited in batch |
| `--keep <regex>` | Protect matching name/value, repeatable and cumulative |
| `--csv <path>` | Inventory CSV, first column domains |
| `--list <path>` | Batch list, cannot combine with explicit domains or CSV |
| `--null-mx` | Deprecated policy override, opt-in Null MX |
| `--caa` | Deprecated CAA-deny override, subject to web guard and provider restrictions |
| `--iodef <mailto:...>` | Deprecated CAA reporting override; implies `--caa` |
| `--rua <mailto:...>` | Deprecated DMARC reporting override |
| `--ttl <seconds>` | Deprecated policy TTL override; Cloudflare accepts 1 for automatic or 60–86400 |
| `--drop-cname a,b` | Deprecated override adding named CNAME deletions |
| `--drop-redirect` | Deprecated explicit removal of OVH redirect markers |
| `--json` | Machine-readable policy or zone discovery |
| `--help`, `--version` | Work without credentials |

Custom policy files are executable JavaScript. Load only modules you trust. See [policy](POLICY.md), [baseline](BASELINE.md) and [audit limits](AUDIT-1.0.md).

Provider contract: `init`, `zones`, exact `zone`, complete `read`, readable `export`, operation `validate`, `create`, `update`, `delete`, `finalize`. Native conversions and restorable fields stay in each adapter. Reads have 15-second deadlines and at most two retries for transport/transient failures. Retry-After delays above 30 seconds terminate the attempt without an early retry. Writes have deadlines and no retries.

Cloudflare requires a dedicated token restricted to the intended zones with Zone Read and DNS Read/Edit as needed. Read-only runs need no DNS Edit. [Record API contract](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/).
