# dns-posture

[Français](README.fr.md) · [Commands](docs/COMMANDS.md) · [Migration](docs/MIGRATION.md)

Inventory OVHcloud and Cloudflare DNS zones, identify residual uses, score an anti-spoofing baseline and harden dormant domains with a reviewable plan. Zero runtime dependencies. **Dry-run is the default.** Active mail, delegated subdomains, protected records and web redirects have explicit safeguards.

## Install

Node 22.14 or later:

```sh
npx dns-posture --help
```

The historical `ovh-domain-manager` executable and `node ovh.mjs` remain compatible entrypoints.

## Configure

Create a `.env` in the directory where you run the command, or use environment variables:

```dotenv
# OVH (default provider)
APP_KEY=your-application-key
APP_SECRET=your-application-secret
OVH_CONSUMER_KEY=your-consumer-key
OVH_ENDPOINT=ovh-eu
# Cloudflare: dedicated token, restricted to your zones
CLOUDFLARE_API_TOKEN=your-api-token
```

OVH consumer-key setup: `npx dns-posture auth`. Cloudflare needs Zone Read and DNS Read, plus DNS Edit for application. Add `--provider cloudflare` to each command to select it.

Storage defaults to `./storage` in the calling directory, separated by provider/account/zone. Set `DNS_POSTURE_STORAGE_DIR`, `DNS_POSTURE_ENV_FILE` or `DNS_POSTURE_POLICY_FILE` to override paths. Historical `OVH_*` aliases remain supported. A policy file is trusted executable JavaScript; keep operational exceptions outside the installed package.

## Inspect, plan, apply, verify

```sh
npx dns-posture zones
npx dns-posture snapshot example.com
npx dns-posture audit example.com
npx dns-posture compliance example.com
npx dns-posture policy example.com
npx dns-posture harden example.com
npx dns-posture harden example.com --apply
npx dns-posture audit example.com
npx dns-posture restore example.com /path/to/before.json
# Review the diff before adding --apply to restore.
```

Inventory, compliance and policy previews use backups entirely offline. Every application, including restoration, saves a complete current snapshot, locks the zone locally and compares provider records before and after writing. A failed write stops the zone. Exit codes: **0 verified/success, 1 error/refusal, 2 partial/uncertain**. Batch continues other zones.

## Limits and reading

DNS propagation is not atomic. Local locks cannot stop remote operators. OVH CAA writes are blocked pending API encoding validation. Null MX and CAA deny are opt-in. Versioned JSON backups retain native metadata for restore; historical `.zone` files remain readable offline but cannot be used for verified automated restore. Account settings, DNSSEC and external services are outside scope.

[Safety audit](docs/AUDIT-1.0.md) · [Policy](docs/POLICY.md) · [Baseline](docs/BASELINE.md) · [Release setup](docs/RELEASING.md)

Development: `npm ci`, `npm test`, `npm run lint`, `npm run test:pack`. Tests use simulated APIs and no real credentials or DNS writes. MIT licensed.
