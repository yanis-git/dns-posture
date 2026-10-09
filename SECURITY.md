# Security

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Credential handling

This tool holds credentials that can **modify DNS records in the OVH or Cloudflare zones granted to them**. Treat them
accordingly.

- Credentials live in `.env`, which is gitignored and never transmitted anywhere except to the
  selected provider API. Point `DNS_POSTURE_ENV_FILE` elsewhere if you prefer to keep them outside the checkout.
- The test suite cannot read your `.env`: it runs with `OVH_ENV_FILE` set to a non-existent path.
- Nothing is logged that contains a key or a secret.
- CI runs a secret scan on every push, and fails the build if a credential, zone dump or CSV
  export is ever committed.

## Least privilege

`node ovh.mjs auth` requests exactly these rights:

| Right | Needed for |
|---|---|
| `GET /me` | identifying the account |
| `GET /domain/*` | listing domains, exporting zones, reading records |
| `POST /domain/zone/*` | creating records and refreshing a zone |
| `PUT /domain/zone/*` | updating records |
| `DELETE /domain/zone/*` | removing records |

If you only want to inventory and never modify, create the consumer key manually in the OVH API
console with just `GET /me` and `GET /domain/*`. `snapshot`, `inventory` and `audit` work with
read-only rights; `harden --apply` and `restore --apply` do not.

When OVH asks for a validity period, choose the shortest one that covers your work.

## Revoking a key

OVH manager → your account → **API keys** (or <https://eu.api.ovh.com/createToken/> for the
region-specific console) → delete the consumer key. Revocation is immediate.

Revoke a key if it has been shared, committed anywhere, pasted into a chat or a ticket, or once a
cleanup campaign is finished.

## What this tool writes to disk

Everything under `storage/` (or `OVH_STORAGE_DIR`):

- **`backups/<domain>/<timestamp>.zone`** — complete DNS zone exports. These are not secrets, but
  they do describe your infrastructure: production IPs, internal hostnames, DKIM public keys,
  domain-verification and ACME tokens, and which SaaS products you use.
- **`reports/*.json`** — full plans, including every record id and value.
- **`inventory.md` / `inventory.json`** — the classified portfolio.

None of it is gitignored by accident: `storage/` is excluded on purpose and CI enforces it. Do not
attach these files to a public issue.

For Cloudflare, use a dedicated API token with Zone Read and DNS Read, adding DNS Edit only for application, restricted to the intended zones. Never use a global account API key.
