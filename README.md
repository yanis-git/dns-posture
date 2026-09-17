# ovh-domain-manager

**English** · [Français](README.fr.md)

[![CI](https://github.com/yanis-git/ovh-domain-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/yanis-git/ovh-domain-manager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A5%2020.12-brightgreen.svg)](#requirements)
[![Zero dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)](package.json)

Attack-surface reduction and default-deny DNS hardening for a portfolio of OVHcloud domains.
Inventory the domains nobody uses any more, score the whole portfolio against a control baseline
mapped to RFC, ISO/IEC 27001:2022, NIS2 and ANSSI references, and publish the records that stop
anyone sending mail in your name.

A dormant domain is a liability. It still resolves, it still has an MX, and unless it explicitly
says otherwise, anyone can forge mail `From:` it — invoices, password resets, phishing at your
customers — and the messages will pass basic checks. Absence is not a closed door: with no CAA
record, *every* certificate authority in the world may issue for the domain; with no null MX, its
inbound posture is merely ambiguous. This tool finds those domains, measures what they still
permit by omission, and publishes the records that shut the door.

Zero runtime dependencies. Everything is dry-run by default, and every mutation is preceded by a
full backup of the zone.

| | |
|---|---|
| **Anti-spoofing** | SPF `-all`, DMARC `p=reject` with strict alignment, wildcard DKIM revocation. |
| **Closed by default** | Null MX (RFC 7505) and an optional CAA deny (RFC 8659): nothing is permitted by omission. |
| **Attack surface** | Wildcards, residual service subdomains, stale verification TXT, dangling CNAMEs. |
| **Evidence** | A scored, reproducible, offline audit of the whole portfolio in markdown, JSON and CSV. |

---

## Safety model

This tool deletes DNS records. Read this section before running anything with `--apply`.

| Guard | Behaviour |
|---|---|
| **Dry-run by default** | `harden`, `harden-batch` and `restore` print a plan and change nothing. You need `--apply` to write. |
| **Backup before every write** | Every run that touches a zone first exports it to `storage/backups/<domain>/<timestamp>.zone`. Nothing is ever overwritten. |
| **Active-mail guard** | A zone classified `mail-active` is refused. Hardening it would break both delivery and sending. |
| **`--force` is single-domain only** | `harden-batch` refuses `--force` outright, so a mistake cannot fan out across a portfolio. |
| **Redirects preserved** | OVH's web-redirection marker records are kept unless you explicitly pass `--drop-redirect`. |
| **`--keep <regex>`** | Protects anything you name — ACME challenges, domain-verification TXT, a specific MX. |
| **CAA is never loosened** | An existing CAA record is left alone unless `--caa` republishes one. Deleting a CAA without publishing one lets *every* CA issue again. |
| **`restore`** | Re-imports the latest backup of a zone. |

> **Applying this policy to a domain that sends mail will break that mail.** The classifier is a
> good filter, not an oracle: it reads DNS, and DNS cannot prove that no mailbox exists (see
> [Classifier](#classifier)). Review the plan before you apply it.

---

## Requirements

- **Node.js ≥ 20.12** (uses `process.loadEnvFile` and the built-in test runner). No `npm install`
  needed to run the tool — dependencies are dev-only.
- An OVH account whose domains use OVH DNS.

```bash
git clone https://github.com/<you>/ovh-domain-manager.git
cd ovh-domain-manager
node ovh.mjs --help
```

---

## Getting started

### 1. Create an OVH application

Go to the OVH API console for your region and create an application:

| Region | Create app | Endpoint value |
|---|---|---|
| Europe | <https://eu.api.ovh.com/createApp/> | `ovh-eu` *(default)* |
| Canada | <https://ca.api.ovh.com/createApp/> | `ovh-ca` |
| US | <https://api.us.ovhcloud.com/createApp/> | `ovh-us` |

You get an **application key** and an **application secret**.

> This is OVH's application-key / consumer-key scheme, not OAuth2. Every request is signed with
> `$1$sha1(secret + consumerKey + method + url + body + timestamp)`. SHA-1 is not a choice here —
> it is what the OVH v1 API mandates.

### 2. Fill in your credentials

```bash
cp .env.example .env
```

```ini
APP_KEY=your_application_key
APP_SECRET=your_application_secret
OVH_CONSUMER_KEY=          # filled in by the next step
OVH_ENDPOINT=ovh-eu        # optional
```

`.env` is gitignored. It is never read by the test suite.

### 3. Mint a consumer key

```bash
node ovh.mjs auth
```

This prints a validation URL and a consumer key. Open the URL, log in, confirm — then paste the
key into `.env` as `OVH_CONSUMER_KEY`.

The key is requested with exactly these rights, and nothing else:

| Right | Why |
|---|---|
| `GET /me` | `whoami`, to confirm which account you are on |
| `GET /domain/*` | list domains, export zones, read records |
| `POST /domain/zone/*` | create records, refresh the zone, import a backup |
| `PUT /domain/zone/*` | update records |
| `DELETE /domain/zone/*` | remove records |

Choose a short validity when OVH asks, and revoke the key from the OVH manager when you are done.

### 4. Check it works

```bash
node ovh.mjs whoami
# Connected as: ab12345-ovh (you@example.com)
```

---

## Domain inventory

### Get the list of domains

Export your portfolio from the OVH manager (**Domain names → the list → export CSV**) and drop the
file in `storage/`. The tool reads the **first column** of the CSV and skips the header row, so
any export containing a domain column first will do. The newest CSV in `storage/` is used unless
you pass `--csv <path>`.

You can also skip the CSV entirely and name domains on the command line.

### Snapshot: fetch, back up, classify

```bash
node ovh.mjs snapshot                  # every domain in the CSV
node ovh.mjs snapshot example.com      # just one
```

For each domain this exports the zone, writes a timestamped backup, classifies it, and rebuilds
`storage/inventory.md` and `storage/inventory.json`. It is **read-only** against OVH.

```
[  1/61] example.com                       dormant     4 records
[  2/61] shop.example                      mail-active 12 records
[  3/61] gone.example                      !! zone not hosted at OVH
```

### The inventory is a worklist

`storage/inventory.md` groups domains by state, dormant first, with a checkbox each:

```markdown
## Dormant — candidates for hardening (1/2)

- [x] **example.com** — 4 records (0 MX, 3 TXT, 0 CNAME) · empty zone <!-- cleaned 2026-09-09 -->
- [ ] **other.example** — 6 records (1 MX, 2 TXT, 1 CNAME) · default OVH MX (mx1.mail.ovh.net.)
```

Tick boxes by hand as you work; `harden --apply` ticks them for you. **Ticks and their notes are
preserved every time the inventory is regenerated.**

### Rebuild offline

```bash
node ovh.mjs inventory
```

Reclassifies the backups already on disk. No network, no credentials needed. Use it after
changing classifier rules, or to re-render the inventory without hammering the API.

---

## Compliance baseline

```bash
node ovh.mjs compliance                  # the whole portfolio
node ovh.mjs compliance example.com      # one domain
```

The classifier answers *"is this domain safe to harden?"*. The baseline answers *"what is the
security posture of this portfolio, and what is the shortest path to improving it?"* — with
twenty-three identified, weighted controls, each mapped to a published reference.

It runs **offline, from the backups already on disk**, so it needs no credentials and the same
backups always produce the same score.

```
Compliance baseline v1.0.0 — 61 domain(s) from backups, offline

[  1/ 61] example.com                        B  86   spoof 100  closed  55  surface 100
[  2/ 61] other.example                      F  31   !! 3 critical failure(s)
[  3/ 61] never-seen.example                 !! no backup — run `snapshot`

== portfolio 78/100 (C) · A:5 B:12 C:15 D:6 F:2 · 1 without backup
   anti-spoofing 91 · closed by default 40 · attack surface 88
   top failure: caa.present (22) · srv.none (9) · wildcard.none (4)
```

Three artefacts land in `storage/`: `compliance.md` for a human (failures and judgement calls
only), `compliance.json` for a machine (every result plus the weights used), and `compliance.csv`
for an auditor — one row per (domain, control), **passes included**, because evidence of what was
checked and found compliant is the point of an audit trail.

### How a domain is scored

Every control belongs to one axis — **anti-spoofing**, **closed by default**, **attack surface** —
and each axis is scored separately, so a portfolio that is strong on one and weak on another
cannot hide behind a single average.

Controls are weighted by severity (`critical` 10, `high` 6, `medium` 3, `low` 1). The score is the
weighted pass ratio; grades run A ≥ 95 down to F. One non-linear rule: **a grade is capped at C if
any critical control fails**, so a zone with no SPF at all cannot show an A on the strength of the
twenty controls that do pass. The portfolio score is the *unweighted mean* of the per-domain
scores, so one forty-record zone cannot outvote forty empty ones.

### Every domain, each against its own expected posture

The audit covers the whole portfolio whatever the state of each domain — but a domain that
legitimately sends mail is not marked down for publishing a DKIM key. Each control declares a
scope (`all`, `non-sending`, `sending`, `dormant`) and returns `n/a` outside it.

`n/a` has exactly one meaning: **the zone's use makes the question meaningless — never that a
record is missing.** A missing record is a failure. `n/a` counts for neither side of the ratio and
is always shown with its reason.

Domains with no usable backup are reported as errors and **excluded from every average**, never
scored zero: "not measured" and "measured badly" are different facts.

The full catalogue is in **[docs/BASELINE.md](docs/BASELINE.md)**; the French control-to-requirement
mapping for ISO/IEC 27001:2022, NIS2 and the ANSSI guides is in
**[docs/CONFORMITE.md](docs/CONFORMITE.md)**.

---

## Classifier

Every zone is sorted into one of four states.

| State | Meaning | Safe to harden? |
|---|---|---|
| `dormant` | No sign of mail or web usage. | **Yes** — this is the target. |
| `web-active` | Serves web content, mail probably unused. | Only after checking. Hardening kills sending from the domain. |
| `mail-active` | Real mail provider, or a published DKIM key. | **No.** Refused without `--force`. |
| `error` | Zone not hosted at OVH, or unreachable. | N/A |

What each signal means:

| Signal | Reads as |
|---|---|
| MX to Google Workspace, Microsoft 365, Mailgun/SendGrid/Mailjet…, OVH Exchange/Pro, Zoho/Proton/Fastmail… | `mail-active` |
| **Unrecognised** MX host | `mail-active` — fail-safe: unknown means "check it yourself" |
| MX to OVH's default hosts (`mx1.mail.ovh.net`) | *not* conclusive on its own — see the caveat below |
| Null MX (`0 .`, RFC 7505) | Explicitly receives no mail |
| A `_domainkey` TXT with a real key, or a `_domainkey` CNAME | `mail-active` — the domain signs mail |
| A `_domainkey` TXT with `p=` empty | Revoked key — not active |
| Any A/AAAA/CNAME outside OVH's parking range | `web-active` |
| A record on `213.186.33.x` | OVH parking — not real content |
| `www` CNAME pointing at its own apex | An alias, not separate content |
| `ftp` CNAME, wildcards, `_`-prefixed names | Ignored for web detection |

> **The one caveat you must know.** OVH MX Plan mailboxes use the *same* default MX hosts as an
> unconfigured domain. DNS alone therefore cannot prove that no mailbox exists. A domain shown as
> `dormant` with a default OVH MX may still have a real mailbox behind it — check the OVH manager
> before hardening if that is plausible for your account.

---

## Backup and restore

Every snapshot, plan and apply writes a full zone export first:

```
storage/backups/<domain>/2026-09-09T11-35-36-671Z.zone
```

Backups are append-only — nothing prunes them, and nothing is overwritten. They are plain
BIND-format zone files, readable and diffable.

```bash
node ovh.mjs restore example.com                    # dry-run: print what would be re-imported
node ovh.mjs restore example.com --apply            # re-import the latest backup
node ovh.mjs restore example.com path/to/old.zone --apply
```

`restore` re-imports through OVH's zone-import endpoint and returns a task id. Check the result
with `node ovh.mjs audit example.com`.

---

## Cleaner (`harden`)

### What it publishes

| Record | Value | Why |
|---|---|---|
| `TXT @` | `v=spf1 -all` | No host on earth is authorised to send for this domain. `-all` is a hard fail, not `~all`. |
| `TXT _dmarc` | `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s` | Receivers reject failures outright, subdomains included, with strict alignment. |
| `TXT *._domainkey` | `v=DKIM1; p=` | Wildcard revocation: every DKIM selector is declared to have no key. |
| `MX @` | `0 .` | *Optional, `--null-mx`.* RFC 7505: the domain accepts no mail. OVH may refuse this record. |
| `CAA @` | `0 issue ";"` / `0 issuewild ";"` | *Optional, `--caa`.* RFC 8659: no certificate authority may issue for this domain. |

Add `--rua mailto:you@example.com` if you want DMARC aggregate reports. Nothing is reported by
default. Add `--iodef mailto:you@example.com` for CAA violation reports; it implies `--caa`.

> **`--caa` is opt-in, and read this before using it.** A CAA deny at the apex is inherited by
> every subdomain (RFC 8659) and will stop a certificate renewing — 60 to 90 days later, not at
> publication. `harden` refuses to publish one on a `web-active` zone, on a zone carrying an OVH
> redirect, on one where the apex or `www` still resolves to a live host, or while an
> `_acme-challenge` is in flight, and prints `caa : skipped — <reason>` instead.
>
> **The OVH `target` syntax for `fieldType: CAA` is not documented and has not been verified
> against a live account.** The value published is the zone-file form. Confirm it on a throwaway
> zone you can restore before your first `--apply --caa`: if OVH rejects the record, the run
> reports a creation error and the zone is left with *no* CAA — looser than before, not broken,
> and `restore` puts it back.

An existing CAA record is never deleted by a plain `harden`. Without `--caa` it is reported as
`. KEEP … -> CAA out of scope (pass --caa)`, because deleting a CAA without publishing one
re-opens issuance to every CA on earth.

### What it removes

Only records at the apex, which is where the policy publishes: `@`, `_dmarc` and
`<selector>._domainkey`.

- The apex `MX` records (a dormant domain needs none).
- The apex `TXT`/`SPF`/`DKIM`/`DMARC` records, replaced by the policy above.
- The `ftp` CNAME (add more with `--drop-cname webmail,autodiscover`).

### What it deliberately leaves alone

- **OVH web-redirect markers** — TXT records shaped `3|www.example.com`. These are plumbing for
  OVH's redirection service and have nothing to do with mail; deleting them alone breaks the
  redirect. Pass `--drop-redirect` if you really want them gone.
- **Anything matching `--keep`** — repeatable regex, matched against both the record name and its
  value:
  ```bash
  node ovh.mjs harden example.com --keep 'site-verification' --keep '_acme-challenge'
  ```
- **Anything on a subdomain.** A domain routing its mail through `mg.example.com` keeps
  `mg MX`, `mg TXT "v=spf1 include:…"`, `_dmarc.mg` and `email._domainkey.mg` — they are not apex
  policy names, so hardening the apex leaves that mail working. The flip side: it also leaves that
  subdomain's posture unaudited.
- A/AAAA/CNAME records other than the ones listed above: out of scope, untouched.

### Single domain

```bash
node ovh.mjs harden example.com              # dry-run
node ovh.mjs harden example.com --apply
```

```
DRY-RUN on example.com — add --apply to execute
   state  : dormant (default OVH MX (mx1.mail.ovh.net.))
   backup : storage/backups/example.com/2026-09-09T11-35-36-671Z.zone

== example.com
   - DELETE  @ MX "10 mx1.mail.ovh.net."  -> MX at the apex
   - DELETE  @ TXT "v=spf1 include:mx.ovh.com ~all"  -> superfluous TXT/SPF/DKIM/DMARC (replaced by the policy)
   + CREATE  @ TXT "v=spf1 -all"  -> SPF: no authorised sender
   + CREATE  _dmarc TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"  -> DMARC: strict reject, subdomains included
   + CREATE  *._domainkey TXT "v=DKIM1; p="  -> DKIM: every key revoked
   . KEEP    ftp CNAME "ftp.cluster021.hosting.ovh.net."  -> out of scope

Report: storage/reports/example.com-plan-2026-09-09T11-35-37-002Z.json
```

Running it again on a hardened zone prints `OK zone already compliant, nothing to do` — the plan
is idempotent, so a compliant record is neither deleted nor recreated.

### In batch

```bash
cat > storage/batch.txt <<'EOT'
# one domain per line, # starts a comment
example.com
other.example
EOT

node ovh.mjs harden-batch --list storage/batch.txt            # dry-run
node ovh.mjs harden-batch --list storage/batch.txt --apply
```

Batch mode iterates with a 300 ms pause between domains (the client has no retry or backoff),
**skips any `mail-active` zone**, refuses `--force`, and never lets one failing zone stop the run.
It writes a consolidated report to `storage/reports/batch-<mode>-<timestamp>.{md,json}`.

---

## Command reference

| Command | Network | Writes to OVH | Description |
|---|---|---|---|
| `auth` | yes | no | Mint a consumer key |
| `whoami` | yes | no | Show the authenticated account |
| `snapshot [domains…]` | yes | no | Export + back up + classify |
| `inventory [domains…]` | **no** | no | Rebuild the inventory from backups |
| `compliance [domains…]` | **no** | no | Score the whole portfolio against the control baseline |
| `audit <domain>` | yes | no | Print the live zone |
| `harden <domain>` | yes | only with `--apply` | Plan/apply the policy on one domain |
| `harden-batch` | yes | only with `--apply` | Same over a list |
| `restore <domain> [file]` | yes | only with `--apply` | Re-import a backup |

`harden`, `audit` and `restore` take exactly one domain per run, by design.

| Option | Default | Description |
|---|---|---|
| `--apply` | off | Actually execute. Everything is a dry-run without it. |
| `--force` | off | Bypass the active-mail guard. Single-domain `harden` only. |
| `--null-mx` | off | Also publish `MX 0 .` (RFC 7505). |
| `--caa` | off | Also publish a CAA deny (RFC 8659). **Opt-in — read the warning below.** |
| `--iodef <mailto:…>` | none | CAA violation-report address. Implies `--caa`. |
| `--rua <mailto:…>` | none | DMARC aggregate report address. |
| `--keep <regex>` | none | Protect matching records. Repeatable. |
| `--drop-cname a,b` | `ftp` | Extra CNAMEs to delete. |
| `--drop-redirect` | off | Also delete OVH redirect markers. **Breaks the redirect.** |
| `--csv <path>` | newest in `storage/` | Source CSV. |
| `--list <path>` | none | Batch file for `harden-batch`. |
| `--ttl <seconds>` | `3600` | TTL of created records. |
| `-h, --help` / `-v, --version` | | |

| Environment variable | Default | Description |
|---|---|---|
| `APP_KEY` | — | OVH application key **(required)** |
| `APP_SECRET` | — | OVH application secret **(required)** |
| `OVH_CONSUMER_KEY` | — | Consumer key, from `auth` |
| `OVH_ENDPOINT` | `ovh-eu` | `ovh-eu`, `ovh-ca` or `ovh-us` |
| `OVH_STORAGE_DIR` | `./storage` | Where backups, reports and the inventory are written |
| `OVH_ENV_FILE` | `./.env` | Credentials file to load |

---

## Troubleshooting

**`Zone "x" not found at OVH (DNS delegated elsewhere?)`** — the domain is registered at OVH but
its DNS is hosted somewhere else, so there is no OVH zone to edit. Nothing to do here.

**`OVH 403 … Invalid signature`** — usually clock skew. The client calls `/auth/time` and corrects
for it automatically; if it persists, check your consumer key is validated and not expired.

**`Missing OVH credentials: APP_KEY, APP_SECRET`** — no `.env`, or it is missing values. See
[Getting started](#getting-started).

**OVH refuses the null MX** — some zones reject `MX 0 .`. It is optional; drop `--null-mx`. SPF
`-all` plus DMARC `p=reject` already stop spoofing; the null MX only stops *inbound* mail.

**A web redirect stopped working** — you passed `--drop-redirect`. Restore the zone
(`node ovh.mjs restore <domain> --apply`) or re-create the redirect in the OVH manager.

**A Let's Encrypt certificate stopped renewing** — you published a CAA deny with `--caa` on a
zone that still needs certificates. A CAA record at the apex is inherited by **every** subdomain
(RFC 8659), and the failure surfaces 60-90 days later at renewal, not at publication. Restore the
zone (`node ovh.mjs restore <domain> --apply`) or delete the CAA records in the OVH manager. The
tool tries hard to prevent this — it refuses to publish a deny on a `web-active` zone, on one
carrying an OVH redirect, or while an `_acme-challenge` is in flight — but it reads DNS, and DNS
cannot see a certificate you issue from somewhere else. This is why `--caa` is opt-in.

**A hardened domain shows up as `mail-active`** — check the signals in the inventory. A leftover
`_domainkey` CNAME (OVH MX Plan DKIM delegation) is the usual cause; it is a CNAME, so the policy
does not remove it. Delete it in the OVH manager if the mailbox is really gone.

---

## Development

```bash
npm install     # dev dependencies only (ESLint)
npm test        # node --test, no network, no credentials
npm run lint
```

The test suite never contacts OVH: unit tests stub `fetch`, and the CLI smoke tests run with
`OVH_ENV_FILE` pointing at a non-existent file so your real `.env` can never be picked up.

See [AGENTS.md](AGENTS.md) for the architecture and the invariants to preserve,
[docs/POLICY.md](docs/POLICY.md) for the reasoning behind the DNS policy,
[docs/BASELINE.md](docs/BASELINE.md) for the compliance control catalogue,
[docs/CONFORMITE.md](docs/CONFORMITE.md) for the French regulatory mapping, and
[CONTRIBUTING.md](CONTRIBUTING.md) to contribute.

## Security

Credentials live in `.env` and never leave your machine. See [SECURITY.md](SECURITY.md) for how to
scope and revoke a consumer key, and how to report a vulnerability.

## License

[MIT](LICENSE) © Yanis Ghidouche
