# The hardening policy, and why each record is what it is

`harden` publishes three records — four with `--null-mx`. This document explains the reasoning, so
you can judge the policy without reading the code. If you disagree with a choice, the values live
in `buildPolicy` (`lib/harden.mjs`).

## The problem

A domain that nobody uses still resolves. Unless it explicitly says otherwise, a receiving mail
server has no basis on which to reject a message claiming to come from it. Attackers know this:
lapsed and dormant corporate domains are attractive precisely because they carry a real brand's
name and no protection.

Publishing "this domain sends no mail" is cheap, permanent, and needs no infrastructure.

## `TXT @` — `v=spf1 -all`

SPF says which hosts may send for the domain. `v=spf1 -all` lists none and ends in a **hard fail**.

- `-all` (hard fail), not `~all` (soft fail). Soft fail asks receivers to accept-and-mark; for a
  domain that legitimately sends nothing, there is no false-positive risk to hedge against, so
  hedging only weakens the signal.
- No `include:` mechanisms, so no DNS lookups — well inside SPF's 10-lookup limit, and nothing to
  break when a third party changes their record.

SPF alone is not enough: it validates the envelope sender (`MAIL FROM`), which the recipient never
sees. That is what DMARC is for.

## `TXT _dmarc` — `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s`

DMARC ties SPF and DKIM to the visible `From:` header and tells receivers what to do on failure.

| Tag | Value | Why |
|---|---|---|
| `p` | `reject` | Not `none` (report only) and not `quarantine` (spam folder). The domain sends nothing, so anything claiming to be it is forged. |
| `sp` | `reject` | Subdomain policy, stated explicitly. Without it, an attacker uses `billing.example.com` instead. |
| `adkim` | `s` | Strict DKIM alignment: the signing domain must match exactly, not just share an organisational domain. |
| `aspf` | `s` | Strict SPF alignment, same reasoning. |

No `rua` by default: aggregate reports need a mailbox that will actually be read, and pointing
them at an unmonitored address is noise. Pass `--rua mailto:you@example.com` if you want them —
useful for a few weeks after a cleanup to confirm nothing legitimate was sending.

## `TXT *._domainkey` — `v=DKIM1; p=`

An empty `p=` is the DKIM way of saying "this key is revoked" (RFC 6376 §3.6.1). Published on the
`*._domainkey` wildcard, it revokes **every** selector at once — including selectors you have
forgotten, and any a previous provider left behind.

This matters because DKIM signatures survive their provider: a key left published by an
ex-provider remains usable by whoever still holds the private half.

The wildcard does not override a specific selector that still exists as its own record. `harden`
deletes the TXT selectors it finds, but **it cannot delete a `_domainkey` CNAME** (OVH MX Plan
delegates DKIM that way) — those are out of scope for the policy and must be removed in the OVH
manager. The classifier reports them as `mail-active` so you notice.

## `MX @` — `0 .` (optional, `--null-mx`)

RFC 7505: a single MX with a null target declares that the domain accepts **no** mail. Senders
fail fast instead of retrying for days, and bounce backscatter stops.

Opt-in because:

- it is about *inbound* mail, whereas spoofing protection is about *outbound* — SPF and DMARC
  already do the job without it;
- OVH refuses the record on some zones;
- it is genuinely destructive if anyone still receives mail there.

## What `harden` removes, and why

- **All MX records** — a dormant domain needs none, and a leftover MX keeps inbound mail flowing
  to a mailbox nobody reads.
- **All TXT/SPF/DKIM/DMARC** — replaced wholesale by the policy above. Keeping a permissive old
  SPF alongside a new restrictive one is worse than either.
- **The `ftp` CNAME** — legacy hosting plumbing, no reason to advertise it.

## What it deliberately does not touch

- **OVH web-redirect markers** (TXT shaped `3|www.example.com`). Not mail records; deleting them
  breaks a live redirect. `--drop-redirect` if you want them gone.
- **A/AAAA/CNAME records** other than `ftp`. A dormant domain may still legitimately serve a
  redirect or a landing page.
- **Anything matching `--keep`** — ACME challenges and domain-verification TXT records are the
  usual candidates. Deleting an `_acme-challenge` breaks certificate renewal; deleting a
  `google-site-verification` silently detaches a Search Console property.

## Verifying the result

```bash
dig +short TXT example.com
dig +short TXT _dmarc.example.com
dig +short TXT '*._domainkey.example.com'
```

Give it a TTL's worth of time (an hour by default) and check with any DMARC inspector. The domain
should report SPF hard-fail, DMARC reject, and no valid DKIM key.
