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

## `CAA @` — `0 issue ";"` / `0 issuewild ";"` (optional, `--caa`)

RFC 8659: a CAA record names the certificate authorities allowed to issue for a domain. The value
`;` is the empty authority list — it names none, so **no CA may issue at all**. `issuewild` says
the same about wildcard certificates. On a domain nobody uses, that closes a door that is
otherwise wide open: with no CAA record at all, every publicly trusted CA on earth may issue for
the name, and a mis-issued certificate for a domain nobody monitors is a convincing phishing
asset.

`--iodef mailto:you@example.com` adds a third record asking CAs to report attempted violations.
It implies `--caa`, since an iodef address on its own publishes nothing that closes anything.

### Why it is opt-in, when SPF and DMARC are not

A CAA record at the apex governs **every** subdomain by inheritance. Publish a deny on a zone that
still needs a certificate and issuance stops — but not visibly, and not now. It surfaces 60 to 90
days later when something tries to renew, long after the change that caused it has been forgotten.
That failure mode is why this is a flag and not a default, and why OVH documents the conflict with
Let's Encrypt on their web hosting.

`harden` refuses to publish a deny — printing `caa    : skipped — <reason>` — when any of:

- the zone classifies as `web-active`;
- it carries an OVH web-redirection marker;
- an `_acme-challenge` TXT is present, meaning a certificate is being issued right now;
- the apex or `www` still resolves to a host outside OVH's parking range.

The same predicate drives the `n/a` verdict on the CAA controls in the compliance baseline: one
rule, two consumers, so the audit and the writer can never disagree about whether a deny is safe.

### An existing CAA is never deleted on its own

Deleting a CAA record without publishing one **loosens** the zone: no CAA means any CA may issue.
So `planZone` only ever touches an existing CAA when the policy replaces it. Without `--caa` it is
reported as `. KEEP … -> CAA out of scope (pass --caa)`.

One corollary of RFC 8659 §4.2 worth knowing: the `issue` properties form a **union**. Keeping a
permissive `0 issue "letsencrypt.org"` with `--keep` while publishing a deny leaves Let's Encrypt
authorised — safe, but not what the flag name suggests, so `printPlan` warns about it explicitly.

### The failure window

`applyPlan` deletes before it creates. If OVH rejects the CAA creation, the zone is left with **no
CAA at all** — more permissive than before, not broken, and `restore` puts it back. That ordering
is acceptable here precisely because the failure direction is "open" rather than "unreachable".

> **Unverified against the OVH API.** Neither OVH's documentation nor the Terraform provider
> states the `target` syntax for `fieldType: CAA`, so the value published is the zone-file form.
> Confirm it on a throwaway zone before the first `--apply --caa`.

## What `harden` removes, and why

Only at the apex. The policy publishes at the apex, so it may only remove what competes with what
it publishes: `@`, `_dmarc`, and `<selector>._domainkey`.

- **The apex MX records** — a dormant domain needs none, and a leftover MX keeps inbound mail
  flowing to a mailbox nobody reads.
- **The apex TXT/SPF/DKIM/DMARC** — replaced wholesale by the policy above. Keeping a permissive
  old SPF alongside a new restrictive one is worse than either.
- **The `ftp` CNAME** — legacy hosting plumbing, no reason to advertise it.

## What it deliberately does not touch

- **OVH web-redirect markers** (TXT shaped `3|www.example.com`). Not mail records; deleting them
  breaks a live redirect. `--drop-redirect` if you want them gone.
- **Everything on a subdomain.** `mg MX`, `mg TXT "v=spf1 include:…"`, `_dmarc.mg`,
  `email._domainkey.mg` — a domain that delegates its mail to an ESP subdomain keeps sending after
  a `harden`, because none of those names is an apex policy name. They are reported as
  `out of scope: mg is not an apex policy name`. Note the consequence: hardening the apex says
  nothing about the subdomain's posture, which you still have to audit on its own.
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
dig +short CAA example.com          # only if you passed --caa
```

Give it a TTL's worth of time (an hour by default) and check with any DMARC inspector. The domain
should report SPF hard-fail, DMARC reject, and no valid DKIM key.
