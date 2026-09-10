# Contributing

Thanks for taking the time. This tool deletes DNS records in production, so the bar for changes to
the classifier and the policy engine is high — but small fixes and new provider signatures are
very welcome.

## Getting set up

```bash
git clone https://github.com/<you>/ovh-domain-manager.git
cd ovh-domain-manager
npm install     # dev dependencies only
npm test
npm run lint
```

Node ≥ 20.12. The tool itself has no runtime dependencies; please keep it that way.

You do **not** need an OVH account to develop or run the tests.

## Before opening a pull request

- `npm test` and `npm run lint` pass.
- New behaviour has a test. New *safety* behaviour has a test that fails without your change.
- Read [AGENTS.md](AGENTS.md) — it lists the invariants that must not be weakened.
- No real domain names, IPs, zone dumps or credentials anywhere in the diff. Fixtures use
  `example.com` and `*.example`.

## Good first contributions

**Adding a mail provider to the classifier.** If a provider's MX is not recognised, the domain is
already treated as `mail-active` (the fail-safe direction), but the signal is vague. Add a pattern
to `REAL_MAIL` in `lib/inventory.mjs` with a test.

**Reporting a misclassification.** Open an issue with the *redacted* zone shape — record types,
names and the shape of the values — and what you expected. Never paste a real zone.

## Changes that need discussion first

Open an issue before working on:

- anything that removes or bypasses a guard rail (dry-run default, backup-before-write, the
  `mail-active` check, `--force` being refused in batch);
- changes to what `buildPolicy` publishes — the SPF/DMARC/DKIM values are deliberate, see
  [docs/POLICY.md](docs/POLICY.md);
- adding a runtime dependency;
- renaming a classifier state — these are written into `inventory.json` and existing installs
  depend on them.

## Style

`npm run lint` is authoritative. Beyond it: English strings, comments that explain *why* rather
than *what*, and error messages that tell the user what to do next.

## Commits

Conventional-ish and imperative: `fix: null MX no longer classifies as mail-active`. One logical
change per commit.
