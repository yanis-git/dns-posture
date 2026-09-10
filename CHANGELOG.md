# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-10

First public release. The tool had been in private use against a real portfolio before this;
this release packages it, translates it to English, and adds a test suite around the parts where
a mistake is destructive.

### Added

- `auth`, `whoami`, `snapshot`, `inventory`, `audit`, `harden`, `harden-batch`, `restore`.
- Dormant / web-active / mail-active classification with an explicit fail-safe on unrecognised
  mail hosts.
- Zone backup before every mutation, and `restore` to put a zone back.
- Consolidated batch reports in Markdown and JSON.
- `--help` and `--version`.
- `OVH_STORAGE_DIR` to relocate the data directory, and `OVH_ENV_FILE` to point at a different
  credentials file.
- 118 tests (`node --test`) covering the parser, classifier, policy engine, signed client,
  inventory rendering, argument parsing and the CLI end to end. No test touches the network.
- CI: lint and tests on Node 20.12 / 22 / 24, a secret scan, and a job that fails the build if a
  zone dump, CSV export or credentials file is ever committed.

### Fixed

- **Records named after a record type were misparsed.** `mx 3600 IN A 1.2.3.4` was read as an MX
  record with the *previous* line's name, because the parser matched the first RR-type token
  anywhere on the line. A domain with an `mx`, `ns`, `a`, `srv`, `ptr` or `caa` subdomain could
  therefore be classified `mail-active` and skipped for ever.
- **A null MX classified as mail-active.** `MX 0 .` (RFC 7505) matched no known provider and fell
  into the unknown-host fail-safe, so a domain hardened with `--null-mx` came back as
  `mail-active` on the next inventory and was skipped by subsequent batch runs.
- **A missing `.env` crashed the CLI before it could print anything**, including `--help`, on a
  fresh clone.
