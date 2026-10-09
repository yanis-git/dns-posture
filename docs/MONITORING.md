# Reporting and periodic checks

For business context: [email impersonation and domain ownership](https://fennec.sh/en/blog/forgotten-domains-responsibility) and [from impersonation risk to a monitoring report](https://fennec.sh/en/blog/cleaning-dns-portfolio). [Versions françaises](https://fennec.sh/blog/nettoyer-portefeuille-dns).

## What the reports measure

`snapshot` reads the provider and saves current records. `compliance` evaluates saved records offline and writes `compliance.md`, `compliance.csv` and `compliance.json` at the storage root. Reports include scores, failed controls, severity and remediation guidance. Inventory describes inferred usage; an operator must confirm legitimate senders before remediation.

The baseline score is a configuration measure, not an attack count, probability of compromise, ANSSI certification or percentage of malicious messages blocked. Read individual findings and the baseline version. The tool does not inspect message contents, analyse DMARC traffic reports, configure active-mail DKIM signing, schedule jobs or send alerts.

## Reproduce the article's fictional report offline

Run this in a new empty directory with Node >=22.14 and dns-posture installed. It creates only fictional legacy-format inputs for offline analysis. It never writes DNS or reads provider credentials.

```sh
mkdir -p demo-before/backups/campaign.example demo-after/backups/campaign.example
cat > demo-before/backups/campaign.example/2026-10-09.zone <<'ZONE'
$ORIGIN campaign.example.
@ 3600 IN NS ns1.example.com.
ZONE
cat > demo-after/backups/campaign.example/2026-10-09.zone <<'ZONE'
$ORIGIN campaign.example.
@ 3600 IN NS ns1.example.com.
@ 3600 IN TXT "v=spf1 -all"
_dmarc 3600 IN TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; pct=100"
ZONE
DNS_POSTURE_ENV_FILE="$PWD/no.env" OVH_ENV_FILE="$PWD/no.env" OVH_ENDPOINT=ovh-nowhere DNS_POSTURE_STORAGE_DIR="$PWD/demo-before" dns-posture compliance campaign.example
DNS_POSTURE_ENV_FILE="$PWD/no.env" OVH_ENV_FILE="$PWD/no.env" OVH_ENDPOINT=ovh-nowhere DNS_POSTURE_STORAGE_DIR="$PWD/demo-after" dns-posture compliance campaign.example
```

Baseline 1.1.0 yields 45/F before and 85/B after. `spf.present` and `dmarc.reject` change from `fail` to `pass`. Other findings remain. The article's two-row table is an editorial summary, not the complete report. These values are reproducible synthetic observations, not a customer result or proof of email delivery. Legacy exports cannot be used for automated restore.

## Periodic monitoring without DNS writes

Have your operations team install a pinned CLI version and run the following sequence using a scheduler such as cron or an existing CI system. Use a provider token with read permissions, a fixed environment file and an explicit list of domains. Choose the cadence based on your operations; a weekly run and another run after DNS changes are examples, not an ANSSI-mandated interval.

1. Create a new private storage directory for each run, with its timestamp in the name. Set `DNS_POSTURE_STORAGE_DIR` to it and `DNS_POSTURE_ENV_FILE` to your credential file. A fresh directory prevents a failed read from silently reusing last week's backup.
2. Run `dns-posture snapshot example.com campaign.example --provider cloudflare`. Stop and notify the operator if it fails. Omit the provider option for OVH.
3. Run `dns-posture compliance example.com campaign.example --provider cloudflare` only after successful reads. Keep the Markdown/CSV/JSON outputs and snapshots together. Reject a report containing an `error` domain or a null score as an incomplete observation.
4. Compare the JSON control statuses with the preceding successful run, matching domain and control ID. Compare like-for-like baseline versions. Decide which new failures, persistent critical failures or missing observations should notify the owner through your existing monitoring system.

All these commands are read-only with respect to DNS. Do not add `harden --apply` to this observation schedule. Review proposed changes separately.

A successful `compliance` process does **not** mean every control passed: the command can complete while reporting failures. Your wrapper must inspect the report, not only the process exit code. Retain the last successful report alongside the new failure notification, labelled with its original date. Keep reports and credentials private; they can disclose operational domain configuration.

This monitors provider configuration at discrete points in time. It does not continuously detect attacks, observe authoritative DNS propagation, collect DMARC aggregate reports or guarantee that recipients enforce the requested policy.
