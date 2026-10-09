#!/usr/bin/env node
import { readFileSync, writeFileSync, realpathSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { relative } from 'node:path';
import { runLive } from './lib/live.mjs';
import { domainName } from './lib/validation.mjs';
import { latestSnapshot, readSnapshot } from './lib/transaction.mjs';
import { posture } from './lib/engine.mjs';
import { OvhClient } from './lib/ovh-client.mjs';
import { recordLabel } from './lib/harden.mjs';
import { parseZone, classify } from './lib/inventory.mjs';
import {
  renderInventory, readTicks, latestBackup,
  renderCompliance, renderComplianceCsv,
} from './lib/report.mjs';
import { evaluate, aggregate, BASELINE_VERSION, SEVERITY_WEIGHT } from './lib/baseline.mjs';
import { loadPolicy } from './lib/policy.mjs';
import { toApiShape, toZoneShape } from './lib/zone.mjs';
import { parseArgs, findCsv, readCsvDomains } from './lib/cli.mjs';
import { loadEnv, ensureStorage, requireCredentials, policyFile } from './lib/config.mjs';

export const VERSION = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

const ACCESS_RULES = [
  { method: 'GET', path: '/me' },
  { method: 'GET', path: '/domain/*' },
  { method: 'POST', path: '/domain/zone/*' },
  { method: 'PUT', path: '/domain/zone/*' },
  { method: 'DELETE', path: '/domain/zone/*' },
];

function client() {
  requireCredentials();
  return new OvhClient({
    endpoint: process.env.OVH_ENDPOINT || 'ovh-eu',
    appKey: process.env.APP_KEY,
    appSecret: process.env.APP_SECRET,
    consumerKey: process.env.OVH_CONSUMER_KEY,
  });
}

async function cmdAuth() {
  const ovh = client();
  const res = await ovh.requestCredentials(ACCESS_RULES, 'https://www.ovh.com/manager/');
  console.log(`\n1. Open and validate this URL:\n\n   ${res.validationUrl}\n`);
  console.log(`2. Then add this to .env:\n\n   OVH_CONSUMER_KEY=${res.consumerKey}\n`);
}

function offlineFile(p, opts, domain) {
  return latestSnapshot(p.storage, opts.provider || 'ovh', domain, opts.account)
    || (opts.provider !== 'cloudflare' ? latestBackup(p.backups, domain) : null);
}
function offlineRecords(file) {
  return file.endsWith('.json') ? readSnapshot(file).records.map(toZoneShape) : parseZone(readFileSync(file, 'utf8'));
}
function writeInventory(entries, p) {
  writeFileSync(p.inventoryJson, JSON.stringify(entries, null, 2));
  writeFileSync(p.inventoryMd, renderInventory(entries, readTicks(p.inventoryMd)));
}

/** Rebuild the inventory by reclassifying the on-disk backups. No network. */
function cmdInventory(opts, p) {
  const domains = opts._.length ? opts._.map(domainName) : readCsvDomains(findCsv(opts, p.storage));
  const entries = domains.map((domain) => {
    const file = offlineFile(p, opts, domain);
    if (!file) return { domain, state: 'error', signals: ['no backup — run `snapshot`'], counts: null };
    const records = offlineRecords(file);
    return { domain, ...classify(records, { domain }) };
  });
  writeInventory(entries, p);
  console.log(`Inventory rebuilt from backups (${entries.length} domains, ticks preserved): ${p.inventoryMd}`);
}

/**
 * Score the whole portfolio against the control baseline, offline.
 *
 * Mirrors `cmdInventory`: it re-reads the on-disk backups, so it needs neither
 * credentials nor network, and it never writes to the inventory — a compliance
 * run must not be able to disturb the hand-ticked worklist.
 */
function cmdCompliance(opts, p) {
  const domains = opts._.length ? opts._.map(domainName) : readCsvDomains(findCsv(opts, p.storage));

  console.log(`Compliance baseline v${BASELINE_VERSION} — ${domains.length} domain(s) from backups, offline\n`);

  const reports = domains.map((domain, i) => {
    const prefix = `[${String(i + 1).padStart(3)}/${domains.length}] ${domain.padEnd(34)}`;
    const file = offlineFile(p, opts, domain);
    if (!file) {
      console.log(`${prefix} !! no backup — run \`snapshot\``);
      return { domain, state: 'error', score: null, grade: null, controls: [], error: 'no backup — run `snapshot`' };
    }
    const records = offlineRecords(file);
    const report = { ...evaluate(records, { domain }), source: relative(p.storage, file) };
    const critical = report.controls.filter((c) => c.status === 'fail' && c.severity === 'critical').length;
    const tail = critical
      ? `!! ${critical} critical failure(s)`
      : `spoof ${String(report.axes.spoofing.score ?? '—').padStart(3)}`
        + `  closed ${String(report.axes.closed.score ?? '—').padStart(3)}`
        + `  surface ${String(report.axes.surface.score ?? '—').padStart(3)}`;
    console.log(`${prefix} ${report.grade}${String(report.score).padStart(4)}   ${tail}`);
    return report;
  });

  const portfolio = aggregate(reports);
  const audit = {
    generatedAt: new Date().toISOString(),
    baselineVersion: BASELINE_VERSION,
    weights: SEVERITY_WEIGHT,
    portfolio,
    domains: reports,
  };

  writeFileSync(p.complianceJson, JSON.stringify(audit, null, 2));
  writeFileSync(p.complianceMd, renderCompliance(audit));
  writeFileSync(p.complianceCsv, renderComplianceCsv(audit));

  const grades = Object.entries(portfolio.byGrade).sort(([a], [b]) => a.localeCompare(b))
    .map(([g, n]) => `${g}:${n}`).join(' ');
  console.log(`\n== portfolio ${portfolio.score ?? '—'}/100 (${portfolio.grade ?? '—'}) · ${grades}`
    + (portfolio.errors ? ` · ${portfolio.errors} without backup` : ''));
  console.log(`   anti-spoofing ${portfolio.axes.spoofing ?? '—'} · closed by default ${portfolio.axes.closed ?? '—'}`
    + ` · attack surface ${portfolio.axes.surface ?? '—'}`);
  if (portfolio.topFailures.length) {
    console.log(`   top failure: ${portfolio.topFailures.slice(0, 3).map((f) => `${f.id} (${f.count})`).join(' · ')}`);
  }
  console.log(`\nReport: ${p.complianceMd}\n        ${p.complianceJson}\n        ${p.complianceCsv}`);
}

// ---------------------------------------------------------------------------
// policy — the effective configuration, offline
// ---------------------------------------------------------------------------

/** What each remedy action does, printed once as a legend. */
const ACTION_LEGEND = [
  'add      publish the record, only if nothing competes with it',
  'enforce  publish the record and delete what it replaces',
  'remove   delete, and publish nothing in its place',
  'manual   remediation text only, nothing is ever written',
  'report   scored, no remedy',
  'off      no automatic remedy; baseline findings remain scored',
];

/** Display form of a path: relative to the working directory when it is inside it. */
function shortPath(file) {
  const rel = relative(process.cwd(), file);
  return rel.startsWith('..') ? file : rel;
}

/** Pad to a column, but never let a long value run into the next one. */
const col = (text, width) => (text.length < width ? text.padEnd(width) : `${text}  `);

const cell = (entry) => `${entry.remedy.action}${entry.remedy.record ? ` ${entry.remedy.record}` : ''}`;

/** `policy` with no domain: the file as loaded, plus the validation verdict. */
function printCatalogue(policy, file) {
  const d = policy.defaults;
  const profiles = Object.keys(policy.profiles);
  const checks = Object.entries(policy.checks);

  console.log(`Policy — ${shortPath(file)} (schema v${policy.version}) — valid\n`);
  console.log('Defaults');
  console.log(`   ttl           : ${d.ttl}`);
  console.log(`   keep          : ${d.keep.map(String).join(' · ') || '(none)'}`);
  console.log(`   drop CNAMEs   : ${d.dropCnames.join(', ') || '(none)'}`);
  console.log(`   drop redirect : ${d.dropRedirect ? 'yes' : 'no'}`);

  const templates = Object.entries(policy.records);
  console.log(`\nRecord templates (${templates.length})`);
  const idW = Math.max(...templates.map(([id]) => id.length)) + 2;
  const labelW = Math.max(...templates.map(([, t]) => recordLabel(t).length)) + 2;
  for (const [id, t] of templates) {
    console.log(`   ${id.padEnd(idW)}${recordLabel(t).padEnd(labelW)}displaces ${t.displaces}`
      + (t.exclusive ? ' · exclusive' : ''));
  }

  console.log(`\nRemedy per check (${checks.length} checks × ${profiles.length} profiles)`);
  const nameW = Math.max(...checks.map(([id]) => id.length)) + 2;
  const cellW = Math.max(
    ...profiles.map((n) => n.length),
    ...checks.flatMap(([id]) => profiles.map((n) => cell(policy.profiles[n].checks[id]).length)),
  ) + 2;
  console.log(`   ${'check'.padEnd(nameW)}${profiles.map((n) => n.padEnd(cellW)).join('').trimEnd()}`);
  for (const [id] of checks) {
    const cells = profiles.map((n) => cell(policy.profiles[n].checks[id]).padEnd(cellW));
    console.log(`   ${id.padEnd(nameW)}${cells.join('').trimEnd()}`);
  }
  console.log(`\n   ${ACTION_LEGEND.join('\n   ')}`);

  const overrides = Object.entries(policy.domains ?? {});
  console.log(`\nDomain overrides (${overrides.length})`);
  for (const [domain, o] of overrides) {
    console.log(`   ${domain} -> profile ${o.profile ?? '(from state)'} · ${o.reason}`);
    for (const [id, entry] of Object.entries(o.checks ?? {})) console.log(`      ${id}: ${cell(entry)}`);
  }
  if (!overrides.length) console.log('   none — every domain follows the profile of its classified state');

  console.log('\nRun `node ovh.mjs policy <domain>` for the effective policy on one zone.');
}

/**
 * Records a failing check wanted to remove, that a `keep` pattern protected.
 *
 * Invariant #7 makes `keep` win over every licence, which is the right default
 * and a silent one: the operator asked for a hardened zone and got a record
 * left standing. Saying so is the difference between a protection and an
 * oversight. Generalises the CAA-union warning `printPlan` has always carried.
 */
function protectedFromLicences(plan, licences) {
  const out = [];
  for (const rec of plan.keep) {
    if (!String(rec.reason).startsWith('protected by')) continue;
    const licence = licences.find((l) => l.displaces(rec));
    if (licence) out.push({ rec, licence });
  }
  return out;
}

function printProtections(protections) {
  if (!protections.length) return;
  console.log(`\n   !! ${protections.length} record(s) a failing check wanted to remove are protected by \`keep\``);
  for (const { rec, licence } of protections) {
    // RFC 8659 §4.2: the `issue` properties form a union, so a permissive CAA
    // kept here still authorises its CA, deny pair or not.
    const note = rec.fieldType === 'CAA'
      ? 'RFC 8659 §4.2: issue is a union, so this CA is still authorised'
      : 'the record stays in effect';
    console.log(`      ${col(recordLabel(rec), 46)}wanted by ${licence.checkId} — ${note}`);
  }
}

/**
 * `policy <domain>`: the resolved policy and a full preview of what `harden`
 * would do, read from the latest backup.
 *
 * Offline and credential-free, which is the point: a whole batch is reviewable
 * — every publication and every deletion, each naming the check that licensed
 * it — without an API call, and long before anything is written.
 */
function printResolved(domain, opts, p, policy) {
  const file = offlineFile(p, opts, domain);
  if (!file) throw new Error(`No backup for ${domain} — run \`node ovh.mjs snapshot ${domain}\` first.`);

  const view = offlineRecords(file);
  const outcome = posture(view.map(toApiShape), domain, policy, opts);
  const { report, resolved, licences, conflicts, plan } = outcome;
  const cls = outcome;
  const protections = protectedFromLicences(plan, licences);

  if (opts.json) {
    console.log(JSON.stringify({
      domain,
      policyFile: shortPath(policyFile()),
      schemaVersion: policy.version,
      state: cls.state,
      signals: cls.signals,
      profile: resolved.profile,
      overrideReason: resolved.overrideReason,
      caaBlocked: resolved.caaBlocked,
      source: relative(p.storage, file),
      keep: resolved.keep.map(String),
      ttl: resolved.ttl,
      dropCnames: resolved.dropCnames,
      dropRedirect: resolved.dropRedirect,
      checks: report.controls.map((c) => {
        const entry = resolved.checks[c.id];
        return {
          id: c.id,
          severity: c.severity,
          axis: c.axis,
          status: c.status,
          naReason: c.naReason,
          action: entry.remedy.action,
          record: entry.remedy.record ?? null,
          reason: entry.reason,
          source: entry.source,
          demotedFrom: entry.demotedFrom,
          demotionReason: entry.demotionReason,
        };
      }),
      conflicts,
      plan: {
        create: plan.create.map((r) => ({ label: recordLabel(r), record: r.record, wantedBy: r.wantedBy, why: r.why })),
        delete: plan.delete.map((r) => ({ label: r.label, checkId: r.checkId ?? null, action: r.action ?? null, reason: r.reason })),
        keep: plan.keep.map((r) => ({ label: recordLabel(r), reason: r.reason })),
      },
      protectedFromLicences: protections.map(({ rec, licence }) => ({ label: recordLabel(rec), checkId: licence.checkId })),
    }, null, 2));
    return;
  }

  console.log(`Policy for ${domain} — ${shortPath(policyFile())} (schema v${policy.version})`);
  console.log(`   state    : ${cls.state}${cls.signals.length ? `   (${cls.signals.join(' · ')})` : ''}`);
  console.log(`   backup   : ${relative(p.storage, file)}`);
  console.log(`   profile  : ${resolved.profile}`
    + (resolved.overrideReason ? `   (override: ${resolved.overrideReason})` : ''));
  console.log(`   keep     : ${resolved.keep.map(String).join(' · ') || '(none)'}`);
  console.log(`   ttl      : ${resolved.ttl}`);
  if (resolved.caaBlocked) console.log(`   caa      : no issuance deny here — ${resolved.caaBlocked}`);

  const controls = report.controls;
  console.log(`\nChecks (${controls.length})`);
  const nameW = Math.max(...controls.map((c) => c.id.length)) + 2;
  for (const c of controls) {
    const entry = resolved.checks[c.id];
    const status = c.status === 'na' ? 'n/a' : c.status;
    const template = entry.template;
    let tail = '';
    if (entry.demotedFrom) tail = `!! demoted from ${entry.demotedFrom} — ${entry.demotionReason}`;
    else if (entry.remedy.action === 'off') tail = entry.reason ?? 'no automated remedy';
    else if (entry.remedy.action === 'remove') tail = `deletes ${template.displaces}, publishes nothing`;
    else if (template) tail = `-> ${recordLabel(template)}`;
    else if (entry.reason) tail = entry.reason;
    console.log((`   ${col(c.id, nameW)}${col(c.severity, 10)}${col(c.axis, 10)}`
      + `${col(status, 6)}${col(entry.remedy.action, 9)}${tail}`).trimEnd());
  }

  const w = 46;
  console.log(`\nWould publish (${plan.create.length})`);
  for (const rec of plan.create) console.log(`   + ${col(recordLabel(rec), w)}${(rec.wantedBy ?? []).join(', ')}`);
  if (!plan.create.length) console.log('   nothing');

  console.log(`\nWould delete (${plan.delete.length})   every deletion is licensed by a failing check`);
  for (const rec of plan.delete) console.log(`   - ${col(rec.label, w)}${rec.reason}`);
  if (!plan.delete.length) console.log('   nothing');

  console.log(`\nWould keep (${plan.keep.length})`);
  for (const rec of plan.keep) console.log(`   . ${col(recordLabel(rec), w)}${rec.reason}`);
  if (!plan.keep.length) console.log('   nothing');

  for (const c of conflicts) {
    console.log(`\n   !! ${c.checkId}: ${c.record} not published — ${c.wanted} would compete with `
      + `${c.competing.join(', ')}`);
  }
  printProtections(protections);
  console.log('\nRead only: this command never contacts a DNS provider. `harden <domain>` plans against the live zone.');
}

/** Show the effective policy — the whole file, or one domain's resolution. */
function cmdPolicy(opts, p, policy) {
  if (opts._.length > 1) throw new Error(`policy takes at most ONE domain (got ${opts._.length}).`);
  if (!opts._.length) {
    if (opts.json) { console.log(JSON.stringify(policy, (k, v) => (v instanceof RegExp ? String(v) : v), 2)); return; }
    printCatalogue(policy, policyFile());
    return;
  }
  printResolved(domainName(opts._[0]), opts, p, policy);
}

export const HELP = `
dns-posture — anti-spoofing DNS hardening for dormant domains

  dns-posture zones                   Discover accessible zones
  dns-posture auth                    Generate the OVH consumer key
  dns-posture whoami                  Check the credentials
  dns-posture snapshot                Back up + inventory EVERY domain in the CSV
  dns-posture snapshot <domain>       Same, for a single domain
  dns-posture inventory               Rebuild the inventory (offline, keeps ticks)
  dns-posture compliance              Score the portfolio against the baseline (offline)
  dns-posture compliance <domain>     Same, for a single domain
  dns-posture policy                  Show the check/remedy configuration (offline)
  dns-posture policy <domain>         Same, resolved for one domain + what harden would do
  dns-posture audit <domain>          Dump the current zone
  dns-posture harden <domain>         Plan (dry-run by default)
  dns-posture harden <domain> --apply
  dns-posture harden-batch --list <file>          Plan for a whole batch (dry-run by default)
  dns-posture harden-batch --list <file> --apply
  dns-posture restore <domain> [f]    Diff/restore a native JSON backup (dry-run by default)

inventory/compliance/policy: offline, no credentials needed — they read provider/account backups (and legacy OVH exports).
compliance: 24 controls over anti-spoofing / closed-by-default / attack surface, scored
            per domain against the posture expected of its state. Writes
            <storage>/compliance.{md,json,csv}. See docs/BASELINE.md.

harden/audit/restore: exactly one domain per run.
harden-batch: iterates over a batch, skips zones with active mail, refuses --force.
              Consolidated report in <storage>/reports/harden-batch-*.json.

Options:
  --provider ovh|cloudflare  DNS provider (default ovh)
  --account <id>       Select account for offline backups / Cloudflare zones
  --apply              Actually execute (dry-run otherwise)
  --force              Bypass the "active mail" guard rail
  --null-mx            Also try an MX "0 ." (RFC 7505) — OVH may refuse it
  --caa                Publish a CAA deny: no CA may issue (RFC 8659). Opt-in —
                       blocked on OVH, suppressed where web use makes denial unsafe
  --iodef <mailto:...> CAA violation report address (implies --caa)
  --rua <mailto:...>   DMARC aggregate report address (none by default)
  --keep <regex>       Protect records whose name/value matches (repeatable)
  --drop-cname a,b     CNAMEs to delete on top of ftp
  --drop-redirect      Also delete the OVH web redirection markers (breaks the redirect)
  --json               Machine-readable output (policy, zones)
  --csv <path>         Source CSV (default: the newest one in <storage>/)
  --list <path>        Batch file for harden-batch (one domain per line, # = comment)
  --ttl <s>            TTL of created records (default 3600)
  -h, --help           Show this help
  -v, --version        Show the version

Environment: APP_KEY, APP_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT (default ovh-eu),
             CLOUDFLARE_API_TOKEN, DNS_POSTURE_STORAGE_DIR (default ./storage),
             DNS_POSTURE_ENV_FILE (default ./.env), DNS_POSTURE_POLICY_FILE.
             OVH_STORAGE_DIR, OVH_ENV_FILE, OVH_POLICY_FILE remain fallback aliases.
             Custom policy modules execute trusted JavaScript; bundled policy is generic.

Exit codes: 0 success/verified, 1 error/refusal, 2 partial/uncertain application.
Legacy executables: ovh-domain-manager and node ovh.mjs.
`;

/** Commands that read config/policy.mjs. */
const POLICY_COMMANDS = new Set(['policy', 'harden', 'harden-batch']);

export async function main(argv) {
  // `node ovh.mjs --version` has no command: the first token is a flag, so it
  // must go through parseArgs rather than be taken as the subcommand name.
  const flagFirst = (argv[0] ?? '').startsWith('-');
  const cmd = flagFirst ? null : argv[0];
  const opts = parseArgs(flagFirst ? argv : argv.slice(1));
  if (opts.version) { console.log(VERSION); return; }
  if (opts.help || !cmd) { console.log(HELP); return; }

  loadEnv();
  const p = ensureStorage();

  // Load the configuration before any client, any credential and any network
  // call, so a typo in it costs an error message and nothing else. Scoped to
  // the commands that read it: a broken policy file must never stand between
  // an operator and `restore`.
  const policy = POLICY_COMMANDS.has(cmd) ? await loadPolicy() : null;

  if (['policy', 'harden', 'harden-batch'].includes(cmd) && ['--null-mx', '--caa', '--iodef', '--rua', '--ttl', '--drop-cname', '--drop-redirect'].some((f) => argv.includes(f))) {
    console.error('Deprecated policy flags: migrate these overrides to DNS_POSTURE_POLICY_FILE. --keep remains cumulative.');
  }
  if (['zones', 'whoami', 'snapshot', 'audit', 'harden', 'harden-batch', 'restore'].includes(cmd)) {
    await runLive(cmd, opts, p, policy);
    return;
  }
  if (cmd === 'auth') {
    if (opts.provider === 'cloudflare') throw new Error('Cloudflare uses a dedicated CLOUDFLARE_API_TOKEN');
    await cmdAuth();
  }
  else if (cmd === 'inventory') cmdInventory(opts, p);
  else if (cmd === 'compliance') cmdCompliance(opts, p);
  else if (cmd === 'policy') cmdPolicy(opts, p, policy);
  else console.log(HELP);
}

if (process.argv[1] && existsSync(process.argv[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    console.error(`\nERROR ${err.message}`);
    process.exit(1);
  }
}
