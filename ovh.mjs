#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { OvhClient } from './lib/ovh-client.mjs';
import { buildPolicy, fetchRecords, planZone, applyPlan, recordLabel } from './lib/harden.mjs';
import { parseZone, classify } from './lib/inventory.mjs';
import { renderInventory, readTicks, tickDomain, saveBackup, latestBackup } from './lib/report.mjs';
import { parseArgs, requireDomain, findCsv, readCsvDomains, readListFile } from './lib/cli.mjs';
import { loadEnv, ensureStorage, requireCredentials } from './lib/config.mjs';

export const VERSION = '0.1.0';

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

async function cmdWhoami() {
  const ovh = client();
  await ovh.syncTime();
  const me = await ovh.get('/me');
  console.log(`Connected as: ${me.nichandle} (${me.email})`);
}

/** Back up the zone and return { zoneText, backupPath, records, ...classification }. */
async function snapshotDomain(ovh, domain, p) {
  const zoneText = await ovh.get(`/domain/zone/${encodeURIComponent(domain)}/export`);
  const backupPath = saveBackup(p.backups, domain, zoneText);
  const records = parseZone(zoneText);
  return { domain, zoneText, backupPath, records, ...classify(records, { domain }) };
}

function writeInventory(entries, p) {
  writeFileSync(p.inventoryJson, JSON.stringify(entries, null, 2));
  writeFileSync(p.inventoryMd, renderInventory(entries, readTicks(p.inventoryMd)));
}

async function cmdSnapshot(opts, p) {
  const domains = opts._.length ? opts._.map((d) => d.toLowerCase()) : readCsvDomains(findCsv(opts, p.storage));
  const ovh = client();
  await ovh.syncTime();

  console.log(`Snapshotting ${domains.length} domain(s) — read only\n`);
  const entries = [];

  for (const [i, domain] of domains.entries()) {
    const prefix = `[${String(i + 1).padStart(3)}/${domains.length}] ${domain.padEnd(34)}`;
    try {
      const snap = await snapshotDomain(ovh, domain, p);
      entries.push({ domain, state: snap.state, signals: snap.signals, counts: snap.counts });
      console.log(`${prefix} ${snap.state.padEnd(11)} ${snap.counts.total} records`);
    } catch (err) {
      const reason = err.status === 404 ? 'zone not hosted at OVH' : err.message;
      entries.push({ domain, state: 'error', signals: [reason], counts: null });
      console.log(`${prefix} !! ${reason}`);
    }
  }

  writeInventory(entries, p);
  console.log(`\nBackups   : ${p.backups}/<domain>/<timestamp>.zone`);
  console.log(`Inventory : ${p.inventoryMd}`);
}

/** Rebuild the inventory by reclassifying the on-disk backups. No network. */
function cmdInventory(opts, p) {
  const domains = opts._.length ? opts._.map((d) => d.toLowerCase()) : readCsvDomains(findCsv(opts, p.storage));
  const entries = domains.map((domain) => {
    const file = latestBackup(p.backups, domain);
    if (!file) return { domain, state: 'error', signals: ['no backup — run `snapshot`'], counts: null };
    const records = parseZone(readFileSync(file, 'utf8'));
    return { domain, ...classify(records, { domain }) };
  });
  writeInventory(entries, p);
  console.log(`Inventory rebuilt from backups (${entries.length} domains, ticks preserved): ${p.inventoryMd}`);
}

function printPlan(zone, plan) {
  console.log(`\n== ${zone}`);
  for (const rec of plan.delete) console.log(`   - DELETE  ${rec.label}  -> ${rec.reason}`);
  for (const rec of plan.create) console.log(`   + CREATE  ${recordLabel(rec)}  -> ${rec.why}`);
  for (const rec of plan.keep.filter((k) => k.reason === 'already compliant')) {
    console.log(`   = OK      ${recordLabel(rec)}`);
  }
  for (const rec of plan.keep.filter((k) => k.reason !== 'already compliant')) {
    console.log(`   . KEEP    ${recordLabel(rec)}  -> ${rec.reason}`);
  }
  if (!plan.delete.length && !plan.create.length) console.log('   OK zone already compliant, nothing to do');
}

async function cmdHarden(opts, p) {
  const zone = requireDomain(opts);
  const ovh = client();
  await ovh.syncTime();

  let snap;
  try {
    snap = await snapshotDomain(ovh, zone, p);
  } catch (err) {
    throw new Error(err.status === 404
      ? `Zone "${zone}" not found at OVH (DNS delegated elsewhere?)`
      : err.message);
  }

  console.log(opts.apply ? `APPLYING to ${zone}` : `DRY-RUN on ${zone} — add --apply to execute`);
  console.log(`   state  : ${snap.state}${snap.signals.length ? ` (${snap.signals.join(' · ')})` : ''}`);
  console.log(`   backup : ${snap.backupPath}`);

  // Guard rail: we do not harden a zone that is still in use, without --force.
  if (snap.state === 'mail-active' && !opts.force) {
    throw new Error(`"${zone}" has active mail (${snap.signals.join(' · ')}).\n`
      + '   Hardening would break both delivery AND sending. Re-run with --force if that is intended.');
  }

  const policy = buildPolicy({ rua: opts.rua, nullMx: opts.nullMx, ttl: opts.ttl || 3600 });
  const records = await fetchRecords(ovh, zone);
  const plan = planZone(records, { policy, keepPatterns: opts.keep, cnamesToDrop: opts.cnames, dropRedirect: opts.dropRedirect });
  printPlan(zone, plan);

  const result = { zone, mode: opts.apply ? 'apply' : 'plan', at: new Date().toISOString(), state: snap.state, backup: snap.backupPath, plan };

  if (opts.apply) {
    result.applied = await applyPlan(ovh, zone, plan);
    console.log(`\n   -> ${result.applied.deleted.length} deletion(s), ${result.applied.created.length} creation(s), zone refreshed`);
    for (const e of result.applied.errors) console.log(`   ERROR ${e}`);

    const note = `cleaned ${new Date().toISOString().slice(0, 10)}${result.applied.errors.length ? ` · ${result.applied.errors.length} error(s)` : ''}`;
    if (tickDomain(p.inventoryMd, zone, note)) console.log(`   ticked in ${p.inventoryMd}`);
  }

  mkdirSync(p.reports, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const path = join(p.reports, `${zone}-${opts.apply ? 'apply' : 'plan'}-${stamp}.json`);
  writeFileSync(path, JSON.stringify(result, null, 2));
  console.log(`\nReport: ${path}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function writeBatchReport(rows, mode, opts, p) {
  mkdirSync(p.reports, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = join(p.reports, `batch-${mode}-${stamp}`);

  const tally = {};
  for (const r of rows) tally[r.status] = (tally[r.status] || 0) + 1;
  const totalDel = rows.reduce((n, r) => n + (r.deletes || 0), 0);
  const totalNew = rows.reduce((n, r) => n + (r.creates || 0), 0);
  const summary = Object.entries(tally).map(([k, v]) => `${k}: ${v}`).join(' · ');

  writeFileSync(`${base}.json`, JSON.stringify({
    mode,
    at: new Date().toISOString(),
    options: {
      dropRedirect: !!opts.dropRedirect,
      nullMx: !!opts.nullMx,
      ttl: opts.ttl || 3600,
      rua: opts.rua || null,
      keep: opts.keep.map((re) => re.source),
      cnamesToDrop: opts.cnames,
    },
    tally,
    totals: { deletes: totalDel, creates: totalNew },
    rows,
  }, null, 2));

  const cell = (r) => (r.reason || (r.errors || []).join(' ; ') || '').replace(/\|/g, '\\|').slice(0, 140);
  writeFileSync(`${base}.md`, [
    `# Batch hardening — ${mode === 'apply' ? 'apply' : 'dry-run'}`,
    '',
    `${new Date().toISOString().slice(0, 16).replace('T', ' ')} · ${rows.length} domains · ${totalDel} deletion(s), ${totalNew} creation(s)`,
    '',
    summary,
    '',
    '| Domain | State | Deleted | Created | Status | Detail |',
    '|---|---|---:|---:|---|---|',
    ...rows.map((r) => `| ${r.domain} | ${r.state || '—'} | ${r.deletes ?? '—'} | ${r.creates ?? '—'} | ${r.status} | ${cell(r)} |`),
    '',
  ].join('\n'));

  console.log(`\n== ${rows.length} domains · ${totalDel} deletion(s), ${totalNew} creation(s)`);
  console.log(`   ${summary}`);
  console.log(`\nReport: ${base}.md`);
  console.log(`        ${base}.json`);
}

/**
 * Roll the policy out over a batch of domains. Reuses the single-domain
 * machinery: one failing zone does not stop the batch, and --force is refused.
 */
async function cmdHardenBatch(opts, p) {
  if (opts.force) {
    throw new Error('--force is refused in batch mode.\n'
      + '   A domain with active mail is handled one at a time: `node ovh.mjs harden <domain> --force`.');
  }
  const domains = opts.list ? readListFile(opts.list) : opts._.map((d) => d.toLowerCase().trim());
  if (!domains.length) throw new Error('No domain: pass --list <file> or domains as arguments.');

  const ovh = client();
  await ovh.syncTime();

  const mode = opts.apply ? 'apply' : 'plan';
  console.log(opts.apply
    ? `APPLYING in batch — ${domains.length} domain(s)\n`
    : `DRY-RUN in batch — ${domains.length} domain(s), add --apply to execute\n`);

  const policy = buildPolicy({ rua: opts.rua, nullMx: opts.nullMx, ttl: opts.ttl || 3600 });
  const rows = [];

  for (const [i, domain] of domains.entries()) {
    const prefix = `[${String(i + 1).padStart(2)}/${domains.length}] ${domain.padEnd(36)}`;
    if (i) await sleep(300); // the OVH API client has neither retry nor backoff

    let snap;
    try {
      snap = await snapshotDomain(ovh, domain, p);
    } catch (err) {
      const reason = err.status === 404 ? 'zone not hosted at OVH' : err.message;
      rows.push({ domain, status: 'error', reason });
      console.log(`${prefix} !! skipped — ${reason}`);
      continue;
    }

    if (snap.state === 'mail-active') {
      rows.push({ domain, status: 'skipped', state: snap.state, backup: snap.backupPath, reason: `active mail — ${snap.signals.join(' · ')}` });
      console.log(`${prefix} >> skipped — active mail`);
      continue;
    }

    try {
      const records = await fetchRecords(ovh, domain);
      const plan = planZone(records, {
        policy, keepPatterns: opts.keep, cnamesToDrop: opts.cnames, dropRedirect: opts.dropRedirect,
      });
      const row = {
        domain, status: mode, state: snap.state, backup: snap.backupPath,
        deletes: plan.delete.length, creates: plan.create.length, plan,
      };

      if (opts.apply) {
        const applied = await applyPlan(ovh, domain, plan);
        row.applied = applied;
        row.errors = applied.errors;
        row.status = applied.errors.length ? 'partial' : 'ok';
        if (!applied.errors.length) {
          row.ticked = tickDomain(p.inventoryMd, domain, `cleaned ${new Date().toISOString().slice(0, 10)}`);
        }
      }
      rows.push(row);

      const verdict = plan.delete.length || plan.create.length
        ? `-${plan.delete.length} +${plan.create.length}`
        : 'already compliant';
      console.log(`${prefix} ${snap.state.padEnd(11)} ${verdict}`);
      for (const e of row.errors || []) console.log(`${' '.repeat(14)}ERROR ${e}`);
    } catch (err) {
      rows.push({ domain, status: 'error', state: snap.state, backup: snap.backupPath, reason: err.message });
      console.log(`${prefix} ERROR ${err.message}`);
    }
  }

  writeBatchReport(rows, mode, opts, p);
}

async function cmdAudit(opts) {
  const zone = requireDomain(opts);
  const ovh = client();
  await ovh.syncTime();
  console.log(await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/export`));
}

async function cmdRestore(opts, p) {
  const zone = opts._[0]?.toLowerCase();
  if (!zone) throw new Error('Usage: restore <domain> [file.zone]');
  const file = opts._[1] || latestBackup(p.backups, zone);
  if (!file || !existsSync(file)) throw new Error(`No backup found for ${zone}`);

  const zoneFile = readFileSync(file, 'utf8');
  console.log(`Restoring ${zone} from ${file}`);
  if (!opts.apply) {
    console.log('\n' + zoneFile);
    console.log('DRY-RUN — add --apply to re-import this zone.');
    return;
  }
  const ovh = client();
  await ovh.syncTime();
  const task = await ovh.post(`/domain/zone/${encodeURIComponent(zone)}/import`, { zoneFile });
  console.log(`Import started (task ${task?.taskId ?? '?'}). Check with: node ovh.mjs audit ${zone}`);
}

export const HELP = `
ovh-domain-manager — anti-spoofing DNS hardening for dormant domains

  node ovh.mjs auth                    Generate the OVH consumer key
  node ovh.mjs whoami                  Check the credentials
  node ovh.mjs snapshot                Back up + inventory EVERY domain in the CSV
  node ovh.mjs snapshot <domain>       Same, for a single domain
  node ovh.mjs inventory               Rebuild the inventory (offline, keeps ticks)
  node ovh.mjs audit <domain>          Dump the current zone
  node ovh.mjs harden <domain>         Plan (dry-run by default)
  node ovh.mjs harden <domain> --apply
  node ovh.mjs harden-batch --list <file>          Plan for a whole batch (dry-run by default)
  node ovh.mjs harden-batch --list <file> --apply
  node ovh.mjs restore <domain> [f]    Re-import the latest backup (dry-run by default)

harden/audit/restore: exactly one domain per run.
harden-batch: iterates over a batch, skips zones with active mail, refuses --force.
              Consolidated report in <storage>/reports/batch-*.{md,json}.

Options:
  --apply              Actually execute (dry-run otherwise)
  --force              Bypass the "active mail" guard rail
  --null-mx            Also try an MX "0 ." (RFC 7505) — OVH may refuse it
  --rua <mailto:...>   DMARC aggregate report address (none by default)
  --keep <regex>       Protect records whose name/value matches (repeatable)
  --drop-cname a,b     CNAMEs to delete on top of ftp
  --drop-redirect      Also delete the OVH web redirection markers (breaks the redirect)
  --csv <path>         Source CSV (default: the newest one in <storage>/)
  --list <path>        Batch file for harden-batch (one domain per line, # = comment)
  --ttl <s>            TTL of created records (default 3600)
  -h, --help           Show this help
  -v, --version        Show the version

Environment: APP_KEY, APP_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT (default ovh-eu),
             OVH_STORAGE_DIR (default ./storage). Read from .env if present.
`;

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

  if (cmd === 'auth') await cmdAuth();
  else if (cmd === 'whoami') await cmdWhoami();
  else if (cmd === 'snapshot') await cmdSnapshot(opts, p);
  else if (cmd === 'inventory') cmdInventory(opts, p);
  else if (cmd === 'audit') await cmdAudit(opts);
  else if (cmd === 'harden') await cmdHarden(opts, p);
  else if (cmd === 'harden-batch') await cmdHardenBatch(opts, p);
  else if (cmd === 'restore') await cmdRestore(opts, p);
  else console.log(HELP);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    console.error(`\nERROR ${err.message}`);
    process.exit(1);
  }
}
