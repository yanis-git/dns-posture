import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { OvhProvider } from './providers/ovh.mjs';
import { CloudflareProvider } from './providers/cloudflare.mjs';
import { domainName } from './validation.mjs';
import { requireDomain, readListFile, readCsvDomains, findCsv } from './cli.mjs';
import { classify } from './inventory.mjs';
import { toZoneShape, recordLabel } from './zone.mjs';
import { tickDomain, latestBackup, renderInventory, readTicks } from './report.mjs';
import { saveSnapshot, readSnapshot, latestSnapshot, applyTransaction, restorePlan, fingerprint } from './transaction.mjs';
import { posture } from './engine.mjs';

export async function providerFor(opts) {
  const provider = opts.provider === 'cloudflare' ? new CloudflareProvider({ account: opts.account }) : new OvhProvider();
  await provider.init();
  if (opts.account && provider.name === 'ovh' && opts.account !== provider.account) throw new Error('OVH account identity mismatch');
  return provider;
}

/** Complete native data is the authority for classification and mutation. */
export async function snapshotDomain(provider, domain, p) {
  const zone = await provider.zone(domain);
  const records = await provider.read(zone);
  const zoneText = await provider.export(zone, records);
  if (fingerprint(await provider.read(zone)) !== fingerprint(records)) throw new Error('Zone changed during snapshot; retry the read');
  const backup = saveSnapshot(p.storage, zone, records, zoneText);
  return { zone, records, backup, ...classify(records.map(toZoneShape), { domain }) };
}

function printPlan(plan) {
  for (const action of ['delete', 'create', 'keep']) {
    for (const r of plan[action]) console.log(`  ${action.toUpperCase()} ${recordLabel(r)}${r.reason ? ` — ${r.reason}` : ''}`);
  }
}
function saveReport(p, domain, report) {
  mkdirSync(p.reports, { recursive: true });
  const file = join(p.reports, `${domain}-${Date.now()}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(`Report: ${file}`);
}

export async function runLive(command, opts, p, policy) {
  if (command === 'harden-batch' && opts.force) throw new Error('--force is refused in batch mode. Handle active mail one at a time.');
  let domains;
  if (['harden', 'audit'].includes(command)) domains = [requireDomain(opts)];
  else if (command === 'restore') {
    if (!opts._.length || opts._.length > 2) throw new Error('Usage: restore <domain> [backup.json|file.zone]');
    domains = [domainName(opts._[0])];
  } else if (command === 'harden-batch') {
    domains = opts.list ? readListFile(opts.list) : opts._.map(domainName);
    if (!domains.length) throw new Error('No domain: pass --list <file> or domains as arguments.');
  } else if (command === 'snapshot') {
    domains = opts._.length ? opts._.map(domainName) : readCsvDomains(findCsv(opts, p.storage));
  }
  if (command === 'restore') {
    const domain = domains[0];
    const file = opts._[1] || latestSnapshot(p.storage, opts.provider || 'ovh', domain, opts.account)
      || (opts.provider !== 'cloudflare' ? latestBackup(p.backups, domain) : null);
    if (!file) throw new Error(`No backup found for ${domain}`);
    if (!file.endsWith('.json')) {
      console.log(readFileSync(file, 'utf8'));
      if (opts.apply) throw new Error('Legacy zone exports lack verifiable account identity and native metadata; restore --apply requires a versioned JSON backup');
      console.log('DRY-RUN — legacy backup readable; native JSON backup required for verified restoration.');
      return;
    }
    const backup = readSnapshot(file);
    if (backup.zone.provider !== (opts.provider || 'ovh') || backup.zone.name !== domain) throw new Error('Backup provider/zone mismatch');
    const provider = await providerFor(opts);
    const snap = await snapshotDomain(provider, domain, p);
    readSnapshot(file, snap.zone);
    const plan = restorePlan(snap.records, backup.records);
    console.log(`Restoring ${domain} from ${file} — ${opts.apply ? 'APPLY' : 'DRY-RUN'}`);
    printPlan(plan);
    const result = opts.apply ? await applyTransaction(provider, snap.zone, snap.records, plan, p.storage) : { code: 0 };
    saveReport(p, domain, { command, plan, result });
    process.exitCode = Math.max(process.exitCode || 0, result.code);
    return;
  }
  const provider = await providerFor(opts);
  if (command === 'zones') {
    const zones = await provider.zones();
    console.log(opts.json ? JSON.stringify(zones, null, 2) : zones.map((z) => `${z.name}\t${z.account}`).join('\n'));
    return;
  }
  if (command === 'whoami') {
    console.log(provider.name === 'ovh' ? `Connected as: ${provider.account}` : JSON.stringify(await provider.zones(), null, 2));
    return;
  }
  const rows = [];
  for (const domain of domains) {
    try {
      const snap = await snapshotDomain(provider, domain, p);
      if (command === 'snapshot' || command === 'audit') {
        console.log(command === 'audit' ? await provider.export(snap.zone, snap.records) : `${domain}: ${snap.state} — ${snap.backup}`);
        rows.push({ domain, state: snap.state, signals: snap.signals, counts: snap.counts });
        continue;
      }
      console.log(`${opts.apply ? 'APPLY' : 'DRY-RUN'} ${domain}: ${snap.state}\nBackup: ${snap.backup}`);
      if (snap.state === 'mail-active' && (!opts.force || command === 'harden-batch')) throw new Error('Active mail: hardening refused (single-domain --force only)');
      const outcome = posture(snap.records, domain, policy, opts);
      printPlan(outcome.plan);
      if (outcome.conflicts.length) throw new Error(`Policy conflicts: ${JSON.stringify(outcome.conflicts)}`);
      const result = opts.apply ? await applyTransaction(provider, snap.zone, snap.records, outcome.plan, p.storage) : { code: 0 };
      for (const error of result.errors || []) console.error(`ERROR ${domain}: ${error}`);
      if (result.verified) tickDomain(p.inventoryMd, domain, `verified ${new Date().toISOString().slice(0, 10)}`);
      rows.push({ domain, state: snap.state, plan: outcome.plan, result });
      saveReport(p, domain, rows.at(-1));
      process.exitCode = Math.max(process.exitCode || 0, result.code);
    } catch (error) {
      if (command !== 'harden-batch' && command !== 'snapshot') throw error;
      console.error(`ERROR ${domain}: ${error.message}`);
      rows.push({ domain, status: 'error', error: error.message });
      process.exitCode = Math.max(process.exitCode || 0, 1);
    }
  }
  if (command === 'snapshot') {
    const entries = rows.map((r) => r.status === 'error' ? { domain: r.domain, state: 'error', signals: [r.error], counts: null } : r);
    writeFileSync(p.inventoryJson, JSON.stringify(entries, null, 2), { mode: 0o600 });
    writeFileSync(p.inventoryMd, renderInventory(entries, readTicks(p.inventoryMd)), { mode: 0o600 });
  }
  if (command === 'harden-batch' || command === 'snapshot') saveReport(p, command, { rows, code: process.exitCode || 0 });
}
