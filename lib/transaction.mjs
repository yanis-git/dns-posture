import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, openSync, closeSync, appendFileSync, unlinkSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { domainName } from './validation.mjs';
import { sameRecord, recordLabel } from './zone.mjs';

const stable = (v) => Array.isArray(v) ? v.map(stable) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])])) : v;
export const digest = (v) => createHash('sha256').update(JSON.stringify(stable(v))).digest('hex');
export const fingerprint = (records) => digest(records.map((r) => stable(r)).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))));
const accountKey = (account) => createHash('sha256').update(String(account)).digest('hex').slice(0, 24);
export function zoneDirectory(storage, zone) {
  if (!['ovh', 'cloudflare'].includes(zone.provider) || !zone.account) throw new Error('Missing provider/account identity');
  return join(storage, 'providers', zone.provider, accountKey(zone.account), domainName(zone.name));
}
export function saveSnapshot(storage, zone, records, zoneText) {
  const dir = join(zoneDirectory(storage, zone), 'backups');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const payload = { format: 1, at: new Date().toISOString(), zone, records, zoneText };
  const document = { ...payload, integrity: digest(payload) };
  const base = join(dir, `${payload.at.replace(/[:.]/g, '-')}-${randomUUID()}`);
  writeFileSync(`${base}.zone`, zoneText, { flag: 'wx', mode: 0o600 });
  writeFileSync(`${base}.json`, JSON.stringify(document, null, 2), { flag: 'wx', mode: 0o600 });
  readSnapshot(`${base}.json`, zone);
  return `${base}.json`;
}
export function readSnapshot(file, zone = null) {
  const { integrity, ...data } = JSON.parse(readFileSync(file, 'utf8'));
  if (data.format !== 1 || digest(data) !== integrity || !Array.isArray(data.records)) throw new Error('Invalid backup format or integrity');
  domainName(data.zone.name);
  if (zone && ['provider', 'account', 'id', 'name'].some((k) => data.zone[k] !== zone[k])) throw new Error('Backup provider/account/zone mismatch');
  return data;
}
export function latestSnapshot(storage, provider, domain, account = null) {
  const base = join(storage, 'providers', provider);
  if (!existsSync(base)) return null;
  const accounts = account ? [accountKey(account)] : readdirSync(base);
  const candidates = [];
  for (const key of accounts) {
    const dir = join(base, key, domainName(domain), 'backups');
    if (!existsSync(dir)) continue;
    const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
    if (files.length) candidates.push(join(dir, files.at(-1)));
  }
  if (candidates.length > 1) throw new Error('Multiple accounts have this zone: select --account');
  return candidates[0] ?? null;
}

export function sameState(a, b) {
  if (!sameRecord(a, b) || a.ttl !== b.ttl) return false;
  // Provider-generated timestamps and ids are not restorable state.
  for (const key of ['proxied', 'comment', 'tags', 'settings', 'data']) {
    if (a.native?.[key] !== undefined && digest(a.native[key]) !== digest(b.native?.[key] ?? null)) return false;
  }
  return true;
}
export function restorePlan(current, wanted) {
  const remaining = [...current];
  const keep = [];
  const create = [];
  for (const record of wanted) {
    const idx = remaining.findIndex((r) => sameState(record, r));
    if (idx < 0) create.push(record);
    else keep.push(remaining.splice(idx, 1)[0]);
  }
  return { keep, create, delete: remaining };
}
export function operationsFor(plan) {
  const deletes = [...plan.delete];
  const operations = [];
  for (const record of plan.create) {
    // CAA needs an observed replacement before removal; do not update it in place.
    const idx = record.fieldType === 'CAA' ? -1 : deletes.findIndex((r) => r.fieldType === record.fieldType && r.subDomain === record.subDomain);
    if (idx < 0) operations.push({ action: 'create', record });
    else {
      const old = deletes.splice(idx, 1)[0];
      operations.push({ action: 'update', old, record: { ...record, native: record.native || old.native } });
    }
  }
  operations.push(...deletes.map((record) => ({ action: 'delete', record })));
  return operations;
}

/** Every CLI mutation, including restore, must pass through this boundary. */
export async function applyTransaction(provider, zone, before, plan, storage) {
  const operations = operationsFor(plan);
  provider.validate(operations, zone);
  if (operations.some((op) => op.action === 'delete' && op.record.fieldType === 'CAA')
    && !plan.create.some((r) => r.fieldType === 'CAA')) throw new Error('CAA deletion requires a replacement');
  const dir = zoneDirectory(storage, zone);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = join(dir, 'apply.lock');
  let fd;
  try { fd = openSync(lock, 'wx', 0o600); } catch { throw new Error('Zone is locked; inspect the previous journal before removing a stale apply.lock'); }
  const result = { code: 0, verified: false, created: [], updated: [], deleted: [], errors: [], journal: join(dir, `journal-${randomUUID()}.jsonl`) };
  let attempted = false;
  const log = (event) => appendFileSync(result.journal, JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n', { mode: 0o600 });
  try {
    writeFileSync(fd, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
    const current = await provider.read(zone);
    if (fingerprint(current) !== fingerprint(before)) throw new Error('Concurrent zone change: re-plan before applying');
    const zoneText = await provider.export(zone, current);
    result.backup = saveSnapshot(storage, zone, current, zoneText);
    // Export and disk I/O take time. Recheck after the backup, immediately before writes.
    if (fingerprint(await provider.read(zone)) !== fingerprint(current)) throw new Error('Concurrent zone change during backup');
    log({ event: 'begin', zone, backup: result.backup, operations });
    for (const op of operations) {
      if (op.action === 'delete' && op.record.fieldType === 'CAA') {
        const replacements = plan.create.filter((r) => r.fieldType === 'CAA');
        if (!replacements.length) throw new Error('CAA deletion requires a replacement');
        const observed = await provider.read(zone);
        if (!replacements.every((r) => observed.some((o) => sameState(r, o)))) throw new Error('CAA replacement not observed; old records retained');
      }
      log({ event: 'intent', operation: op });
      attempted = true;
      if (op.action === 'update') await provider.update(zone, op.old, op.record);
      else await provider[op.action](zone, op.record);
      result[op.action === 'create' ? 'created' : op.action === 'update' ? 'updated' : 'deleted'].push(recordLabel(op.record));
      log({ event: 'complete', operation: op });
    }
    if (operations.length) {
      log({ event: 'finalize-intent' });
      await provider.finalize(zone);
      log({ event: 'finalized' });
    }
    const expected = [...plan.keep, ...operations.filter((o) => o.action !== 'delete').map((o) => o.record)];
    const observed = await provider.read(zone);
    const delta = restorePlan(observed, expected);
    if (delta.create.length || delta.delete.length) throw new Error('Final verification diverged from the planned state');
    result.verified = true;
    log({ event: 'verified' });
  } catch (error) {
    result.errors.push(error.message);
    result.code = attempted ? 2 : 1;
    try { log({ event: attempted ? 'uncertain' : 'refused', error: error.message }); } catch { /* Preserve the original failure if storage itself failed. */ }
  } finally {
    closeSync(fd);
    unlinkSync(lock);
  }
  return result;
}
