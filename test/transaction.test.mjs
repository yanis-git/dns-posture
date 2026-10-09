import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyTransaction, saveSnapshot, readSnapshot, zoneDirectory, restorePlan } from '../lib/transaction.mjs';
import { posture } from '../lib/engine.mjs';
import policy from '../config/policy.mjs';

let storage;
beforeEach(() => { storage = mkdtempSync(join(tmpdir(), 'dns-transaction-')); });
afterEach(() => { rmSync(storage, { recursive: true, force: true }); });
globalThis.fetch = () => { throw new Error('No network'); };
const zone = { name: 'example.com', id: 'zone1', provider: 'cloudflare', account: 'account1' };
const r = (id, target, fieldType = 'TXT', subDomain = '') => ({ id, target, fieldType, subDomain, ttl: 3600 });
function fake(records, options = {}) {
  let state = structuredClone(records);
  let reads = 0;
  const calls = [];
  return {
    calls,
    validate() {},
    async read() {
      reads++;
      if (options.concurrent && reads === 2) state.push(r('race', 'changed'));
      if (options.diverge && calls.includes('finalize')) return [];
      return structuredClone(state);
    },
    async export() { if (options.exportFail) throw new Error('Export failed'); return '$ORIGIN example.com.\n'; },
    async create(_zone, record) {
      calls.push('create');
      if (options.failCreate) throw new Error('Write outcome uncertain');
      state.push({ ...record, id: 'new' + calls.length });
    },
    async update(_zone, old, record) {
      calls.push('update');
      state = state.map((v) => v.id === old.id ? { ...record, id: old.id } : v);
    },
    async delete(_zone, record) { calls.push('delete'); state = state.filter((v) => v.id !== record.id); },
    async finalize() { calls.push('finalize'); },
  };
}
const plan = (records) => ({ delete: records, create: [r(undefined, 'v=spf1 -all')], keep: [] });

test('prefers an update and verifies the final state against the backed-up snapshot', async () => {
  const records = [r('old', 'v=spf1 ~all')];
  const provider = fake(records);
  const result = await applyTransaction(provider, zone, records, plan(records), storage);
  assert.equal(result.code, 0);
  assert.equal(result.verified, true);
  assert.deepEqual(provider.calls, ['update', 'finalize']);
  assert.deepEqual(readSnapshot(result.backup, zone).records, records);
  assert.match(readFileSync(result.journal, 'utf8'), /"event":"intent"/);
});

test('an uncertain creation stops all remaining writes and returns exit 2', async () => {
  const records = [r('old', '10 mx1.ovh.net.', 'MX')];
  const provider = fake(records, { failCreate: true });
  const result = await applyTransaction(provider, zone, records, plan(records), storage);
  assert.equal(result.code, 2);
  assert.equal(result.verified, false);
  assert.deepEqual(provider.calls, ['create']);
});

test('final verification divergence cannot become success', async () => {
  const provider = fake([], { diverge: true });
  const result = await applyTransaction(provider, zone, [], plan([]), storage);
  assert.equal(result.code, 2);
  assert.match(result.errors[0], /Final verification/);
});

for (const failure of ['exportFail', 'concurrent']) {
  test(`${failure} blocks every write before application`, async () => {
    const provider = fake([], { [failure]: true });
    const result = await applyTransaction(provider, zone, [], plan([]), storage);
    assert.equal(result.code, 1);
    assert.deepEqual(provider.calls, []);
  });
}

test('a failed backup write blocks DNS writes', async () => {
  const dir = zoneDirectory(storage, zone);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'backups'), 'not a directory');
  const provider = fake([]);
  assert.equal((await applyTransaction(provider, zone, [], plan([]), storage)).code, 1);
  assert.deepEqual(provider.calls, []);
});

test('a local lock prevents a second writer without clearing the first lock', async () => {
  const dir = zoneDirectory(storage, zone);
  mkdirSync(dir, { recursive: true });
  const lock = join(dir, 'apply.lock');
  writeFileSync(lock, 'another writer');
  const provider = fake([]);
  await assert.rejects(applyTransaction(provider, zone, [], plan([]), storage), /locked/);
  assert.equal(existsSync(lock), true);
  assert.deepEqual(provider.calls, []);
});

test('integrity and provider identity are checked before restoration', () => {
  const file = saveSnapshot(storage, zone, [], '$ORIGIN example.com.');
  assert.throws(() => readSnapshot(file, { ...zone, account: 'another' }), /mismatch/);
  const data = JSON.parse(readFileSync(file));
  data.records.push(r('extra', 'tampered'));
  writeFileSync(file, JSON.stringify(data));
  assert.throws(() => readSnapshot(file), /integrity/);
});

test('restoration preserves native proxy, comments, tags and settings', async () => {
  const old = { ...r('old', '203.0.113.1', 'A'), native: { proxied: true, comment: 'example comment', tags: ['scope:example'], settings: { ipv4_only: true } } };
  const current = [{ ...old, target: '203.0.113.2', native: { ...old.native, comment: 'changed' } }];
  const provider = fake(current);
  const result = await applyTransaction(provider, zone, current, restorePlan(current, [old]), storage);
  assert.equal(result.code, 0);
  assert.deepEqual((await provider.read())[0].native, old.native);
});

test('CAA replacement is created and observed before old CAA removal', async () => {
  const records = [r('old', '0 issue "ca.example"', 'CAA')];
  const provider = fake(records);
  const result = await applyTransaction(provider, zone, records, { delete: records, keep: [], create: [r(undefined, '0 issue ";"', 'CAA')] }, storage);
  assert.equal(result.code, 0);
  assert.deepEqual(provider.calls, ['create', 'delete', 'finalize']);
});

test('a second hardening pass is empty and does not finalize the zone', async () => {
  const first = posture([], zone.name, policy).plan;
  const records = first.create.map((v, i) => ({ ...v, id: String(i) }));
  const second = posture(records, zone.name, policy).plan;
  assert.equal(second.create.length + second.delete.length, 0);
  const provider = fake(records);
  assert.equal((await applyTransaction(provider, zone, records, second, storage)).code, 0);
  assert.deepEqual(provider.calls, []);
});

test('disabling remediation cannot improve the baseline score', () => {
  const changed = structuredClone({ ...policy, defaults: { ...policy.defaults, keep: [] } });
  changed.profiles.dormant.checks['spf.present'] = { remedy: { action: 'off' }, reason: 'operator exception' };
  assert.equal(posture([], zone.name, changed).report.score, posture([], zone.name, policy).report.score);
});

test('unknown MX keeps the mail profile non-mutating even with legacy overrides', () => {
  const records = [r('mx', '10 mail.example.', 'MX'), r('ftp', 'example.com.', 'CNAME', 'ftp')];
  const out = posture(records, zone.name, policy, { nullMx: true, caa: true, cnames: ['ftp'], dropRedirect: true });
  assert.equal(out.state, 'mail-active');
  assert.equal(out.plan.create.length + out.plan.delete.length, 0);
});
