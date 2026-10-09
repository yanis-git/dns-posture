import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
let dir;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'dns-live-cli-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });
function cli(provider, args, fail) {
  return spawnSync(process.execPath, ['--import', resolve('test/helpers/provider-simulator.mjs'), resolve('ovh.mjs'), ...args, '--provider', provider], {
    encoding: 'utf8', timeout: 20000, cwd: dir,
    env: { PATH: process.env.PATH, OVH_ENV_FILE: join(dir, 'absent.env'), OVH_ENDPOINT: 'ovh-nowhere',
      DNS_POSTURE_STORAGE_DIR: join(dir, 'storage'), APP_KEY: 'test', APP_SECRET: 'test', OVH_CONSUMER_KEY: 'test',
      CLOUDFLARE_API_TOKEN: 'test', SIM_STATE: join(dir, 'state.json'), ...(fail ? { SIM_FAIL: fail } : {}),
    },
  });
}
for (const provider of ['ovh', 'cloudflare']) {
  test(`${provider}: dry-run, verified application, offline review, idempotence and restoration`, () => {
    const dry = cli(provider, ['harden', 'example.com']);
    assert.equal(dry.status, 0, dry.stderr);
    assert.equal(existsSync(join(dir, 'state.json')), false);
    const done = cli(provider, ['harden', 'example.com', '--apply']);
    assert.equal(done.status, 0, done.stderr);
    const before = JSON.parse(readFileSync(join(dir, 'state.json'))).writes.length;
    assert.equal(cli(provider, ['harden', 'example.com', '--apply']).status, 0);
    assert.equal(JSON.parse(readFileSync(join(dir, 'state.json'))).writes.length, before);
    const root = join(dir, 'storage', 'providers', provider);
    const backups = join(root, readdirSync(root)[0], 'example.com', 'backups');
    const earliest = readdirSync(backups).filter((f) => f.endsWith('.json')).sort()[0];
    const restored = cli(provider, ['restore', 'example.com', join(backups, earliest), '--apply']);
    assert.equal(restored.status, 0, restored.stderr);
    const records = JSON.parse(readFileSync(join(dir, 'state.json'))).records;
    assert.equal(records.length, 1);
    assert.equal(records[0].fieldType, 'MX');
    const review = cli(provider, ['policy', 'example.com', '--json']);
    assert.equal(review.status, 0, review.stderr);
  });
  for (const fail of ['write', 'diverge']) {
    test(`${provider}: ${fail} produces exit 2 instead of success`, () => {
      const result = cli(provider, ['harden', 'example.com', '--apply'], fail);
      assert.equal(result.status, 2, result.stderr + result.stdout);
    });
  }
}

test('batch continues after a refused zone and returns the worst result', () => {
  const result = cli('ovh', ['harden-batch', 'missing.example', 'example.com', '--apply']);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, /APPLY example.com/);
  assert.ok(JSON.parse(readFileSync(join(dir, 'state.json'))).writes.length > 0);
});
