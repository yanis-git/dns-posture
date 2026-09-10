// End-to-end: spawns the real CLI the way a freshly cloned checkout runs it —
// no .env, no credentials, no network. Everything asserted here is a first-run
// experience or a guard rail that protects a live zone.

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const CLI = join(dirname(dirname(fileURLToPath(import.meta.url))), 'ovh.mjs');

let storage;
beforeEach(() => { storage = mkdtempSync(join(tmpdir(), 'odm-smoke-')); });
afterEach(() => { rmSync(storage, { recursive: true, force: true }); });

/**
 * Run the CLI in a deliberately sterile environment.
 *
 * OVH_ENV_FILE points at a file that does not exist, so the developer's real
 * .env is never picked up — without it these tests would authenticate against a
 * live OVH account. OVH_ENDPOINT is invalid on top, so any code path that does
 * manage to build a client fails locally instead of reaching the network.
 */
async function cli(args) {
  const env = {
    PATH: process.env.PATH,
    HOME: storage,
    OVH_STORAGE_DIR: storage,
    OVH_ENV_FILE: join(storage, 'no-such.env'),
    OVH_ENDPOINT: 'ovh-nowhere',
  };
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args], { env, timeout: 20000 });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code ?? 1, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

describe('first run on a fresh clone', () => {
  test('no arguments prints help and exits 0 — no .env required', async () => {
    const { code, stdout } = await cli([]);
    assert.equal(code, 0);
    assert.match(stdout, /anti-spoofing DNS hardening/);
    assert.match(stdout, /node ovh\.mjs auth/);
  });

  test('--help and --version work without credentials', async () => {
    assert.equal((await cli(['--help'])).code, 0);
    const version = await cli(['--version']);
    assert.equal(version.code, 0);
    assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/);
  });

  test('an unknown command falls back to help rather than a stack trace', async () => {
    const { code, stdout } = await cli(['frobnicate']);
    assert.equal(code, 0);
    assert.match(stdout, /Options:/);
  });

  test('a command needing the API names the missing variables', async () => {
    const { code, stderr } = await cli(['whoami']);
    assert.equal(code, 1);
    assert.match(stderr, /Missing OVH credentials: APP_KEY, APP_SECRET/);
    assert.doesNotMatch(stderr, /at \w+ \(/, 'should be a message, not a stack trace');
  });
});

describe('guard rails', () => {
  test('harden refuses to run without exactly one domain', async () => {
    const none = await cli(['harden']);
    assert.equal(none.code, 1);
    assert.match(none.stderr, /exactly ONE domain/);

    const two = await cli(['harden', 'a.com', 'b.com']);
    assert.equal(two.code, 1);
    assert.match(two.stderr, /exactly ONE domain/);
  });

  test('harden-batch refuses --force outright', async () => {
    const { code, stderr } = await cli(['harden-batch', '--force', '--list', 'x.txt']);
    assert.equal(code, 1);
    assert.match(stderr, /--force is refused in batch mode/);
    assert.match(stderr, /one at a time/);
  });

  test('harden-batch with no domains refuses to run empty', async () => {
    const { code, stderr } = await cli(['harden-batch']);
    assert.equal(code, 1);
    assert.match(stderr, /No domain: pass --list/);
  });

  test('an unknown option stops the run before anything happens', async () => {
    const { code, stderr } = await cli(['harden', 'example.com', '--yolo']);
    assert.equal(code, 1);
    assert.match(stderr, /Unknown option: --yolo/);
  });

  test('restore without a backup says so instead of touching the zone', async () => {
    const { code, stderr } = await cli(['restore', 'example.com']);
    assert.equal(code, 1);
    assert.match(stderr, /No backup found for example\.com/);
  });
});

describe('offline inventory', () => {
  const ZONES = {
    'dormant.example': [
      '$TTL 3600',
      '@\tIN SOA dns101.ovh.net. tech.ovh.net. (2088953526 86400 3600 3600000 60)',
      '   3600 IN TXT     "v=spf1 -all"',
      '_dmarc   3600 IN TXT     "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"',
    ].join('\n'),
    'mail.example': [
      '$TTL 3600',
      '@ 3600 IN MX 10 aspmx.l.google.com.',
    ].join('\n'),
    'web.example': [
      '$TTL 3600',
      'www 3600 IN A 203.0.113.10',
    ].join('\n'),
  };

  function seedBackups() {
    for (const [domain, zone] of Object.entries(ZONES)) {
      const dir = join(storage, 'backups', domain);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, '2026-01-01T00-00-00-000Z.zone'), zone);
    }
    writeFileSync(join(storage, 'domains.csv'), ['Domain', ...Object.keys(ZONES), 'never-seen.example'].join('\n'));
  }

  test('rebuilds the inventory from backups with no network and no credentials', async () => {
    seedBackups();
    const { code, stdout } = await cli(['inventory']);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /Inventory rebuilt from backups \(4 domains/);

    const md = readFileSync(join(storage, 'inventory.md'), 'utf8');
    assert.match(md, /- \[ \] \*\*dormant\.example\*\*/);
    assert.match(md, /Mail active — DO NOT harden/);

    const json = JSON.parse(readFileSync(join(storage, 'inventory.json'), 'utf8'));
    const state = Object.fromEntries(json.map((e) => [e.domain, e.state]));
    assert.deepEqual(state, {
      'dormant.example': 'dormant',
      'mail.example': 'mail-active',
      'web.example': 'web-active',
      'never-seen.example': 'error',
    });
  });

  test('a domain with no backup is flagged, not silently dropped', async () => {
    seedBackups();
    await cli(['inventory']);
    const json = JSON.parse(readFileSync(join(storage, 'inventory.json'), 'utf8'));
    const missing = json.find((e) => e.domain === 'never-seen.example');
    assert.match(missing.signals.join(' '), /no backup — run `snapshot`/);
  });

  test('a manual tick survives a rebuild', async () => {
    seedBackups();
    await cli(['inventory']);

    const path = join(storage, 'inventory.md');
    writeFileSync(path, readFileSync(path, 'utf8').replace('- [ ] **dormant.example**', '- [x] **dormant.example**'));

    await cli(['inventory']);
    assert.match(readFileSync(path, 'utf8'), /- \[x\] \*\*dormant\.example\*\*/);
  });

  test('the storage tree is created under OVH_STORAGE_DIR, not in the checkout', async () => {
    await cli(['inventory', 'dormant.example']);
    assert.ok(existsSync(join(storage, 'backups')));
    assert.ok(existsSync(join(storage, 'reports')));
    assert.ok(existsSync(join(storage, 'inventory.md')));
  });
});
