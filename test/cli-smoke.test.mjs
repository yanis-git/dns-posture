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
async function cli(args, extraEnv = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: storage,
    OVH_STORAGE_DIR: storage,
    OVH_ENV_FILE: join(storage, 'no-such.env'),
    OVH_ENDPOINT: 'ovh-nowhere',
    ...extraEnv,
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

// The shared zone fixture: one dormant, one mail-active, one web-active, plus a
// domain in the CSV with no backup at all. `inventory` and `compliance` read the
// same backups, so they read the same fixture.
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

describe('offline inventory', () => {
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

describe('compliance — the offline portfolio audit', () => {
  test('it runs with no credentials, no network, and exits 0', async () => {
    seedBackups();
    const { code, stdout } = await cli(['compliance']);
    assert.equal(code, 0);
    assert.match(stdout, /Compliance baseline v\d+\.\d+\.\d+/);
    assert.match(stdout, /offline/);
  });

  test('it writes the three deliverables', async () => {
    seedBackups();
    await cli(['compliance']);
    for (const f of ['compliance.md', 'compliance.json', 'compliance.csv']) {
      assert.ok(existsSync(join(storage, f)), `${f} was not written`);
    }
  });

  test('a dormant zone is scored and graded', async () => {
    seedBackups();
    await cli(['compliance']);
    const json = JSON.parse(readFileSync(join(storage, 'compliance.json'), 'utf8'));
    const dormant = json.domains.find((d) => d.domain === 'dormant.example');
    assert.equal(dormant.state, 'dormant');
    assert.equal(typeof dormant.score, 'number');
    assert.match(dormant.grade, /^[A-F]$/);
    assert.ok(dormant.controls.length >= 20, 'the whole catalogue should be evaluated');
  });

  test('every domain is audited whatever its state — not just the dormant ones', async () => {
    seedBackups();
    await cli(['compliance']);
    const json = JSON.parse(readFileSync(join(storage, 'compliance.json'), 'utf8'));
    const states = Object.fromEntries(json.domains.map((d) => [d.domain, d.state]));
    assert.equal(states['web.example'], 'web-active');
    assert.equal(states['mail.example'], 'mail-active');
    assert.equal(states['never-seen.example'], 'error');
  });

  test('a domain with no backup is excluded from the average, not scored zero', async () => {
    seedBackups();
    await cli(['compliance']);
    const { portfolio, domains } = JSON.parse(readFileSync(join(storage, 'compliance.json'), 'utf8'));
    const missing = domains.find((d) => d.domain === 'never-seen.example');
    assert.equal(missing.score, null);
    assert.match(missing.error, /no backup/);
    assert.equal(portfolio.errors, 1);
    assert.equal(portfolio.scored, domains.length - 1);

    const scored = domains.filter((d) => typeof d.score === 'number');
    const mean = Math.round(scored.reduce((sum, d) => sum + d.score, 0) / scored.length);
    assert.equal(portfolio.score, mean);
  });

  test('the console prints the portfolio score and the axes', async () => {
    seedBackups();
    const { stdout } = await cli(['compliance']);
    assert.match(stdout, /portfolio \d+\/100 \([A-F]\)/);
    assert.match(stdout, /anti-spoofing \d+ · closed by default \d+ · attack surface \d+/);
  });

  test('a single domain can be audited on its own', async () => {
    seedBackups();
    await cli(['compliance', 'dormant.example']);
    const json = JSON.parse(readFileSync(join(storage, 'compliance.json'), 'utf8'));
    assert.deepEqual(json.domains.map((d) => d.domain), ['dormant.example']);
  });

  // The inventory is a worklist people tick by hand. A read-only audit that
  // rewrote it would silently reorder lines under someone's cursor.
  test('it leaves inventory.md byte-identical', async () => {
    seedBackups();
    await cli(['inventory']);
    const path = join(storage, 'inventory.md');
    writeFileSync(path, readFileSync(path, 'utf8').replace('- [ ] **dormant.example**', '- [x] **dormant.example**'));
    const before = readFileSync(path);

    await cli(['compliance']);
    assert.deepEqual(readFileSync(path), before);
  });

  test('the CSV is one row per (domain, control) with a stable header', async () => {
    seedBackups();
    await cli(['compliance']);
    const rows = readFileSync(join(storage, 'compliance.csv'), 'utf8').trim().split('\n');
    assert.equal(rows[0], 'domain,state,score,grade,control,title,axis,severity,scope,status,detail,refs,remediation');
    assert.ok(rows.length > 50, 'four domains against the catalogue is a lot of rows');
  });

  test('with no backup at all it says what to run rather than crashing', async () => {
    writeFileSync(join(storage, 'domains.csv'), 'Domain\nnever-seen.example\n');
    const { code, stdout } = await cli(['compliance']);
    assert.equal(code, 0);
    assert.match(readFileSync(join(storage, 'compliance.md'), 'utf8'), /No domain could be scored/);
    assert.match(stdout, /no backup/);
  });

  test('the help lists the command and the CAA options', async () => {
    const { stdout } = await cli([]);
    assert.match(stdout, /node ovh\.mjs compliance/);
    assert.match(stdout, /--caa/);
    assert.match(stdout, /--iodef/);
  });
});

describe('the policy subcommand', () => {
  test('prints the shipped configuration with no backup, no credentials and no network', async () => {
    const { code, stdout } = await cli(['policy']);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /config\/policy\.mjs \(schema v1\) — valid/);
    assert.match(stdout, /Record templates \(6\)/);
    assert.match(stdout, /Remedy per check \(24 checks × 3 profiles\)/);
    // The remedy of a check is the whole point of the file: show it, per profile.
    assert.match(stdout, /spf\.hardfail\s+enforce spf\.deny\s+enforce spf\.deny/);
  });

  test('resolves one domain against its backup and previews what harden would do', async () => {
    seedBackups();
    const { code, stdout } = await cli(['policy', 'dormant.example']);
    assert.equal(code, 0, stdout);
    assert.match(stdout, /state {4}: dormant/);
    assert.match(stdout, /profile {2}: dormant/);
    assert.match(stdout, /Would publish/);
    assert.match(stdout, /Would delete \(\d+\) {3}every deletion is licensed by a failing check/);
    // The dormant fixture is already hardened bar the DKIM revocation.
    assert.match(stdout, /\+ \*\._domainkey TXT "v=DKIM1; p="\s+dkim\.wildcard-revoked/);
    assert.match(stdout, /never contacts OVH/);
  });

  test('a mail-active zone resolves to a profile that would write nothing', async () => {
    seedBackups();
    const { code, stdout } = await cli(['policy', 'mail.example', '--json']);
    assert.equal(code, 0, stdout);
    const out = JSON.parse(stdout);
    assert.equal(out.state, 'mail-active');
    assert.equal(out.profile, 'mail-active');
    assert.deepEqual([out.plan.create, out.plan.delete], [[], []]);
    assert.ok(out.checks.every((c) => !['add', 'enforce', 'remove'].includes(c.action)),
      'a mail-active profile must carry no writing remedy');
  });

  test('--json names the check behind every publication', async () => {
    seedBackups();
    const { stdout } = await cli(['policy', 'dormant.example', '--json']);
    const out = JSON.parse(stdout);
    assert.equal(out.schemaVersion, 1);
    assert.equal(out.checks.length, 24);
    for (const rec of out.plan.create) assert.ok(rec.wantedBy.length, `${rec.label} was published by nothing`);
    for (const rec of out.plan.delete) assert.ok(rec.checkId, `${rec.label} was deleted by nothing`);
  });

  test('without a backup it says what to run instead of crashing', async () => {
    const { code, stderr } = await cli(['policy', 'never-seen.example']);
    assert.equal(code, 1);
    assert.match(stderr, /No backup for never-seen\.example/);
    assert.match(stderr, /snapshot never-seen\.example/);
  });

  test('a broken policy file stops the run and says nothing was touched', async () => {
    const broken = join(storage, 'broken-policy.mjs');
    writeFileSync(broken, 'export default { version: 1, profiles: {}, oops: true };\n');
    const { code, stderr } = await cli(['policy'], { OVH_POLICY_FILE: broken });
    assert.equal(code, 1);
    assert.match(stderr, /unknown top-level key/);
    assert.match(stderr, /no profile covers the classifier state "dormant"/);
    assert.match(stderr, /Nothing was read from OVH and nothing was written/);
  });

  test('a policy file that is not there at all fails by name', async () => {
    const { code, stderr } = await cli(['policy'], { OVH_POLICY_FILE: join(storage, 'absent.mjs') });
    assert.equal(code, 1);
    assert.match(stderr, /cannot be loaded/);
  });

  test('a broken policy file does not stand between an operator and restore', async () => {
    seedBackups();
    const broken = join(storage, 'broken-policy.mjs');
    writeFileSync(broken, 'export default { version: 99 };\n');
    const { code, stdout } = await cli(['restore', 'dormant.example'], { OVH_POLICY_FILE: broken });
    assert.equal(code, 0, stdout);
    assert.match(stdout, /DRY-RUN — legacy backup readable/);
  });

  test('the help lists the subcommand and the policy file', async () => {
    const { stdout } = await cli([]);
    assert.match(stdout, /node ovh\.mjs policy/);
    assert.match(stdout, /OVH_POLICY_FILE/);
  });
});
