import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
const dir = mkdtempSync(join(tmpdir(), 'dns-posture-pack-'));
try {
  const [pack] = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', dir], { encoding: 'utf8' }));
  for (const { path } of pack.files) {
    assert.match(path, /^(?:lib\/[^/]+\.mjs|lib\/providers\/[^/]+\.mjs|config\/policy\.mjs|docs\/[^/]+\.md|(?:dns-posture|ovh)\.mjs|package\.json|README(?:\.fr)?\.md|LICENSE|CHANGELOG\.md)$/);
    assert.doesNotMatch(path, /storage|\.env|test\//);
  }
  const archive = join(dir, pack.filename);
  execFileSync('tar', ['-xzf', archive, '-C', dir]);
  const root = join(dir, 'package');
  const bundledPolicy = (await import(new URL(`file://${join(root, 'config/policy.mjs')}`))).default;
  assert.equal(Object.keys(bundledPolicy.domains).length, 0, 'Bundled policy must not contain operational overrides');
  const pkg = JSON.parse(readFileSync(join(root, 'package.json')));
  assert.equal(pkg.dependencies, undefined);
  const caller = join(dir, 'caller');
  mkdirSync(caller);
  const blocker = join(dir, 'offline.mjs');
  writeFileSync(blocker, "globalThis.fetch = () => { throw new Error('Network forbidden in pack smoke'); };\n");
  const env = { PATH: process.env.PATH, HOME: caller, OVH_ENV_FILE: join(dir, 'absent.env'), OVH_ENDPOINT: 'ovh-nowhere' };
  const run = (args) => execFileSync(process.execPath, ['--import', blocker, join(root, 'dns-posture.mjs'), ...args], { cwd: caller, env, encoding: 'utf8' });
  assert.match(run(['--help']), /dns-posture/);
  assert.equal(run(['--version']).trim(), pkg.version);
  run(['policy']);
  run(['inventory', 'example.com']);
  run(['compliance', 'example.com']);
  assert.ok(readFileSync(join(caller, 'storage', 'inventory.json')));
  // A second installation can consume the caller's persistent storage.
  rmSync(root, { recursive: true });
  execFileSync('tar', ['-xzf', archive, '-C', dir]);
  assert.match(run(['inventory', 'example.com']), /rebuilt/);
  if (process.argv[2]) {
    const destination = resolve(process.argv[2]);
    mkdirSync(destination, { recursive: true });
    writeFileSync(join(destination, pack.filename), readFileSync(archive));
  }
  console.log(`Verified ${pack.filename}: ${pack.files.length} allowlisted files, offline CLI, persistent caller storage`);
} finally { rmSync(dir, { recursive: true, force: true }); }
