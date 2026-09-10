// Inventory rendering and the backup store. The invariant that matters here is
// that a regeneration never loses a human's tick: the inventory is a worklist
// people edit by hand between runs.

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  STATE_ORDER, readTicks, renderInventory, tickDomain,
  backupDir, latestBackup, saveBackup,
} from '../lib/report.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

let dir;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'odm-report-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const entry = (domain, state, over = {}) => ({
  domain, state, signals: ['empty zone'],
  counts: { mx: 0, txt: 1, cname: 0, a: 0, total: 1 }, ...over,
});

describe('renderInventory', () => {
  test('groups by state in triage order, dormant first', () => {
    const md = renderInventory([
      entry('c.com', 'mail-active'), entry('a.com', 'dormant'), entry('b.com', 'web-active'),
    ]);
    const order = STATE_ORDER.filter((s) => md.includes(`| ${s} |`));
    assert.deepEqual(order, ['dormant', 'web-active', 'mail-active']);
    assert.ok(md.indexOf('Dormant') < md.indexOf('Mail active'));
  });

  test('warns loudly on the mail-active section', () => {
    assert.match(renderInventory([entry('a.com', 'mail-active')]), /DO NOT harden without checking/);
  });

  test('domains are sorted inside a group', () => {
    const md = renderInventory([entry('z.com', 'dormant'), entry('a.com', 'dormant')]);
    assert.ok(md.indexOf('**a.com**') < md.indexOf('**z.com**'));
  });

  test('an empty state produces no section', () => {
    const md = renderInventory([entry('a.com', 'dormant')]);
    assert.equal(md.includes('Unreachable'), false);
  });

  test('a domain with no counts renders a dash, not a crash', () => {
    const md = renderInventory([entry('a.com', 'error', { counts: null })]);
    assert.match(md, /\*\*a\.com\*\* — —/);
  });
});

describe('ticks survive regeneration', () => {
  test('readTicks -> renderInventory -> readTicks keeps state and note', () => {
    const path = join(dir, 'inventory.md');
    writeFileSync(path, renderInventory([entry('a.com', 'dormant'), entry('b.com', 'dormant')]));

    assert.equal(tickDomain(path, 'a.com', 'cleaned 2026-01-01'), true);

    const ticks = readTicks(path);
    assert.deepEqual(ticks['a.com'], { checked: true, note: 'cleaned 2026-01-01' });
    assert.deepEqual(ticks['b.com'], { checked: false, note: null });

    // Regenerate as `snapshot` and `inventory` do, then re-read.
    writeFileSync(path, renderInventory([entry('a.com', 'dormant'), entry('b.com', 'dormant')], ticks));
    const after = readTicks(path);
    assert.deepEqual(after['a.com'], { checked: true, note: 'cleaned 2026-01-01' });
    assert.equal(after['b.com'].checked, false);
  });

  test('a tick survives the domain changing state', () => {
    const path = join(dir, 'inventory.md');
    writeFileSync(path, renderInventory([entry('a.com', 'dormant')]));
    tickDomain(path, 'a.com', 'cleaned');
    const ticks = readTicks(path);

    const md = renderInventory([entry('a.com', 'web-active')], ticks);
    assert.match(md, /- \[x\] \*\*a\.com\*\*/);
    assert.equal(readTicks(join(dir, 'nope.md'))['a.com'], undefined);
  });

  test('the header counts ticked domains per group', () => {
    const md = renderInventory(
      [entry('a.com', 'dormant'), entry('b.com', 'dormant')],
      { 'a.com': { checked: true, note: null } },
    );
    assert.match(md, /## Dormant[^\n]*\(1\/2\)/);
    assert.match(md, /\| dormant \| 2 \| 1 \|/);
  });
});

describe('tickDomain', () => {
  test('returns false for an unknown domain and leaves the file alone', () => {
    const path = join(dir, 'inventory.md');
    const before = renderInventory([entry('a.com', 'dormant')]);
    writeFileSync(path, before);
    assert.equal(tickDomain(path, 'other.com', 'x'), false);
    assert.equal(readFileSync(path, 'utf8'), before);
  });

  test('returns false when there is no inventory yet', () => {
    assert.equal(tickDomain(join(dir, 'missing.md'), 'a.com', 'x'), false);
  });

  test('re-ticking replaces the note instead of appending a second one', () => {
    const path = join(dir, 'inventory.md');
    writeFileSync(path, renderInventory([entry('a.com', 'dormant')]));
    tickDomain(path, 'a.com', 'first');
    tickDomain(path, 'a.com', 'second');
    const line = readFileSync(path, 'utf8').split('\n').find((l) => l.includes('a.com'));
    assert.match(line, /<!-- second -->$/);
    assert.equal(line.match(/<!--/g).length, 1);
  });

  test('a domain that is a substring of another is not ticked by mistake', () => {
    const path = join(dir, 'inventory.md');
    writeFileSync(path, renderInventory([entry('example.com', 'dormant'), entry('my-example.com', 'dormant')]));
    tickDomain(path, 'example.com', 'x');
    const ticks = readTicks(path);
    assert.equal(ticks['example.com'].checked, true);
    assert.equal(ticks['my-example.com'].checked, false);
  });
});

describe('backup store', () => {
  test('saveBackup writes a timestamped zone that latestBackup finds again', () => {
    const text = '$TTL 3600\n@ IN TXT "v=spf1 -all"\n';
    const path = saveBackup(dir, 'example.com', text);
    assert.match(path, /example\.com\/[\dTZ-]+\.zone$/);
    assert.equal(readFileSync(path, 'utf8'), text);
    assert.equal(latestBackup(dir, 'example.com'), path);
  });

  test('the newest timestamp wins', () => {
    const d = backupDir(dir, 'example.com');
    writeFileSync(join(d, '2026-01-01T00-00-00-000Z.zone'), 'old');
    writeFileSync(join(d, '2026-06-01T00-00-00-000Z.zone'), 'new');
    assert.equal(readFileSync(latestBackup(dir, 'example.com'), 'utf8'), 'new');
  });

  test('non-zone files are ignored', () => {
    const d = backupDir(dir, 'example.com');
    writeFileSync(join(d, '2026-01-01T00-00-00-000Z.zone'), 'zone');
    writeFileSync(join(d, '2099-01-01-notes.txt'), 'not a zone');
    assert.match(latestBackup(dir, 'example.com'), /\.zone$/);
  });

  test('no backup at all -> null, so callers can say "run snapshot"', () => {
    assert.equal(latestBackup(dir, 'never-seen.com'), null);
    mkdirSync(join(dir, 'empty.com'));
    assert.equal(latestBackup(dir, 'empty.com'), null);
  });

  test('backupDir creates the directory on demand', () => {
    const d = backupDir(join(dir, 'deep', 'nested'), 'example.com');
    writeFileSync(join(d, 'x.zone'), 'ok');
    assert.equal(latestBackup(join(dir, 'deep', 'nested'), 'example.com'), join(d, 'x.zone'));
  });
});
