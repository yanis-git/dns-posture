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
  renderCompliance, renderComplianceCsv,
} from '../lib/report.mjs';
import { evaluate, aggregate } from '../lib/baseline.mjs';

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
  // The scores seam. `snapshot` and `inventory` call renderInventory with two
  // arguments; only a future caller passes scores. The two-argument form must
  // stay byte-identical, because LINE_RE and tickDomain both parse this exact
  // line shape and a hand-ticked box has to survive every regeneration.
  test('omitting the scores argument produces byte-identical output', () => {
    const entries = [entry('a.com', 'dormant'), entry('b.com', 'web-active')];
    const ticks = { 'a.com': { checked: true, note: 'done by hand' } };
    assert.equal(renderInventory(entries, ticks), renderInventory(entries, ticks, {}));
  });

  test('a score is rendered right after the domain, where the line parser still finds it', () => {
    const entries = [entry('a.com', 'dormant')];
    const md = renderInventory(entries, {}, { 'a.com': { score: 86, grade: 'B' } });
    assert.match(md, /- \[ \] \*\*a\.com\*\* `B 86` —/);

    const path = join(dir, 'inventory.md');
    writeFileSync(path, md);
    assert.deepEqual(Object.keys(readTicks(path)), ['a.com']);
    assert.equal(tickDomain(path, 'a.com', 'hardened'), true);
    assert.match(readFileSync(path, 'utf8'), /- \[x\] \*\*a\.com\*\* `B 86` .* <!-- hardened -->/);
  });

  test('a domain the scorer could not reach is rendered exactly as before', () => {
    const entries = [entry('a.com', 'dormant')];
    assert.equal(renderInventory(entries, {}, { 'a.com': { score: null, grade: null } }),
      renderInventory(entries, {}));
  });

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

// ---------------------------------------------------------------------------

describe('compliance rendering', () => {
  const report = (domain, records, over = {}) => ({ ...evaluate(records, { domain }), ...over });
  const portfolio = (domains) => ({
    generatedAt: '2026-09-16T10:00:00.000Z',
    baselineVersion: '1.0.0',
    portfolio: aggregate(domains),
    domains,
  });

  const perfect = () => report('good.example', [
    { name: '@', type: 'TXT', rdata: '"v=spf1 -all"' },
    { name: '_dmarc', type: 'TXT', rdata: '"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"' },
    { name: '*._domainkey', type: 'TXT', rdata: '"v=DKIM1; p="' },
    { name: '@', type: 'CAA', rdata: '0 issue ";"' },
    { name: '@', type: 'CAA', rdata: '0 issuewild ";"' },
    { name: '@', type: 'MX', rdata: '0 .' },
  ]);
  const broken = { domain: 'gone.example', state: 'error', score: null, grade: null, controls: [], error: 'no backup — run `snapshot`' };

  test('the worst domain is listed first — the reader acts top-down', () => {
    const md = renderCompliance(portfolio([perfect(), report('bad.example', [])]));
    assert.ok(md.indexOf('| bad.example |') < md.indexOf('| good.example |'));
  });

  test('a domain with no backup renders as an error, never as a zero', () => {
    const md = renderCompliance(portfolio([perfect(), broken]));
    assert.match(md, /\| gone\.example \| error \| — \|/);
    assert.doesNotMatch(md, /\| gone\.example \| \w+ \| 0 \|/);
    assert.match(md, /## Not scored/);
    assert.match(md, /excluded from every average — not scored zero/);
  });

  test('an n/a the baseline decided is shown with its reason; a mechanical one is not', () => {
    // A zone with an OVH redirect: CAA is n/a by judgement, and worth reading.
    const redirecting = report('redirect.example', [{ name: '@', type: 'TXT', rdata: '"3|www.example.com"' }]);
    const md = renderCompliance(portfolio([redirecting]));
    assert.match(md, /`n\/a` `caa\.issue-deny`/);
    assert.doesNotMatch(md, /`n\/a` `spf\.no-permissive`/);
  });

  test('a finding carries its reference and the command that fixes it', () => {
    const md = renderCompliance(portfolio([report('bad.example', [])]));
    assert.match(md, /`spf\.present` \(critical\)/);
    assert.match(md, /refs: RFC 7208/);
    assert.match(md, /node ovh\.mjs harden bad\.example --apply/);
  });

  test('a critical failure is marked so it is visible in a wall of bullets', () => {
    assert.match(renderCompliance(portfolio([report('bad.example', [])])), /\*\*!! `[a-z.]+` \(critical\)\*\*/);
  });

  test('a pipe in a value cannot break the table open', () => {
    const piped = report('pipe.example', [{ name: '@', type: 'TXT', rdata: '"3|www.example.com"' }]);
    for (const line of renderCompliance(portfolio([piped])).split('\n')) {
      if (!line.startsWith('| pipe.example')) continue;
      assert.equal(line.replace(/\\\|/g, '').split('|').length - 1, 9, `cells broke: ${line}`);
    }
  });

  test('an empty portfolio says what to do instead of printing a null score', () => {
    const md = renderCompliance(portfolio([]));
    assert.match(md, /No domain could be scored/);
    assert.match(md, /node ovh\.mjs snapshot/);
  });

  test('the header states the baseline version — a score is meaningless without it', () => {
    assert.match(renderCompliance(portfolio([perfect()])), /baseline v1\.0\.0/);
  });
});

describe('compliance CSV', () => {
  const portfolio = (domains) => ({ portfolio: aggregate(domains), domains });
  const rows = (csv) => csv.trim().split('\n');

  test('one row per (domain, control), passes included — that is the audit trail', () => {
    const a = evaluate([], { domain: 'a.example' });
    const b = evaluate([], { domain: 'b.example' });
    const out = rows(renderComplianceCsv(portfolio([a, b])));
    assert.equal(out.length, 1 + a.controls.length + b.controls.length);
    assert.ok(out.some((r) => r.includes(',pass,')), 'a pass must appear, not only failures');
  });

  test('the header is stable — someone has a spreadsheet pointed at these columns', () => {
    assert.equal(rows(renderComplianceCsv(portfolio([])))[0],
      'domain,state,score,grade,control,title,axis,severity,scope,status,detail,refs,remediation');
  });

  test('commas and quotes are escaped RFC 4180 style', () => {
    const csv = renderComplianceCsv(portfolio([evaluate([
      { name: '@', type: 'TXT', rdata: '"v=spf1 include:a.example, include:b.example ~all"' },
    ], { domain: 'x.example' })]));
    for (const row of rows(csv).slice(1)) {
      const outside = row.replace(/"(?:[^"]|"")*"/g, '');
      assert.equal(outside.split(',').length, 13, `a value leaked a separator: ${row}`);
    }
    assert.ok(csv.includes('""'), 'an embedded quote should be doubled, not dropped');
  });

  test('a domain with no backup still gets a row rather than vanishing', () => {
    const csv = renderComplianceCsv(portfolio([
      { domain: 'gone.example', state: 'error', score: null, grade: null, controls: [], error: 'no backup' },
    ]));
    assert.match(csv, /^gone\.example,error,,,,,,,,error,no backup,,$/m);
  });

  test('the file ends with a newline — a bare last line confuses spreadsheet imports', () => {
    assert.ok(renderComplianceCsv(portfolio([])).endsWith('\n'));
  });
});
