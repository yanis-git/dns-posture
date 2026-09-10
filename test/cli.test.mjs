// Argument and input-file parsing. Getting --keep or --list wrong is how a
// protected record ends up deleted, so the flags are pinned here.

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, requireDomain, findCsv, readCsvDomains, readListFile } from '../lib/cli.mjs';

globalThis.fetch = () => { throw new Error('no network in unit tests'); };

let dir;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'odm-cli-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const write = (name, body) => { const p = join(dir, name); writeFileSync(p, body); return p; };

describe('parseArgs', () => {
  test('dry-run is the default: no flag means no apply, no force', () => {
    const o = parseArgs(['example.com']);
    assert.equal(o.apply, undefined);
    assert.equal(o.force, undefined);
    assert.equal(o.dropRedirect, undefined);
    assert.equal(o.nullMx, false);
    assert.deepEqual(o._, ['example.com']);
  });

  test('boolean flags are recognised', () => {
    const o = parseArgs(['--apply', '--force', '--null-mx', '--drop-redirect']);
    assert.deepEqual(
      { a: o.apply, f: o.force, n: o.nullMx, d: o.dropRedirect },
      { a: true, f: true, n: true, d: true },
    );
  });

  test('--keep is repeatable and case-insensitive', () => {
    const o = parseArgs(['--keep', 'acme', '--keep', 'site-verification']);
    assert.equal(o.keep.length, 2);
    assert.ok(o.keep[0].test('_ACME-challenge'));
    assert.ok(o.keep[1].flags.includes('i'));
  });

  test('--drop-cname extends the ftp default rather than replacing it', () => {
    assert.deepEqual(parseArgs([]).cnames, ['ftp']);
    assert.deepEqual(parseArgs(['--drop-cname', 'webmail, Autodiscover']).cnames, ['ftp', 'webmail', 'autodiscover']);
  });

  test('--ttl is a number, not a string', () => {
    assert.strictEqual(parseArgs(['--ttl', '60']).ttl, 60);
  });

  test('value flags consume their argument', () => {
    const o = parseArgs(['--rua', 'mailto:d@example.com', '--csv', 'a.csv', '--list', 'b.txt', 'example.com']);
    assert.equal(o.rua, 'mailto:d@example.com');
    assert.equal(o.csv, 'a.csv');
    assert.equal(o.list, 'b.txt');
    assert.deepEqual(o._, ['example.com']);
  });

  test('an unknown option is rejected rather than silently ignored', () => {
    assert.throws(() => parseArgs(['--dry-run']), /Unknown option: --dry-run/);
  });

  test('--help and --version are understood', () => {
    assert.equal(parseArgs(['-h']).help, true);
    assert.equal(parseArgs(['--version']).version, true);
  });
});

describe('requireDomain', () => {
  test('accepts exactly one domain, normalised', () => {
    assert.equal(requireDomain({ _: ['  Example.COM '] }), 'example.com');
  });

  test('refuses zero domains', () => {
    assert.throws(() => requireDomain({ _: [] }), /exactly ONE domain \(got: none\)/);
  });

  test('refuses several — this command must not fan out silently', () => {
    assert.throws(() => requireDomain({ _: ['a.com', 'b.com'] }), /exactly ONE domain \(got: 2\)/);
  });
});

describe('readCsvDomains', () => {
  test('takes the first column, skips the header, lowercases and dedupes', () => {
    const p = write('x.csv', 'Domain,Expiry\nExample.COM,2027-01-01\nb.com,2027-01-01\nexample.com,2028-01-01\n');
    assert.deepEqual(readCsvDomains(p), ['example.com', 'b.com']);
  });

  test('strips a UTF-8 BOM and quoted fields', () => {
    const p = write('bom.csv', '\uFEFFDomain,Owner\n"example.com","ACME"\n');
    assert.deepEqual(readCsvDomains(p), ['example.com']);
  });

  test('blank lines are skipped', () => {
    const p = write('blank.csv', 'Domain\na.com\n\n\nb.com\n');
    assert.deepEqual(readCsvDomains(p), ['a.com', 'b.com']);
  });

  test('a header-only file yields nothing rather than a bogus domain', () => {
    assert.deepEqual(readCsvDomains(write('empty.csv', 'Domain\n')), []);
  });
});

describe('readListFile', () => {
  test('one domain per line, # comments, dedupe, lowercase', () => {
    const p = write('lot.txt', [
      '# batch of the day',
      'Example.com',
      'b.com   # keep an eye on this one',
      '',
      'example.com',
    ].join('\n'));
    assert.deepEqual(readListFile(p), ['example.com', 'b.com']);
  });

  test('a file with only comments is an error, not an empty silent run', () => {
    assert.throws(() => readListFile(write('c.txt', '# nothing here\n\n')), /contains no domain/);
  });
});

describe('findCsv', () => {
  test('--csv wins over anything in storage', () => {
    assert.equal(findCsv({ csv: '/tmp/given.csv' }, dir), '/tmp/given.csv');
  });

  test('otherwise the last CSV by name — dated exports sort chronologically', () => {
    write('domains_2026-01-01.csv', 'Domain\n');
    write('domains_2026-09-03.csv', 'Domain\n');
    write('notes.txt', 'x');
    assert.equal(findCsv({}, dir), join(dir, 'domains_2026-09-03.csv'));
  });

  test('no CSV at all points the user at --csv', () => {
    assert.throws(() => findCsv({}, dir), /No CSV found in .* pass --csv/);
  });
});
