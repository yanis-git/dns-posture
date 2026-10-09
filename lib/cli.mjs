// Argument parsing and the small file formats the CLI reads (CSV export from
// the OVH manager, batch list files). Kept out of the entrypoint so it can be
// unit-tested without spawning a process.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { domainName, validTtl } from './validation.mjs';
import { DEFAULT_CNAMES_TO_DROP } from './harden.mjs';

export function parseArgs(argv) {
  const opts = { _: [], keep: [], cnames: [...DEFAULT_CNAMES_TO_DROP], nullMx: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (['--provider', '--account', '--csv', '--list', '--rua', '--iodef', '--ttl', '--keep', '--drop-cname'].includes(a)
      && (!argv[i + 1] || argv[i + 1].startsWith('--'))) throw new Error(`Missing value for ${a}`);
    if (a === '--provider') opts.provider = argv[++i];
    else if (a === '--account') opts.account = argv[++i];
    else if (a === '--apply') opts.apply = true;
    else if (a === '--null-mx') opts.nullMx = true;
    else if (a === '--caa') opts.caa = true;
    // An iodef address on its own publishes nothing that closes the zone, so it
    // implies --caa rather than silently doing half the job.
    else if (a === '--iodef') { opts.iodef = argv[++i]; opts.caa = true; }
    else if (a === '--force') opts.force = true;
    else if (a === '--drop-redirect') opts.dropRedirect = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--csv') opts.csv = argv[++i];
    else if (a === '--list') opts.list = argv[++i];
    else if (a === '--rua') opts.rua = argv[++i];
    else if (a === '--ttl') opts.ttl = Number(argv[++i]);
    else if (a === '--keep') opts.keep.push(new RegExp(argv[++i], 'i'));
    else if (a === '--drop-cname') { opts.cnamesExplicit = true; opts.cnames.push(...argv[++i].split(',').map((s) => s.trim().toLowerCase())); }
    else if (a.startsWith('--')) throw new Error(`Unknown option: ${a}`);
    else opts._.push(a);
  }
  if (opts.provider && !['ovh', 'cloudflare'].includes(opts.provider)) throw new Error('Provider must be ovh or cloudflare');
  if (opts.account && !/^[a-zA-Z0-9_-]{1,100}$/.test(opts.account)) throw new Error('Invalid account identifier');
  if (opts.cnames.some((name) => !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/.test(name))) throw new Error('Invalid --drop-cname name');
  if (opts.ttl !== undefined) validTtl(opts.ttl);
  for (const key of ['rua', 'iodef']) {
    if (opts[key] && !/^mailto:[^\s;"<>@]+@[^\s;"<>@]+\.[^\s;"<>@]+$/.test(opts[key])) throw new Error(`Invalid --${key} mailto address`);
  }
  if (opts.list && opts.csv) throw new Error('Use either --list or --csv');
  if (opts.list && opts._.length) throw new Error('Use either --list or explicit domains');
  if (opts.csv && opts._.length) throw new Error('Use either --csv or explicit domains');
  return opts;
}

// One domain per run: we validate a single zone before iterating over a pool.
export function requireDomain(opts) {
  if (opts._.length !== 1) {
    throw new Error(`This command takes exactly ONE domain (got: ${opts._.length || 'none'}).`);
  }
  return domainName(opts._[0]);
}

/** Newest CSV in the storage directory, unless --csv points somewhere else. */
export function findCsv(opts, storage) {
  if (opts.csv) return opts.csv;
  const files = readdirSync(storage).filter((f) => f.endsWith('.csv')).sort();
  if (!files.length) throw new Error(`No CSV found in ${storage} — pass --csv <path>`);
  return join(storage, files[files.length - 1]);
}

/** Domain list from an OVH manager CSV export: first column, header row skipped. */
export function readCsvDomains(path) {
  const lines = readFileSync(path, 'utf8').replace(/^\uFEFF/, '').split('\n').slice(1);
  const out = [];
  for (const line of lines) {
    const first = line.split(',')[0]?.trim().replace(/^"|"$/g, '').toLowerCase();
    if (first) out.push(domainName(first));
  }
  return [...new Set(out)];
}

/** Batch file: one domain per line, # starts a comment. */
export function readListFile(path) {
  const lines = readFileSync(path, 'utf8').split('\n')
    .map((l) => l.replace(/#.*$/, '').trim().toLowerCase())
    .filter(Boolean);
  if (!lines.length) throw new Error(`Batch file ${path} contains no domain.`);
  return [...new Set(lines.map(domainName))];
}
