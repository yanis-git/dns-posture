import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

export const STATE_ORDER = ['dormant', 'web-active', 'mail-active', 'error'];

const STATE_TITLES = {
  dormant: 'Dormant — candidates for hardening',
  'web-active': 'Web active — mail probably unused, to be confirmed',
  'mail-active': 'Mail active — DO NOT harden without checking',
  error: 'Unreachable',
};

const LINE_RE = /^- \[( |x)\] \*\*([^*]+)\*\*/;

/** Re-read the existing inventory so hand-ticked boxes are not lost. */
export function readTicks(path) {
  const ticks = {};
  if (!existsSync(path)) return ticks;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = line.match(LINE_RE);
    if (m) ticks[m[2]] = { checked: m[1] === 'x', note: (line.match(/<!-- (.+?) -->/) || [])[1] || null };
  }
  return ticks;
}

export function renderInventory(entries, ticks = {}) {
  const now = new Date().toISOString().slice(0, 10);
  const out = [
    '# DNS inventory — anti-spoofing hardening',
    '',
    `Generated on ${now} · ${entries.length} domains · regenerate with \`node ovh.mjs inventory\``,
    '',
    'Tick the box once the domain is cleaned. `harden --apply` ticks it automatically.',
    'Ticked boxes are preserved across regenerations.',
    '',
  ];

  for (const state of STATE_ORDER) {
    const group = entries.filter((e) => e.state === state);
    if (!group.length) continue;
    const done = group.filter((e) => ticks[e.domain]?.checked).length;
    out.push(`## ${STATE_TITLES[state]} (${done}/${group.length})`, '');

    for (const e of group.sort((a, b) => a.domain.localeCompare(b.domain))) {
      const tick = ticks[e.domain]?.checked ? 'x' : ' ';
      const note = ticks[e.domain]?.note;
      const counts = e.counts
        ? `${e.counts.total} records (${e.counts.mx} MX, ${e.counts.txt} TXT, ${e.counts.cname} CNAME)`
        : '—';
      const signals = e.signals?.length ? ` · ${e.signals.join(' · ')}` : '';
      out.push(`- [${tick}] **${e.domain}** — ${counts}${signals}${note ? ` <!-- ${note} -->` : ''}`);
    }
    out.push('');
  }

  out.push('---', '', '| State | Domains | Cleaned |', '|---|---|---|');
  for (const state of STATE_ORDER) {
    const group = entries.filter((e) => e.state === state);
    if (!group.length) continue;
    out.push(`| ${state} | ${group.length} | ${group.filter((e) => ticks[e.domain]?.checked).length} |`);
  }
  out.push('');
  return out.join('\n');
}

/** Tick a domain in the inventory, in place. */
export function tickDomain(path, domain, note) {
  if (!existsSync(path)) return false;
  const lines = readFileSync(path, 'utf8').split('\n');
  let found = false;
  const next = lines.map((line) => {
    const m = line.match(LINE_RE);
    if (!m || m[2] !== domain) return line;
    found = true;
    return line.replace('- [ ]', '- [x]').replace(/ <!-- .+? -->$/, '') + (note ? ` <!-- ${note} -->` : '');
  });
  if (found) writeFileSync(path, next.join('\n'));
  return found;
}

export function backupDir(backups, domain) {
  const dir = join(backups, domain);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function latestBackup(backups, domain) {
  const dir = join(backups, domain);
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir).filter((f) => f.endsWith('.zone')).sort();
  return files.length ? join(dir, files[files.length - 1]) : null;
}

export function saveBackup(backups, domain, zoneText) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const path = join(backupDir(backups, domain), `${stamp}.zone`);
  writeFileSync(path, zoneText);
  return path;
}
