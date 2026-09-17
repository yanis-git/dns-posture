import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { AXIS_TITLES } from './baseline.mjs';

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

/**
 * Render the inventory.
 *
 * `scores` is an optional { domain: { score, grade } } map. Omitting it — which
 * is what `snapshot` and `inventory` do — produces byte-identical output to
 * before the compliance baseline existed. That matters: LINE_RE and
 * `tickDomain` both parse this exact line shape, and a hand-ticked box must
 * survive every regeneration.
 */
export function renderInventory(entries, ticks = {}, scores = {}) {
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
      const s = scores[e.domain];
      const score = s && typeof s.score === 'number' ? ` \`${s.grade} ${s.score}\`` : '';
      out.push(`- [${tick}] **${e.domain}**${score} — ${counts}${signals}${note ? ` <!-- ${note} -->` : ''}`);
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

// ---------------------------------------------------------------------------
// Compliance reporting
//
// The markdown is the thing a human reads, so it lists only what needs acting
// on: failures, plus the `na` results the baseline decided itself (never the
// mechanical out-of-scope ones). Passes are counted in the summary and spelled
// out in full in compliance.json and compliance.csv — at sixty domains and
// twenty-three controls, a complete dump is unreadable and nobody reads it.
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/** Markdown table cells must not be split by a value containing a pipe. */
const cell = (value) => String(value ?? '').replace(/\|/g, '\\|');

/** Worst first, then alphabetically. Domains with no backup sort last. */
function bySeverityOfResult(a, b) {
  if (typeof a.score !== typeof b.score) return typeof a.score === 'number' ? -1 : 1;
  if (typeof a.score === 'number' && a.score !== b.score) return a.score - b.score;
  return String(a.domain).localeCompare(String(b.domain));
}

export function renderCompliance(portfolio) {
  const { generatedAt, baselineVersion, portfolio: agg, domains } = portfolio;
  const day = String(generatedAt ?? '').slice(0, 10);
  const ranked = [...domains].sort(bySeverityOfResult);
  const scored = ranked.filter((d) => typeof d.score === 'number');
  const broken = ranked.filter((d) => typeof d.score !== 'number');

  const out = [
    '# DNS compliance baseline — anti-spoofing, closed by default, attack surface',
    '',
    `Generated on ${day} · ${agg.domains} domains · baseline v${baselineVersion}`
    + ' · regenerate with `node ovh.mjs compliance`',
    '',
    agg.score === null
      ? '**No domain could be scored.** Run `node ovh.mjs snapshot` first.'
      : `**Portfolio ${agg.score}/100 (${agg.grade})** — anti-spoofing ${agg.axes.spoofing ?? '—'}`
        + ` · closed by default ${agg.axes.closed ?? '—'} · attack surface ${agg.axes.surface ?? '—'}`,
    '',
    'Scores are computed offline from the zone backups in `storage/backups/`. A control that does not',
    'apply to a domain\'s state counts neither for nor against it — see `docs/BASELINE.md`.',
    '',
    '| Domain | State | Score | Grade | Spoof | Closed | Surface | Failing |',
    '|---|---|---:|---|---:|---:|---:|---|',
  ];

  for (const d of ranked) {
    if (typeof d.score !== 'number') {
      out.push(`| ${cell(d.domain)} | error | — | — | — | — | — | ${cell(d.error ?? 'not scored')} |`);
      continue;
    }
    const failing = d.controls.filter((c) => c.status === 'fail').map((c) => c.id);
    const shown = failing.slice(0, 3).join(', ') + (failing.length > 3 ? `, +${failing.length - 3}` : '');
    const axis = (a) => d.axes[a]?.score ?? '—';
    out.push(`| ${cell(d.domain)} | ${d.state} | ${d.score} | ${d.grade} | ${axis('spoofing')}`
      + ` | ${axis('closed')} | ${axis('surface')} | ${cell(shown || '—')} |`);
  }
  out.push('');

  if (agg.topFailures.length) {
    out.push('## Most frequent failures', '',
      '| Control | Severity | Axis | Domains | Reference |',
      '|---|---|---|---:|---|');
    for (const f of agg.topFailures) {
      out.push(`| \`${cell(f.id)}\` | ${f.severity} | ${cell(AXIS_TITLES[f.axis] ?? f.axis)} | ${f.count}`
        + ` | ${cell(f.refs.join(' · '))} |`);
    }
    out.push('');
  }

  out.push('## Findings by domain', '');
  for (const d of scored) {
    const findings = d.controls
      .filter((c) => c.status === 'fail' || c.naReason === 'check')
      .sort((a, b) => (a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1)
        || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    if (!findings.length) continue;

    out.push(`### ${d.domain} — ${d.score}/100 (${d.grade})`, '');
    out.push(`${d.state} · ${d.tally.pass} pass · ${d.tally.fail} fail · ${d.tally.na} n/a`
      + (d.source ? ` · source \`${d.source}\`` : ''), '');
    for (const c of findings) {
      if (c.status === 'na') {
        out.push(`- \`n/a\` \`${c.id}\` — ${c.detail}`);
        continue;
      }
      const mark = c.severity === 'critical' ? '!! ' : '';
      out.push(`- **${mark}\`${c.id}\` (${c.severity})** — ${c.detail}`);
      out.push(`  refs: ${c.refs.join(' · ')}`);
      if (c.remediation?.text) {
        out.push(`  fix: ${c.remediation.text}${c.remediation.command ? ` \`${c.remediation.command}\`` : ''}`);
      }
    }
    out.push('');
  }

  if (broken.length) {
    out.push('## Not scored', '',
      'These domains have no usable backup. They are excluded from every average — not scored zero.', '');
    for (const d of broken) out.push(`- **${d.domain}** — ${d.error ?? 'no backup'}`);
    out.push('');
  }

  return out.join('\n');
}

const CSV_HEADER = [
  'domain', 'state', 'score', 'grade', 'control', 'title',
  'axis', 'severity', 'scope', 'status', 'detail', 'refs', 'remediation',
];

/** RFC 4180 quoting: only when needed, doubling any embedded quote. */
function csvCell(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * One row per (domain, control) — the deliverable an auditor filters in a
 * spreadsheet. Unlike the markdown this holds every result, passes included:
 * evidence of what was checked and passed is the point of an audit trail.
 */
export function renderComplianceCsv(portfolio) {
  const rows = [CSV_HEADER.join(',')];
  for (const d of [...portfolio.domains].sort(bySeverityOfResult)) {
    if (!d.controls?.length) {
      rows.push([d.domain, 'error', '', '', '', '', '', '', '', 'error', d.error ?? 'no backup', '', '']
        .map(csvCell).join(','));
      continue;
    }
    for (const c of d.controls) {
      rows.push([
        d.domain, d.state, d.score ?? '', d.grade ?? '', c.id, c.title,
        c.axis, c.severity, c.scope, c.status, c.detail, c.refs.join(' | '),
        c.remediation ? [c.remediation.text, c.remediation.command].filter(Boolean).join(' ') : '',
      ].map(csvCell).join(','));
    }
  }
  return rows.join('\n') + '\n';
}
