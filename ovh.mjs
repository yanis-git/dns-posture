#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join, relative } from 'node:path';
import { OvhClient } from './lib/ovh-client.mjs';
import { buildPolicy, fetchRecords, planZone, applyPlan, recordLabel, TEXTUAL_TYPES } from './lib/harden.mjs';
import { parseZone, classify } from './lib/inventory.mjs';
import {
  renderInventory, readTicks, tickDomain, saveBackup, latestBackup,
  renderCompliance, renderComplianceCsv,
} from './lib/report.mjs';
import { evaluate, aggregate, caaBlocker, BASELINE_VERSION, SEVERITY_WEIGHT } from './lib/baseline.mjs';
import { loadPolicy, resolvePolicy, planFromFindings } from './lib/policy.mjs';
import { toApiShape } from './lib/zone.mjs';
import { parseArgs, requireDomain, findCsv, readCsvDomains, readListFile } from './lib/cli.mjs';
import { loadEnv, ensureStorage, requireCredentials, policyFile } from './lib/config.mjs';

export const VERSION = '0.2.0';

const ACCESS_RULES = [
  { method: 'GET', path: '/me' },
  { method: 'GET', path: '/domain/*' },
  { method: 'POST', path: '/domain/zone/*' },
  { method: 'PUT', path: '/domain/zone/*' },
  { method: 'DELETE', path: '/domain/zone/*' },
];

function client() {
  requireCredentials();
  return new OvhClient({
    endpoint: process.env.OVH_ENDPOINT || 'ovh-eu',
    appKey: process.env.APP_KEY,
    appSecret: process.env.APP_SECRET,
    consumerKey: process.env.OVH_CONSUMER_KEY,
  });
}

async function cmdAuth() {
  const ovh = client();
  const res = await ovh.requestCredentials(ACCESS_RULES, 'https://www.ovh.com/manager/');
  console.log(`\n1. Open and validate this URL:\n\n   ${res.validationUrl}\n`);
  console.log(`2. Then add this to .env:\n\n   OVH_CONSUMER_KEY=${res.consumerKey}\n`);
}

async function cmdWhoami() {
  const ovh = client();
  await ovh.syncTime();
  const me = await ovh.get('/me');
  console.log(`Connected as: ${me.nichandle} (${me.email})`);
}

/** Back up the zone and return { zoneText, backupPath, records, ...classification }. */
async function snapshotDomain(ovh, domain, p) {
  const zoneText = await ovh.get(`/domain/zone/${encodeURIComponent(domain)}/export`);
  const backupPath = saveBackup(p.backups, domain, zoneText);
  const records = parseZone(zoneText);
  return { domain, zoneText, backupPath, records, ...classify(records, { domain }) };
}

function writeInventory(entries, p) {
  writeFileSync(p.inventoryJson, JSON.stringify(entries, null, 2));
  writeFileSync(p.inventoryMd, renderInventory(entries, readTicks(p.inventoryMd)));
}

async function cmdSnapshot(opts, p) {
  const domains = opts._.length ? opts._.map((d) => d.toLowerCase()) : readCsvDomains(findCsv(opts, p.storage));
  const ovh = client();
  await ovh.syncTime();

  console.log(`Snapshotting ${domains.length} domain(s) — read only\n`);
  const entries = [];

  for (const [i, domain] of domains.entries()) {
    const prefix = `[${String(i + 1).padStart(3)}/${domains.length}] ${domain.padEnd(34)}`;
    try {
      const snap = await snapshotDomain(ovh, domain, p);
      entries.push({ domain, state: snap.state, signals: snap.signals, counts: snap.counts });
      console.log(`${prefix} ${snap.state.padEnd(11)} ${snap.counts.total} records`);
    } catch (err) {
      const reason = err.status === 404 ? 'zone not hosted at OVH' : err.message;
      entries.push({ domain, state: 'error', signals: [reason], counts: null });
      console.log(`${prefix} !! ${reason}`);
    }
  }

  writeInventory(entries, p);
  console.log(`\nBackups   : ${p.backups}/<domain>/<timestamp>.zone`);
  console.log(`Inventory : ${p.inventoryMd}`);
}

/** Rebuild the inventory by reclassifying the on-disk backups. No network. */
function cmdInventory(opts, p) {
  const domains = opts._.length ? opts._.map((d) => d.toLowerCase()) : readCsvDomains(findCsv(opts, p.storage));
  const entries = domains.map((domain) => {
    const file = latestBackup(p.backups, domain);
    if (!file) return { domain, state: 'error', signals: ['no backup — run `snapshot`'], counts: null };
    const records = parseZone(readFileSync(file, 'utf8'));
    return { domain, ...classify(records, { domain }) };
  });
  writeInventory(entries, p);
  console.log(`Inventory rebuilt from backups (${entries.length} domains, ticks preserved): ${p.inventoryMd}`);
}

/**
 * Score the whole portfolio against the control baseline, offline.
 *
 * Mirrors `cmdInventory`: it re-reads the on-disk backups, so it needs neither
 * credentials nor network, and it never writes to the inventory — a compliance
 * run must not be able to disturb the hand-ticked worklist.
 */
function cmdCompliance(opts, p) {
  const domains = opts._.length ? opts._.map((d) => d.toLowerCase()) : readCsvDomains(findCsv(opts, p.storage));

  console.log(`Compliance baseline v${BASELINE_VERSION} — ${domains.length} domain(s) from backups, offline\n`);

  const reports = domains.map((domain, i) => {
    const prefix = `[${String(i + 1).padStart(3)}/${domains.length}] ${domain.padEnd(34)}`;
    const file = latestBackup(p.backups, domain);
    if (!file) {
      console.log(`${prefix} !! no backup — run \`snapshot\``);
      return { domain, state: 'error', score: null, grade: null, controls: [], error: 'no backup — run `snapshot`' };
    }
    const records = parseZone(readFileSync(file, 'utf8'));
    const report = { ...evaluate(records, { domain }), source: relative(p.storage, file) };
    const critical = report.controls.filter((c) => c.status === 'fail' && c.severity === 'critical').length;
    const tail = critical
      ? `!! ${critical} critical failure(s)`
      : `spoof ${String(report.axes.spoofing.score ?? '—').padStart(3)}`
        + `  closed ${String(report.axes.closed.score ?? '—').padStart(3)}`
        + `  surface ${String(report.axes.surface.score ?? '—').padStart(3)}`;
    console.log(`${prefix} ${report.grade}${String(report.score).padStart(4)}   ${tail}`);
    return report;
  });

  const portfolio = aggregate(reports);
  const audit = {
    generatedAt: new Date().toISOString(),
    baselineVersion: BASELINE_VERSION,
    weights: SEVERITY_WEIGHT,
    portfolio,
    domains: reports,
  };

  writeFileSync(p.complianceJson, JSON.stringify(audit, null, 2));
  writeFileSync(p.complianceMd, renderCompliance(audit));
  writeFileSync(p.complianceCsv, renderComplianceCsv(audit));

  const grades = Object.entries(portfolio.byGrade).sort(([a], [b]) => a.localeCompare(b))
    .map(([g, n]) => `${g}:${n}`).join(' ');
  console.log(`\n== portfolio ${portfolio.score ?? '—'}/100 (${portfolio.grade ?? '—'}) · ${grades}`
    + (portfolio.errors ? ` · ${portfolio.errors} without backup` : ''));
  console.log(`   anti-spoofing ${portfolio.axes.spoofing ?? '—'} · closed by default ${portfolio.axes.closed ?? '—'}`
    + ` · attack surface ${portfolio.axes.surface ?? '—'}`);
  if (portfolio.topFailures.length) {
    console.log(`   top failure: ${portfolio.topFailures.slice(0, 3).map((f) => `${f.id} (${f.count})`).join(' · ')}`);
  }
  console.log(`\nReport: ${p.complianceMd}\n        ${p.complianceJson}\n        ${p.complianceCsv}`);
}

// ---------------------------------------------------------------------------
// policy — the effective configuration, offline
// ---------------------------------------------------------------------------

/** What each remedy action does, printed once as a legend. */
const ACTION_LEGEND = [
  'add      publish the record, only if nothing competes with it',
  'enforce  publish the record and delete what it replaces',
  'remove   delete, and publish nothing in its place',
  'manual   remediation text only, nothing is ever written',
  'report   scored, no remedy',
  'off      not evaluated, with the reason shown',
];

/** Display form of a path: relative to the working directory when it is inside it. */
function shortPath(file) {
  const rel = relative(process.cwd(), file);
  return rel.startsWith('..') ? file : rel;
}

/** Pad to a column, but never let a long value run into the next one. */
const col = (text, width) => (text.length < width ? text.padEnd(width) : `${text}  `);

const cell = (entry) => `${entry.remedy.action}${entry.remedy.record ? ` ${entry.remedy.record}` : ''}`;

/** `policy` with no domain: the file as loaded, plus the validation verdict. */
function printCatalogue(policy, file) {
  const d = policy.defaults;
  const profiles = Object.keys(policy.profiles);
  const checks = Object.entries(policy.checks);

  console.log(`Policy — ${shortPath(file)} (schema v${policy.version}) — valid\n`);
  console.log('Defaults');
  console.log(`   ttl           : ${d.ttl}`);
  console.log(`   keep          : ${d.keep.map(String).join(' · ') || '(none)'}`);
  console.log(`   drop CNAMEs   : ${d.dropCnames.join(', ') || '(none)'}`);
  console.log(`   drop redirect : ${d.dropRedirect ? 'yes' : 'no'}`);

  const templates = Object.entries(policy.records);
  console.log(`\nRecord templates (${templates.length})`);
  const idW = Math.max(...templates.map(([id]) => id.length)) + 2;
  const labelW = Math.max(...templates.map(([, t]) => recordLabel(t).length)) + 2;
  for (const [id, t] of templates) {
    console.log(`   ${id.padEnd(idW)}${recordLabel(t).padEnd(labelW)}displaces ${t.displaces}`
      + (t.exclusive ? ' · exclusive' : ''));
  }

  console.log(`\nRemedy per check (${checks.length} checks × ${profiles.length} profiles)`);
  const nameW = Math.max(...checks.map(([id]) => id.length)) + 2;
  const cellW = Math.max(
    ...profiles.map((n) => n.length),
    ...checks.flatMap(([id]) => profiles.map((n) => cell(policy.profiles[n].checks[id]).length)),
  ) + 2;
  console.log(`   ${'check'.padEnd(nameW)}${profiles.map((n) => n.padEnd(cellW)).join('').trimEnd()}`);
  for (const [id] of checks) {
    const cells = profiles.map((n) => cell(policy.profiles[n].checks[id]).padEnd(cellW));
    console.log(`   ${id.padEnd(nameW)}${cells.join('').trimEnd()}`);
  }
  console.log(`\n   ${ACTION_LEGEND.join('\n   ')}`);

  const overrides = Object.entries(policy.domains ?? {});
  console.log(`\nDomain overrides (${overrides.length})`);
  for (const [domain, o] of overrides) {
    console.log(`   ${domain} -> profile ${o.profile ?? '(from state)'} · ${o.reason}`);
    for (const [id, entry] of Object.entries(o.checks ?? {})) console.log(`      ${id}: ${cell(entry)}`);
  }
  if (!overrides.length) console.log('   none — every domain follows the profile of its classified state');

  console.log('\nRun `node ovh.mjs policy <domain>` for the effective policy on one zone.');
}

/**
 * Records a failing check wanted to remove, that a `keep` pattern protected.
 *
 * Invariant #7 makes `keep` win over every licence, which is the right default
 * and a silent one: the operator asked for a hardened zone and got a record
 * left standing. Saying so is the difference between a protection and an
 * oversight. Generalises the CAA-union warning `printPlan` has always carried.
 */
function protectedFromLicences(plan, licences) {
  const out = [];
  for (const rec of plan.keep) {
    if (!String(rec.reason).startsWith('protected by')) continue;
    const licence = licences.find((l) => l.displaces(rec));
    if (licence) out.push({ rec, licence });
  }
  return out;
}

function printProtections(protections) {
  if (!protections.length) return;
  console.log(`\n   !! ${protections.length} record(s) a failing check wanted to remove are protected by \`keep\``);
  for (const { rec, licence } of protections) {
    // RFC 8659 §4.2: the `issue` properties form a union, so a permissive CAA
    // kept here still authorises its CA, deny pair or not.
    const note = rec.fieldType === 'CAA'
      ? 'RFC 8659 §4.2: issue is a union, so this CA is still authorised'
      : 'the record stays in effect';
    console.log(`      ${col(recordLabel(rec), 46)}wanted by ${licence.checkId} — ${note}`);
  }
}

/**
 * `policy <domain>`: the resolved policy and a full preview of what `harden`
 * would do, read from the latest backup.
 *
 * Offline and credential-free, which is the point: a whole batch is reviewable
 * — every publication and every deletion, each naming the check that licensed
 * it — without an API call, and long before anything is written.
 */
function printResolved(domain, opts, p, policy) {
  const file = latestBackup(p.backups, domain);
  if (!file) throw new Error(`No backup for ${domain} — run \`node ovh.mjs snapshot ${domain}\` first.`);

  const view = parseZone(readFileSync(file, 'utf8'));
  const cls = classify(view, { domain });
  // The backup read through the write path's eyes, restricted to the types
  // `fetchRecords` actually retrieves — otherwise the preview reports on NS and
  // SOA records `harden` never sees, and stops matching what it would do. No
  // record ids either: this plan is for reading, `applyPlan` could not run it.
  const fetched = [...TEXTUAL_TYPES, 'MX', 'CNAME', 'CAA'];
  const records = view.filter((r) => fetched.includes(r.type)).map(toApiShape);

  const report = evaluate(view, { domain, state: cls.state });
  const resolved = resolvePolicy(view, { domain, state: cls.state, policy });
  const { wanted, licences, conflicts } = planFromFindings(report, resolved, records);
  const plan = planZone(records, {
    wanted,
    licences,
    keepPatterns: resolved.keep,
    dropCnames: resolved.dropCnames,
    dropRedirect: resolved.dropRedirect,
  });
  const protections = protectedFromLicences(plan, licences);

  if (opts.json) {
    console.log(JSON.stringify({
      domain,
      policyFile: shortPath(policyFile()),
      schemaVersion: policy.version,
      state: cls.state,
      signals: cls.signals,
      profile: resolved.profile,
      overrideReason: resolved.overrideReason,
      caaBlocked: resolved.caaBlocked,
      source: relative(p.storage, file),
      keep: resolved.keep.map(String),
      ttl: resolved.ttl,
      dropCnames: resolved.dropCnames,
      dropRedirect: resolved.dropRedirect,
      checks: report.controls.map((c) => {
        const entry = resolved.checks[c.id];
        return {
          id: c.id,
          severity: c.severity,
          axis: c.axis,
          status: c.status,
          naReason: c.naReason,
          action: entry.remedy.action,
          record: entry.remedy.record ?? null,
          reason: entry.reason,
          source: entry.source,
          demotedFrom: entry.demotedFrom,
          demotionReason: entry.demotionReason,
        };
      }),
      conflicts,
      plan: {
        create: plan.create.map((r) => ({ label: recordLabel(r), record: r.record, wantedBy: r.wantedBy, why: r.why })),
        delete: plan.delete.map((r) => ({ label: r.label, checkId: r.checkId ?? null, action: r.action ?? null, reason: r.reason })),
        keep: plan.keep.map((r) => ({ label: recordLabel(r), reason: r.reason })),
      },
      protectedFromLicences: protections.map(({ rec, licence }) => ({ label: recordLabel(rec), checkId: licence.checkId })),
    }, null, 2));
    return;
  }

  console.log(`Policy for ${domain} — ${shortPath(policyFile())} (schema v${policy.version})`);
  console.log(`   state    : ${cls.state}${cls.signals.length ? `   (${cls.signals.join(' · ')})` : ''}`);
  console.log(`   backup   : ${relative(p.storage, file)}`);
  console.log(`   profile  : ${resolved.profile}`
    + (resolved.overrideReason ? `   (override: ${resolved.overrideReason})` : ''));
  console.log(`   keep     : ${resolved.keep.map(String).join(' · ') || '(none)'}`);
  console.log(`   ttl      : ${resolved.ttl}`);
  if (resolved.caaBlocked) console.log(`   caa      : no issuance deny here — ${resolved.caaBlocked}`);

  const controls = report.controls;
  console.log(`\nChecks (${controls.length})`);
  const nameW = Math.max(...controls.map((c) => c.id.length)) + 2;
  for (const c of controls) {
    const entry = resolved.checks[c.id];
    const status = c.status === 'na' ? 'n/a' : c.status;
    const template = entry.template;
    let tail = '';
    if (entry.demotedFrom) tail = `!! demoted from ${entry.demotedFrom} — ${entry.demotionReason}`;
    else if (entry.remedy.action === 'off') tail = entry.reason ?? 'not evaluated';
    else if (entry.remedy.action === 'remove') tail = `deletes ${template.displaces}, publishes nothing`;
    else if (template) tail = `-> ${recordLabel(template)}`;
    else if (entry.reason) tail = entry.reason;
    console.log((`   ${col(c.id, nameW)}${col(c.severity, 10)}${col(c.axis, 10)}`
      + `${col(status, 6)}${col(entry.remedy.action, 9)}${tail}`).trimEnd());
  }

  const w = 46;
  console.log(`\nWould publish (${plan.create.length})`);
  for (const rec of plan.create) console.log(`   + ${col(recordLabel(rec), w)}${(rec.wantedBy ?? []).join(', ')}`);
  if (!plan.create.length) console.log('   nothing');

  console.log(`\nWould delete (${plan.delete.length})   every deletion is licensed by a failing check`);
  for (const rec of plan.delete) console.log(`   - ${col(rec.label, w)}${rec.reason}`);
  if (!plan.delete.length) console.log('   nothing');

  console.log(`\nWould keep (${plan.keep.length})`);
  for (const rec of plan.keep) console.log(`   . ${col(recordLabel(rec), w)}${rec.reason}`);
  if (!plan.keep.length) console.log('   nothing');

  for (const c of conflicts) {
    console.log(`\n   !! ${c.checkId}: ${c.record} not published — ${c.wanted} would compete with `
      + `${c.competing.join(', ')}`);
  }
  printProtections(protections);
  console.log('\nRead only: this command never contacts OVH. `harden <domain>` plans against the live zone.');
}

/** Show the effective policy — the whole file, or one domain's resolution. */
function cmdPolicy(opts, p, policy) {
  if (opts._.length > 1) throw new Error(`policy takes at most ONE domain (got ${opts._.length}).`);
  if (!opts._.length) {
    if (opts.json) { console.log(JSON.stringify(policy, (k, v) => (v instanceof RegExp ? String(v) : v), 2)); return; }
    printCatalogue(policy, policyFile());
    return;
  }
  printResolved(opts._[0].toLowerCase().trim(), opts, p, policy);
}

/**
 * Resolve --caa against the zone itself.
 *
 * A CAA at the apex is inherited by every subdomain (RFC 8659 §3), so a deny on
 * a zone that still serves web content breaks the next certificate renewal —
 * sixty to ninety days later, long after anyone connects the two. The flag asks;
 * the zone decides. One predicate, shared with the compliance baseline, so the
 * audit and the write path can never disagree about what is safe.
 */
function resolveCaa(opts, snap, log) {
  if (!opts.caa) return false;
  const blocked = caaBlocker(snap.records, snap);
  if (blocked) {
    log(`   caa    : skipped — ${blocked}`);
    return false;
  }
  return true;
}

function printPlan(zone, plan) {
  console.log(`\n== ${zone}`);
  for (const rec of plan.delete) console.log(`   - DELETE  ${rec.label}  -> ${rec.reason}`);
  for (const rec of plan.create) console.log(`   + CREATE  ${recordLabel(rec)}  -> ${rec.why}`);
  for (const rec of plan.keep.filter((k) => k.reason === 'already compliant')) {
    console.log(`   = OK      ${recordLabel(rec)}`);
  }
  for (const rec of plan.keep.filter((k) => k.reason !== 'already compliant')) {
    console.log(`   . KEEP    ${recordLabel(rec)}  -> ${rec.reason}`);
  }
  if (!plan.delete.length && !plan.create.length) console.log('   OK zone already compliant, nothing to do');

  // RFC 8659 §4.2: the `issue` properties form a union. A permissive record
  // kept by --keep therefore still authorises its CA, deny pair or not.
  const keptPermissive = plan.keep.some((r) => r.fieldType === 'CAA'
    && /^"?\s*\d+\s+issuewild?\s+"?\s*[^";\s]/i.test(String(r.target ?? '')));
  if (keptPermissive && plan.create.some((r) => r.fieldType === 'CAA')) {
    console.log('   !! a permissive CAA is kept alongside the deny — issuance is still allowed');
  }
}

async function cmdHarden(opts, p) {
  const zone = requireDomain(opts);
  const ovh = client();
  await ovh.syncTime();

  let snap;
  try {
    snap = await snapshotDomain(ovh, zone, p);
  } catch (err) {
    throw new Error(err.status === 404
      ? `Zone "${zone}" not found at OVH (DNS delegated elsewhere?)`
      : err.message, { cause: err });
  }

  console.log(opts.apply ? `APPLYING to ${zone}` : `DRY-RUN on ${zone} — add --apply to execute`);
  console.log(`   state  : ${snap.state}${snap.signals.length ? ` (${snap.signals.join(' · ')})` : ''}`);
  console.log(`   backup : ${snap.backupPath}`);

  // Guard rail: we do not harden a zone that is still in use, without --force.
  if (snap.state === 'mail-active' && !opts.force) {
    throw new Error(`"${zone}" has active mail (${snap.signals.join(' · ')}).\n`
      + '   Hardening would break both delivery AND sending. Re-run with --force if that is intended.');
  }

  const policy = buildPolicy({
    rua: opts.rua,
    nullMx: opts.nullMx,
    caa: resolveCaa(opts, snap, console.log),
    iodef: opts.iodef,
    ttl: opts.ttl || 3600,
  });
  const records = await fetchRecords(ovh, zone);
  const plan = planZone(records, { policy, keepPatterns: opts.keep, cnamesToDrop: opts.cnames, dropRedirect: opts.dropRedirect });
  printPlan(zone, plan);

  const result = { zone, mode: opts.apply ? 'apply' : 'plan', at: new Date().toISOString(), state: snap.state, backup: snap.backupPath, plan };

  if (opts.apply) {
    result.applied = await applyPlan(ovh, zone, plan);
    console.log(`\n   -> ${result.applied.deleted.length} deletion(s), ${result.applied.created.length} creation(s), zone refreshed`);
    for (const e of result.applied.errors) console.log(`   ERROR ${e}`);

    const note = `cleaned ${new Date().toISOString().slice(0, 10)}${result.applied.errors.length ? ` · ${result.applied.errors.length} error(s)` : ''}`;
    if (tickDomain(p.inventoryMd, zone, note)) console.log(`   ticked in ${p.inventoryMd}`);
  }

  mkdirSync(p.reports, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const path = join(p.reports, `${zone}-${opts.apply ? 'apply' : 'plan'}-${stamp}.json`);
  writeFileSync(path, JSON.stringify(result, null, 2));
  console.log(`\nReport: ${path}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function writeBatchReport(rows, mode, opts, p) {
  mkdirSync(p.reports, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const base = join(p.reports, `batch-${mode}-${stamp}`);

  const tally = {};
  for (const r of rows) tally[r.status] = (tally[r.status] || 0) + 1;
  const totalDel = rows.reduce((n, r) => n + (r.deletes || 0), 0);
  const totalNew = rows.reduce((n, r) => n + (r.creates || 0), 0);
  const summary = Object.entries(tally).map(([k, v]) => `${k}: ${v}`).join(' · ');

  writeFileSync(`${base}.json`, JSON.stringify({
    mode,
    at: new Date().toISOString(),
    options: {
      dropRedirect: !!opts.dropRedirect,
      nullMx: !!opts.nullMx,
      caa: !!opts.caa,
      iodef: opts.iodef || null,
      ttl: opts.ttl || 3600,
      rua: opts.rua || null,
      keep: opts.keep.map((re) => re.source),
      cnamesToDrop: opts.cnames,
    },
    tally,
    totals: { deletes: totalDel, creates: totalNew },
    rows,
  }, null, 2));

  const cell = (r) => (r.reason || (r.errors || []).join(' ; ') || '').replace(/\|/g, '\\|').slice(0, 140);
  writeFileSync(`${base}.md`, [
    `# Batch hardening — ${mode === 'apply' ? 'apply' : 'dry-run'}`,
    '',
    `${new Date().toISOString().slice(0, 16).replace('T', ' ')} · ${rows.length} domains · ${totalDel} deletion(s), ${totalNew} creation(s)`,
    '',
    summary,
    '',
    '| Domain | State | Deleted | Created | Status | Detail |',
    '|---|---|---:|---:|---|---|',
    ...rows.map((r) => `| ${r.domain} | ${r.state || '—'} | ${r.deletes ?? '—'} | ${r.creates ?? '—'} | ${r.status} | ${cell(r)} |`),
    '',
  ].join('\n'));

  console.log(`\n== ${rows.length} domains · ${totalDel} deletion(s), ${totalNew} creation(s)`);
  console.log(`   ${summary}`);
  console.log(`\nReport: ${base}.md`);
  console.log(`        ${base}.json`);
}

/**
 * Roll the policy out over a batch of domains. Reuses the single-domain
 * machinery: one failing zone does not stop the batch, and --force is refused.
 */
async function cmdHardenBatch(opts, p) {
  if (opts.force) {
    throw new Error('--force is refused in batch mode.\n'
      + '   A domain with active mail is handled one at a time: `node ovh.mjs harden <domain> --force`.');
  }
  const domains = opts.list ? readListFile(opts.list) : opts._.map((d) => d.toLowerCase().trim());
  if (!domains.length) throw new Error('No domain: pass --list <file> or domains as arguments.');

  const ovh = client();
  await ovh.syncTime();

  const mode = opts.apply ? 'apply' : 'plan';
  console.log(opts.apply
    ? `APPLYING in batch — ${domains.length} domain(s)\n`
    : `DRY-RUN in batch — ${domains.length} domain(s), add --apply to execute\n`);

  const rows = [];

  for (const [i, domain] of domains.entries()) {
    const prefix = `[${String(i + 1).padStart(2)}/${domains.length}] ${domain.padEnd(36)}`;
    if (i) await sleep(300); // the OVH API client has neither retry nor backoff

    let snap;
    try {
      snap = await snapshotDomain(ovh, domain, p);
    } catch (err) {
      const reason = err.status === 404 ? 'zone not hosted at OVH' : err.message;
      rows.push({ domain, status: 'error', reason });
      console.log(`${prefix} !! skipped — ${reason}`);
      continue;
    }

    if (snap.state === 'mail-active') {
      rows.push({ domain, status: 'skipped', state: snap.state, backup: snap.backupPath, reason: `active mail — ${snap.signals.join(' · ')}` });
      console.log(`${prefix} >> skipped — active mail`);
      continue;
    }

    try {
      // Built per domain: --caa is resolved against each zone, so one zone
      // serving web content cannot disable the deny for the whole batch, and
      // cannot have it forced on either.
      const caa = resolveCaa(opts, snap, (line) => console.log(`${' '.repeat(14)}${line.trim()}`));
      const policy = buildPolicy({
        rua: opts.rua, nullMx: opts.nullMx, caa, iodef: opts.iodef, ttl: opts.ttl || 3600,
      });
      const records = await fetchRecords(ovh, domain);
      const plan = planZone(records, {
        policy, keepPatterns: opts.keep, cnamesToDrop: opts.cnames, dropRedirect: opts.dropRedirect,
      });
      const row = {
        domain, status: mode, state: snap.state, backup: snap.backupPath,
        deletes: plan.delete.length, creates: plan.create.length, plan,
      };

      if (opts.apply) {
        const applied = await applyPlan(ovh, domain, plan);
        row.applied = applied;
        row.errors = applied.errors;
        row.status = applied.errors.length ? 'partial' : 'ok';
        if (!applied.errors.length) {
          row.ticked = tickDomain(p.inventoryMd, domain, `cleaned ${new Date().toISOString().slice(0, 10)}`);
        }
      }
      rows.push(row);

      const verdict = plan.delete.length || plan.create.length
        ? `-${plan.delete.length} +${plan.create.length}`
        : 'already compliant';
      console.log(`${prefix} ${snap.state.padEnd(11)} ${verdict}`);
      for (const e of row.errors || []) console.log(`${' '.repeat(14)}ERROR ${e}`);
    } catch (err) {
      rows.push({ domain, status: 'error', state: snap.state, backup: snap.backupPath, reason: err.message });
      console.log(`${prefix} ERROR ${err.message}`);
    }
  }

  writeBatchReport(rows, mode, opts, p);
}

async function cmdAudit(opts) {
  const zone = requireDomain(opts);
  const ovh = client();
  await ovh.syncTime();
  console.log(await ovh.get(`/domain/zone/${encodeURIComponent(zone)}/export`));
}

async function cmdRestore(opts, p) {
  const zone = opts._[0]?.toLowerCase();
  if (!zone) throw new Error('Usage: restore <domain> [file.zone]');
  const file = opts._[1] || latestBackup(p.backups, zone);
  if (!file || !existsSync(file)) throw new Error(`No backup found for ${zone}`);

  const zoneFile = readFileSync(file, 'utf8');
  console.log(`Restoring ${zone} from ${file}`);
  if (!opts.apply) {
    console.log('\n' + zoneFile);
    console.log('DRY-RUN — add --apply to re-import this zone.');
    return;
  }
  const ovh = client();
  await ovh.syncTime();
  const task = await ovh.post(`/domain/zone/${encodeURIComponent(zone)}/import`, { zoneFile });
  console.log(`Import started (task ${task?.taskId ?? '?'}). Check with: node ovh.mjs audit ${zone}`);
}

export const HELP = `
ovh-domain-manager — anti-spoofing DNS hardening for dormant domains

  node ovh.mjs auth                    Generate the OVH consumer key
  node ovh.mjs whoami                  Check the credentials
  node ovh.mjs snapshot                Back up + inventory EVERY domain in the CSV
  node ovh.mjs snapshot <domain>       Same, for a single domain
  node ovh.mjs inventory               Rebuild the inventory (offline, keeps ticks)
  node ovh.mjs compliance              Score the portfolio against the baseline (offline)
  node ovh.mjs compliance <domain>     Same, for a single domain
  node ovh.mjs policy                  Show the check/remedy configuration (offline)
  node ovh.mjs policy <domain>         Same, resolved for one domain + what harden would do
  node ovh.mjs audit <domain>          Dump the current zone
  node ovh.mjs harden <domain>         Plan (dry-run by default)
  node ovh.mjs harden <domain> --apply
  node ovh.mjs harden-batch --list <file>          Plan for a whole batch (dry-run by default)
  node ovh.mjs harden-batch --list <file> --apply
  node ovh.mjs restore <domain> [f]    Re-import the latest backup (dry-run by default)

inventory/compliance/policy: offline, no credentials needed — they read <storage>/backups/.
compliance: 23 controls over anti-spoofing / closed-by-default / attack surface, scored
            per domain against the posture expected of its state. Writes
            <storage>/compliance.{md,json,csv}. See docs/BASELINE.md.

harden/audit/restore: exactly one domain per run.
harden-batch: iterates over a batch, skips zones with active mail, refuses --force.
              Consolidated report in <storage>/reports/batch-*.{md,json}.

Options:
  --apply              Actually execute (dry-run otherwise)
  --force              Bypass the "active mail" guard rail
  --null-mx            Also try an MX "0 ." (RFC 7505) — OVH may refuse it
  --caa                Publish a CAA deny: no CA may issue (RFC 8659). Opt-in —
                       skipped automatically on a zone that serves web content
  --iodef <mailto:...> CAA violation report address (implies --caa)
  --rua <mailto:...>   DMARC aggregate report address (none by default)
  --keep <regex>       Protect records whose name/value matches (repeatable)
  --drop-cname a,b     CNAMEs to delete on top of ftp
  --drop-redirect      Also delete the OVH web redirection markers (breaks the redirect)
  --json               Machine-readable output (policy)
  --csv <path>         Source CSV (default: the newest one in <storage>/)
  --list <path>        Batch file for harden-batch (one domain per line, # = comment)
  --ttl <s>            TTL of created records (default 3600)
  -h, --help           Show this help
  -v, --version        Show the version

Environment: APP_KEY, APP_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT (default ovh-eu),
             OVH_STORAGE_DIR (default ./storage). Read from .env if present.
             OVH_POLICY_FILE (default ./config/policy.mjs) — a module, and loading it runs it.
`;

/** Commands that read config/policy.mjs. */
const POLICY_COMMANDS = new Set(['policy']);

export async function main(argv) {
  // `node ovh.mjs --version` has no command: the first token is a flag, so it
  // must go through parseArgs rather than be taken as the subcommand name.
  const flagFirst = (argv[0] ?? '').startsWith('-');
  const cmd = flagFirst ? null : argv[0];
  const opts = parseArgs(flagFirst ? argv : argv.slice(1));
  if (opts.version) { console.log(VERSION); return; }
  if (opts.help || !cmd) { console.log(HELP); return; }

  loadEnv();
  const p = ensureStorage();

  // Load the configuration before any client, any credential and any network
  // call, so a typo in it costs an error message and nothing else. Scoped to
  // the commands that read it: a broken policy file must never stand between
  // an operator and `restore`.
  const policy = POLICY_COMMANDS.has(cmd) ? await loadPolicy() : null;

  if (cmd === 'auth') await cmdAuth();
  else if (cmd === 'whoami') await cmdWhoami();
  else if (cmd === 'snapshot') await cmdSnapshot(opts, p);
  else if (cmd === 'inventory') cmdInventory(opts, p);
  else if (cmd === 'compliance') cmdCompliance(opts, p);
  else if (cmd === 'policy') cmdPolicy(opts, p, policy);
  else if (cmd === 'audit') await cmdAudit(opts);
  else if (cmd === 'harden') await cmdHarden(opts, p);
  else if (cmd === 'harden-batch') await cmdHardenBatch(opts, p);
  else if (cmd === 'restore') await cmdRestore(opts, p);
  else console.log(HELP);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    console.error(`\nERROR ${err.message}`);
    process.exit(1);
  }
}
