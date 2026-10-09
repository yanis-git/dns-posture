import { classify } from './inventory.mjs';
import { evaluate } from './baseline.mjs';
import { resolvePolicy, planFromFindings } from './policy.mjs';
import { planZone } from './harden.mjs';
import { toZoneShape } from './zone.mjs';

export function posture(records, domain, policy, opts = {}) {
  const view = records.map(toZoneShape);
  const cls = classify(view, { domain });
  const report = evaluate(view, { domain });
  const resolved = resolvePolicy(view, { domain, state: cls.state, policy });
  resolved.keep = [...resolved.keep, ...(opts.keep || [])];
  if (opts.ttl !== undefined) resolved.ttl = opts.ttl;
  // Legacy flags become overrides, after classification. They cannot activate a mail profile.
  if (cls.state !== 'mail-active') {
    if (opts.dropRedirect) resolved.dropRedirect = true;
    if (opts.cnames && (opts.cnamesExplicit || !opts._)) resolved.dropCnames = [...new Set([...resolved.dropCnames, ...opts.cnames])];
    if (opts.nullMx) {
      for (const id of ['mx.closed', 'mx.null-explicit']) {
        resolved.checks[id] = { ...resolved.checks[id], remedy: { action: 'enforce', record: 'mx.null' }, template: policy.records['mx.null'] };
      }
    }
    if (opts.caa && !resolved.caaBlocked) {
      for (const [id, key] of [['caa.issue-deny', 'caa.deny-issue'], ['caa.issuewild-deny', 'caa.deny-issuewild']]) {
        resolved.checks[id] = { ...resolved.checks[id], remedy: { action: 'enforce', record: key }, template: policy.records[key] };
      }
    }
    if (opts.rua) {
      for (const entry of Object.values(resolved.checks)) {
        if (entry.template?.subDomain === '_dmarc') entry.template = { ...entry.template, target: entry.template.target.replace(/;\s*rua=[^;]*/g, '') + `; rua=${opts.rua}` };
      }
    }
  }
  const inputs = planFromFindings(report, resolved, records);
  if (opts.iodef && opts.caa && !resolved.caaBlocked && cls.state !== 'mail-active') {
    inputs.wanted.push({ subDomain: '', fieldType: 'CAA', target: `0 iodef "${opts.iodef}"`, ttl: resolved.ttl });
  }
  const plan = planZone(records, { ...inputs, keepPatterns: resolved.keep, dropCnames: resolved.dropCnames, dropRedirect: resolved.dropRedirect });
  // A keep-protected exclusive record cannot coexist with a newly created SPF/DMARC/MX.
  for (const r of plan.create) {
    const template = Object.values(policy.records).find((t) => t.fieldType === r.fieldType && t.subDomain === r.subDomain && t.exclusive);
    if (template && plan.keep.some((k) => k.fieldType === r.fieldType && k.subDomain === r.subDomain && (r.fieldType !== 'TXT' || /^v=(spf1|dmarc1)/i.test(k.target.replace(/^"/, ''))))) {
      inputs.conflicts.push({ wanted: r, reason: 'Protected exclusive record competes with policy' });
    }
  }
  return { ...cls, report, resolved, ...inputs, plan };
}
