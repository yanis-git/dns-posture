// Scoring and evaluation for the compliance baseline.
//
// Pure and offline. It reads the { name, type, rdata } shape produced by
// parseZone, so it scores the on-disk backups without touching the network —
// the same source `inventory` rebuilds from.
//
// The checks themselves live in ./checks.mjs. What is left here is the part
// that turns their verdicts into a number an auditor can read: which checks
// apply to which state, what a severity is worth, how a grade is capped, and
// how sixty per-domain reports roll up into one portfolio figure.
//
// `na` is excluded from the numerator AND the denominator, and always carries
// its reason. Changing a weight, a scope or the catalogue changes every score
// without a single DNS record changing, so BASELINE_VERSION is stamped into
// every report and must be bumped whenever any of them moves.

import { classify } from './inventory.mjs';
import { caaApplicable, caaBlocker } from './zone.mjs';
import { CHECKS, CONTROLS, context, na } from './checks.mjs';

// Re-exported: the catalogue moved to ./checks.mjs, but callers and tests have
// always reached it through here.
export { CHECKS, CONTROLS };

// Re-exported: `caaBlocker` moved to the leaf when the policy resolver became
// its third consumer, but it is part of this module's published surface.
export { caaBlocker, caaApplicable };

export const BASELINE_VERSION = '1.1.0';

export const AXES = ['spoofing', 'closed', 'surface'];

export const AXIS_TITLES = {
  spoofing: 'Anti-spoofing',
  closed: 'Closed by default',
  surface: 'Attack surface',
};

export const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1 };

export const GRADE_BANDS = [[95, 'A'], [85, 'B'], [70, 'C'], [50, 'D'], [0, 'F']];

// Which classifier states a control applies to. Everything else is `na`: an
// audit that covers the whole portfolio has to score each domain against the
// posture expected of *its* state, or every mail-active domain reads as F.
export const SCOPES = {
  'all': ['dormant', 'web-active', 'mail-active'],
  'non-sending': ['dormant', 'web-active'],
  'sending': ['mail-active'],
  'dormant': ['dormant'],
};


function scoreOf(controls) {
  let num = 0;
  let den = 0;
  for (const c of controls) {
    if (c.status === 'na') continue;
    const weight = SEVERITY_WEIGHT[c.severity] ?? 0;
    den += weight;
    if (c.status === 'pass') num += weight;
  }
  return den === 0 ? null : Math.round((100 * num) / den);
}

/**
 * Grade from the score, capped at C when a critical control fails.
 *
 * The cap is the one non-linear rule, and it earns its place: without it a zone
 * with no SPF at all still reads "A" because the twenty other controls pass.
 */
function gradeOf(score, controls) {
  if (score === null) return null;
  const band = GRADE_BANDS.find(([min]) => score >= min);
  const grade = band ? band[1] : 'F';
  const criticalFail = controls.some((c) => c.status === 'fail' && c.severity === 'critical');
  return criticalFail && (grade === 'A' || grade === 'B') ? 'C' : grade;
}

function axisBreakdown(controls) {
  const axes = {};
  for (const axis of AXES) {
    const subset = controls.filter((c) => c.axis === axis);
    axes[axis] = {
      score: scoreOf(subset),
      pass: subset.filter((c) => c.status === 'pass').length,
      fail: subset.filter((c) => c.status === 'fail').length,
      na: subset.filter((c) => c.status === 'na').length,
    };
  }
  return axes;
}

/**
 * Score one zone against the baseline.
 *
 * `state` overrides the classifier — used by tests and by callers that already
 * classified. `classify` is called either way: the report carries the signals
 * and counts so a reader never has to open two files.
 */
export function evaluate(records, { domain = null, state = null } = {}) {
  const cls = classify(records, { domain });
  const effective = state ?? cls.state;
  const ctx = context(records, { domain, state: effective, signals: cls.signals, counts: cls.counts });

  const hardenable = effective !== 'mail-active';

  const controls = CONTROLS.map((control) => {
    const inScope = SCOPES[control.scope].includes(effective);
    const result = inScope
      ? control.check(records, ctx)
      : na(`out of scope for a ${effective} domain (control applies to: ${SCOPES[control.scope].join(', ')}).`);

    const remediation = result.status === 'fail' ? (result.remediation ?? null) : null;
    return {
      id: control.id,
      title: control.title,
      axis: control.axis,
      severity: control.severity,
      scope: control.scope,
      refs: control.refs,
      status: result.status,
      // Why a control is `na`. 'scope' is mechanical — it follows from the
      // state and says nothing a reader does not already know. 'check' is a
      // judgement the baseline made about this zone, and is worth reading.
      naReason: result.status !== 'na' ? null : (inScope ? 'check' : 'scope'),
      detail: result.detail,
      evidence: result.evidence ?? [],
      remediation: remediation && {
        text: remediation.text,
        // `harden` publishes `v=spf1 -all` and refuses a mail-active zone
        // anyway. Printing the command next to a finding on a domain that
        // legitimately sends mail is advice that would break that mail, so the
        // fix stays manual there.
        command: hardenable && remediation.command && domain
          ? remediation.command.replace('<domain>', domain)
          : (hardenable ? remediation.command ?? null : null),
      },
    };
  });

  const score = scoreOf(controls);
  return {
    domain,
    state: effective,
    signals: cls.signals,
    counts: cls.counts,
    score,
    grade: gradeOf(score, controls),
    tally: {
      pass: controls.filter((c) => c.status === 'pass').length,
      fail: controls.filter((c) => c.status === 'fail').length,
      na: controls.filter((c) => c.status === 'na').length,
    },
    axes: axisBreakdown(controls),
    controls,
  };
}

const mean = (values) => (values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : null);

/**
 * Roll per-domain reports up into a portfolio summary.
 *
 * The portfolio score is the unweighted mean of the per-domain scores, not a
 * pooled sum of weights: otherwise one zone with forty records would outvote
 * forty empty ones, and the number would stop meaning "how is the portfolio".
 * Domains with no backup are counted apart, never scored 0.
 */
export function aggregate(reports) {
  const scored = reports.filter((r) => typeof r.score === 'number');
  const errors = reports.filter((r) => r.state === 'error');

  const byState = {};
  const byGrade = {};
  for (const r of reports) byState[r.state] = (byState[r.state] ?? 0) + 1;
  for (const r of scored) byGrade[r.grade] = (byGrade[r.grade] ?? 0) + 1;

  const axes = {};
  for (const axis of AXES) {
    axes[axis] = mean(scored.map((r) => r.axes[axis].score).filter((s) => typeof s === 'number'));
  }

  const counters = new Map();
  for (const r of scored) {
    for (const c of r.controls) {
      if (c.status !== 'fail') continue;
      const entry = counters.get(c.id)
        ?? { id: c.id, title: c.title, axis: c.axis, severity: c.severity, refs: c.refs, count: 0 };
      entry.count++;
      counters.set(c.id, entry);
    }
  }
  const topFailures = [...counters.values()].sort((a, b) => b.count - a.count
    || (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0)
    || a.id.localeCompare(b.id));

  const score = mean(scored.map((r) => r.score));
  return {
    domains: reports.length,
    scored: scored.length,
    errors: errors.length,
    score,
    grade: score === null ? null : (GRADE_BANDS.find(([min]) => score >= min)?.[1] ?? 'F'),
    axes,
    byState,
    byGrade,
    topFailures,
  };
}
