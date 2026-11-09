/**
 * CVSS v3.1 Base Score calculator - the published FIRST.org formula, nothing homegrown.
 * Dual-exported (ESM `export` for the browser, CommonJS `module.exports` for node --test)
 * so the arithmetic itself gets a real automated test instead of "looks right."
 */

// Metric definitions drive both the scoring and the button grid the GUI builds from them.
// Order matches the standard vector string order.
export const METRICS = [
  { key: 'AV', label: 'Attack Vector', options: [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']] },
  { key: 'AC', label: 'Attack Complexity', options: [['L', 'Low'], ['H', 'High']] },
  { key: 'PR', label: 'Privileges Required', options: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'UI', label: 'User Interaction', options: [['N', 'None'], ['R', 'Required']] },
  { key: 'S', label: 'Scope', options: [['U', 'Unchanged'], ['C', 'Changed']] },
  { key: 'C', label: 'Confidentiality', options: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'I', label: 'Integrity', options: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'A', label: 'Availability', options: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
];

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }, // Scope Unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.5 }, // Scope Changed
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0, L: 0.22, H: 0.56 },
};

const SEVERITY = [
  [0, 'None'], [0.1, 'Low'], [4.0, 'Medium'], [7.0, 'High'], [9.0, 'Critical'],
];

/** The FIRST.org Roundup() reference algorithm: smallest 1-decimal number >= input, done in
 * integer space to dodge float rounding traps (0.1 + 0.2 !== 0.3 and all that). */
function roundup(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function severityFor(score) {
  if (score <= 0) return 'None';
  let out = 'None';
  for (const [min, label] of SEVERITY) if (score >= min) out = label;
  return out;
}

/**
 * metrics: { AV, AC, PR, UI, S, C, I, A } - single-letter values as in the table above.
 * Returns null if any metric is missing (incomplete vector - nothing to score yet).
 * Otherwise { vector, score, severity }.
 */
export function computeCvss31(metrics) {
  for (const m of METRICS) if (!metrics[m.key]) return null;
  const { AV, AC, PR, UI, S, C, I, A } = metrics;

  const prWeight = (S === 'C' ? W.PR_C : W.PR_U)[PR];
  const iscBase = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
  const impact = S === 'C'
    ? 7.52 * (iscBase - 0.029) - 3.25 * (iscBase - 0.02) ** 15
    : 6.42 * iscBase;
  const exploitability = 8.22 * W.AV[AV] * W.AC[AC] * prWeight * W.UI[UI];

  let score;
  if (impact <= 0) score = 0;
  else if (S === 'C') score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  else score = roundup(Math.min(impact + exploitability, 10));

  const vector = `CVSS:3.1/${METRICS.map((m) => `${m.key}:${metrics[m.key]}`).join('/')}`;
  return { vector, score, severity: severityFor(score) };
}

/** Parse a vector string ("CVSS:3.1/AV:N/AC:L/...") back into { AV, AC, ... } for re-editing a
 * saved finding. Returns {} (not null) on anything unparseable, so the UI just starts blank. */
export function parseCvss31Vector(vector) {
  const out = {};
  if (typeof vector !== 'string') return out;
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (METRICS.some((m) => m.key === k) && v) out[k] = v;
  }
  return out;
}
