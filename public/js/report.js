// Shared, memoized access to the passive-analysis report so the Recon view and
// the Explorer sidebar both reuse a single analysis pass per spec/history change
// instead of each re-walking every endpoint and log entry on every render.

import { state } from './state.js';
import { analyzeSpec } from './static-analysis.js';
import { endpointRiskMap } from './analyzers/risk.js';

export { endpointRiskMap };

let cache = { specRef: null, sig: '', report: null };

// Cheap signature that changes whenever the analysis inputs change: history
// length plus the newest entry's timestamp (so it still detects a fresh log
// even when the capped history stays the same length).
function historySig() {
  const history = Array.isArray(state.history) ? state.history : [];
  return `${history.length}:${history[0]?.at || 0}`;
}

export function getReport() {
  if (!state.spec) return { findings: [], summary: null, categoryLabels: {} };
  const sig = historySig();
  if (cache.report && cache.specRef === state.spec && cache.sig === sig) {
    return cache.report;
  }
  const report = analyzeSpec(state.spec, state.history);
  cache = { specRef: state.spec, sig, report };
  return report;
}

// Force a recompute on the next getReport() call.
export function invalidateReport() {
  cache = { specRef: null, sig: '', report: null };
}
