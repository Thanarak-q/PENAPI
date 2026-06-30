// Pure risk-aggregation helpers over an analysis report. No DOM, no state — so
// this can be unit-tested directly (report.js wraps it with the memoized,
// state-bound getReport()).

import { SEV_WEIGHT } from './shared.js';

export const SEV_RANK = { high: 3, medium: 2, low: 1, info: 0 };

// Aggregate findings per endpoint id for at-a-glance risk badges.
// Returns Map<endpointId, { score, count, worst, high, medium, titles }>.
export function endpointRiskMap(report) {
  const map = new Map();
  for (const finding of report?.findings || []) {
    if (!finding.endpointId) continue;
    const cur = map.get(finding.endpointId) || { score: 0, count: 0, worst: 'info', high: 0, medium: 0, titles: [] };
    cur.score += SEV_WEIGHT[finding.sev] || 0;
    cur.count += 1;
    if (finding.sev === 'high') cur.high += 1;
    if (finding.sev === 'medium') cur.medium += 1;
    if (SEV_RANK[finding.sev] > SEV_RANK[cur.worst]) cur.worst = finding.sev;
    if (cur.titles.length < 6) cur.titles.push(`${finding.sev}: ${finding.title}`);
    map.set(finding.endpointId, cur);
  }
  return map;
}
