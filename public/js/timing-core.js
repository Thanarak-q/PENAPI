// Timing Analysis — pure, DOM-free core. Aggregates per-endpoint response times
// from captured history so slow endpoints and timing oracles (e.g. login that
// takes longer for valid usernames) stand out. DOM-free for `node --test`.

function median(sortedNums) {
  const n = sortedNums.length;
  if (!n) return 0;
  const mid = Math.floor(n / 2);
  return n % 2 ? sortedNums[mid] : (sortedNums[mid - 1] + sortedNums[mid]) / 2;
}

// Aggregate timings grouped by "METHOD url". Returns rows sorted by average
// time descending: { key, method, url, count, min, max, avg, median }.
export function aggregateTimings(entries) {
  const groups = new Map();
  for (const entry of entries || []) {
    const t = entry && entry.timeMs;
    if (t == null || Number.isNaN(t)) continue;
    const method = entry.method || '';
    const url = entry.url || '';
    const key = `${method} ${url}`;
    if (!groups.has(key)) groups.set(key, { key, method, url, times: [] });
    groups.get(key).times.push(Number(t));
  }

  const rows = [];
  for (const g of groups.values()) {
    const sorted = g.times.slice().sort((a, b) => a - b);
    const sum = sorted.reduce((a, b) => a + b, 0);
    rows.push({
      key: g.key,
      method: g.method,
      url: g.url,
      count: sorted.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: sum / sorted.length,
      median: median(sorted),
    });
  }
  rows.sort((a, b) => b.avg - a.avg);
  return rows;
}

// The largest avg-time gap between consecutive same-endpoint groups can hint at
// a timing oracle when grouped by a varying input. Exposed for callers/tests.
export { median };
