// Timestamp Converter — pure, DOM-free core. Parses a timestamp from several
// formats (Unix seconds, Unix milliseconds, ISO 8601) and reports each
// representation plus a human-relative offset. Useful for reading JWT exp/iat
// and other epoch claims. DOM-free for `node --test`.

const MS_PER = { s: 1000, m: 60000, h: 3600000, d: 86400000 };

// Detect and parse an input into epoch milliseconds.
// Returns { ms, kind } or null when unparseable. `now` (ms) is injectable for
// deterministic tests.
export function parseTimestamp(input, now = Date.now()) {
  const v = String(input == null ? '' : input).trim();
  if (!v) return null;

  if (/^-?\d+$/.test(v)) {
    const n = Number(v);
    // Heuristic: 10-digit (or fewer) integers are seconds; 13-ish are ms.
    // Anything with |value| >= 1e12 is treated as milliseconds.
    if (Math.abs(n) >= 1e12) return { ms: n, kind: 'unix-ms' };
    return { ms: n * 1000, kind: 'unix-s' };
  }
  if (/^-?\d+\.\d+$/.test(v)) {
    return { ms: Math.round(Number(v) * 1000), kind: 'unix-s' };
  }

  const parsed = Date.parse(v);
  if (!Number.isNaN(parsed)) return { ms: parsed, kind: 'iso' };

  return null;
}

// Format a parsed result into representations. Returns null on bad input.
export function describeTimestamp(input, now = Date.now()) {
  const p = parseTimestamp(input, now);
  if (!p) return null;
  const d = new Date(p.ms);
  if (Number.isNaN(d.getTime())) return null;
  return {
    detectedAs: p.kind,
    unixSeconds: Math.floor(p.ms / 1000),
    unixMillis: p.ms,
    iso: d.toISOString(),
    utc: d.toUTCString(),
    relative: relativeTime(p.ms, now),
    isPast: p.ms < now,
  };
}

// Human-relative string like "in 2 hours" / "3 days ago".
export function relativeTime(ms, now = Date.now()) {
  const diff = ms - now;
  const abs = Math.abs(diff);
  let unit = 's';
  if (abs >= MS_PER.d) unit = 'd';
  else if (abs >= MS_PER.h) unit = 'h';
  else if (abs >= MS_PER.m) unit = 'm';
  const n = Math.round(abs / MS_PER[unit]);
  const label = { s: 'second', m: 'minute', h: 'hour', d: 'day' }[unit];
  const plural = n === 1 ? label : label + 's';
  if (n === 0) return 'now';
  return diff >= 0 ? `in ${n} ${plural}` : `${n} ${plural} ago`;
}

// Current time in both common epoch forms — handy "now" button.
export function nowStamps(now = Date.now()) {
  return { unixSeconds: Math.floor(now / 1000), unixMillis: now, iso: new Date(now).toISOString() };
}
