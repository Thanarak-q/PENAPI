// HTTP Status Reference — pure, DOM-free core. A lookup table of HTTP status
// codes with their meaning and a short pentest-oriented note, plus a search
// filter over code / phrase / note. DOM-free for `node --test`.

const CODES = [
  [200, 'OK', 'Baseline success — compare body/length against unauthorized attempts to spot access-control gaps.'],
  [201, 'Created', 'A write succeeded — check whether you should have been allowed to create this resource.'],
  [204, 'No Content', 'Action accepted with empty body — common on DELETE/PUT; confirm authorization was enforced.'],
  [301, 'Moved Permanently', 'Redirect — follow it; redirects to login can mask auth failures behind a 200.'],
  [302, 'Found', 'Redirect — a 302 to /login often means "unauthorized" dressed up; treat as access denied.'],
  [304, 'Not Modified', 'Cache validation — ETag/If-None-Match handling; rarely security-relevant.'],
  [307, 'Temporary Redirect', 'Method-preserving redirect — POST stays POST; watch for open redirect in the Location.'],
  [400, 'Bad Request', 'Malformed input — flip between 400/500 while fuzzing to find parser edges and injection.'],
  [401, 'Unauthorized', 'Authentication required/failed — supply or swap credentials; check if any path skips it.'],
  [403, 'Forbidden', 'Authn ok, authz denied — try verb tampering, path tricks, X-Original-URL / X-Forwarded-For, case games.'],
  [404, 'Not Found', 'Missing — or a 403 hidden as 404. Diff response size/timing to confirm existence (content discovery).'],
  [405, 'Method Not Allowed', 'Wrong verb — enumerate allowed methods (Allow header); try TRACE/PUT/PATCH for misconfig.'],
  [406, 'Not Acceptable', 'Content negotiation — vary Accept; sometimes bypasses filters expecting JSON only.'],
  [415, 'Unsupported Media Type', 'Server rejects the Content-Type — try alt encodings (see Body Converter) to slip past validation.'],
  [418, "I'm a Teapot", 'Often a WAF/joke response — can indicate a filtering proxy is interfering.'],
  [429, 'Too Many Requests', 'Rate limited — note the limit and Retry-After; test per-IP vs per-token scoping and bypasses.'],
  [500, 'Internal Server Error', 'Unhandled exception — gold for error-based injection; capture stack traces / SQL errors.'],
  [501, 'Not Implemented', 'Verb/feature unimplemented — fingerprinting signal for the stack.'],
  [502, 'Bad Gateway', 'Upstream failed — possible SSRF/proxy boundary; probe internal hosts behind the gateway.'],
  [503, 'Service Unavailable', 'Overloaded/down or WAF block page — distinguish real outage from active blocking.'],
  [504, 'Gateway Timeout', 'Upstream timed out — a long delay can reveal SSRF to a non-routable host or a time-based injection.'],
];

const TABLE = CODES.map(([code, phrase, note]) => ({ code, phrase, note }));

// All entries.
export function allStatuses() {
  return TABLE.slice();
}

// Exact lookup by numeric code.
export function lookupStatus(code) {
  const n = Number(code);
  return TABLE.find((e) => e.code === n) || null;
}

// Search by code prefix / phrase / note substring (case-insensitive).
export function searchStatuses(query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return allStatuses();
  return TABLE.filter((e) =>
    String(e.code).startsWith(q) ||
    e.phrase.toLowerCase().includes(q) ||
    e.note.toLowerCase().includes(q)
  );
}
