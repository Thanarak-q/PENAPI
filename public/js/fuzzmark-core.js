// fuzzmark-core.js — DOM-free helpers for placing a single §…§ fuzz injection
// marker. The fuzzer replaces every marker with the same payload, so auto-mark
// deliberately marks exactly ONE position (the most likely injection point).
// Pure functions, testable under `node --test`.

// Wrap a [start,end) range of `value` in §…§. With an empty range, inserts an
// empty §§ at `start`. Returns { value, caret } (caret sits inside the markers).
export function wrapMarker(value, start, end) {
  if (end > start) {
    return {
      value: value.slice(0, start) + '§' + value.slice(start, end) + '§' + value.slice(end),
      caret: end + 2,
    };
  }
  return {
    value: value.slice(0, start) + '§§' + value.slice(start),
    caret: start + 1,
  };
}

// Mark a likely injection point in a URL: the first query-param value, else the
// last path segment. Returns the marked URL (or the original if nothing fits).
export function autoMarkUrl(url) {
  if (!url || url.includes('§')) return url;
  if (url.includes('?')) {
    const marked = url.replace(/([?&][^=&#]+=)([^&#]*)/, (m, k, v) => `${k}§${v}§`);
    if (marked !== url) return marked;
  }
  return url.replace(/\/([^/?#]+)(\/?)(\?[^#]*)?$/, (m, seg, slash, qs) => `/§${seg}§${slash}${qs || ''}`);
}

// Mark the first scalar value in a request body: JSON string, then JSON number,
// then a urlencoded value. Returns the marked body, or null if nothing matched.
export function autoMarkBody(body) {
  if (!body || body.includes('§')) return null;
  let out = body.replace(/(:\s*)"([^"\\]*)"/, (m, pre, val) => `${pre}"§${val}§"`);
  if (out !== body) return out;
  out = body.replace(/(:\s*)(-?\d+(?:\.\d+)?)/, (m, pre, val) => `${pre}§${val}§`);
  if (out !== body) return out;
  out = body.replace(/^([^=&\n]+=)([^&\n]*)/, (m, k, v) => `${k}§${v}§`);
  if (out !== body) return out;
  return null;
}
