// Body Converter — pure, DOM-free core. Converts a flat JSON object into other
// request-body encodings (form-urlencoded, multipart/form-data, query string)
// to probe content-type confusion and parameter pollution on an API. Nested
// values are JSON-encoded so they survive the round trip. DOM-free for `node --test`.

// Convert a parsed object to entries [[key, stringValue]]. Nested objects /
// arrays are serialized to JSON; primitives are stringified.
export function toEntries(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('Body must be a JSON object at the top level.');
  }
  return Object.entries(obj).map(([k, v]) => [
    k,
    v === null || typeof v !== 'object' ? String(v) : JSON.stringify(v),
  ]);
}

// application/x-www-form-urlencoded
export function toFormUrlencoded(obj) {
  return toEntries(obj)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

// Query string (same encoding, prefixed with ?). Empty object -> ''.
export function toQueryString(obj) {
  const body = toFormUrlencoded(obj);
  return body ? `?${body}` : '';
}

// multipart/form-data with a fixed boundary, returns { boundary, body }.
export function toMultipart(obj, boundary = '----SwaggernautBoundary7MA4YWxkTrZu0gW') {
  const parts = toEntries(obj).map(
    ([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`
  );
  return { boundary, body: parts.join('') + `--${boundary}--\r\n` };
}

// Parse JSON then produce every encoding. Returns { ok, error, ...encodings }.
export function convertBody(text) {
  let obj;
  try {
    obj = JSON.parse(String(text || ''));
  } catch (e) {
    return { ok: false, error: 'Invalid JSON: ' + e.message };
  }
  try {
    const multipart = toMultipart(obj);
    return {
      ok: true,
      error: null,
      formUrlencoded: toFormUrlencoded(obj),
      queryString: toQueryString(obj),
      multipartBoundary: multipart.boundary,
      multipart: multipart.body,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
