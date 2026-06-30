'use strict';

// Generates request variants for one-click "quick attack" checks against a
// single base request. Each variant returns { name, note, request } and the
// caller sends them and diffs the responses against the baseline.

const AUTH_HEADERS = ['authorization', 'cookie', 'x-api-key', 'api-key', 'x-auth-token'];

function stripAuth(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!AUTH_HEADERS.includes(k.toLowerCase())) out[k] = v;
  }
  return out;
}

function findAuthKey(headers) {
  return Object.keys(headers).find((k) => k.toLowerCase() === 'authorization');
}

// Merge privileged fields into a JSON object body for a quick mass-assignment
// probe. Returns the new body string, or null when the body is not a JSON object.
function injectPrivilegedFields(body) {
  if (!body) return null;
  let obj;
  try {
    obj = JSON.parse(body);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  return JSON.stringify({ ...obj, role: 'admin', isAdmin: true, is_admin: true, admin: true });
}

function toggleTrailingSlash(url) {
  try {
    const u = new URL(url);
    if (u.pathname.endsWith('/')) u.pathname = u.pathname.replace(/\/+$/, '');
    else u.pathname += '/';
    return u.toString();
  } catch {
    return url;
  }
}

// Return a copy of `url` with its path transformed by `fn(path) -> newPath`.
// Operates on the raw string (not the URL parser) so non-normalized sequences
// like "/.", "%2f", and "//" survive — that is the whole point of these
// bypass variants. Handles absolute (scheme://host/path) and bare-path URLs.
function rewritePath(url, fn) {
  const s = String(url || '');
  const m = s.match(/^([a-z][a-z0-9+.-]*:\/\/[^/?#]*)?([^?#]*)(.*)$/i);
  if (!m) return s;
  const [, origin = '', path, rest = ''] = m;
  return origin + fn(path || '') + rest;
}

// Build the variant list for a base request.
function buildVariants(base) {
  const headers = base.headers || {};
  const variants = [];
  const add = (name, note, req) => variants.push({ name, note, request: req });

  add('baseline', 'request as sent', { ...base });

  // Authentication
  add('no auth', 'all auth headers stripped', {
    ...base,
    headers: stripAuth(headers),
  });

  const authKey = findAuthKey(headers);
  if (authKey) {
    add('empty bearer', 'Authorization: Bearer (empty)', {
      ...base,
      headers: { ...headers, [authKey]: 'Bearer ' },
    });
    add('malformed token', 'syntactically invalid JWT', {
      ...base,
      headers: { ...headers, [authKey]: 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.' },
    });
  }

  // Method tampering / HTTP verb confusion
  if (base.method !== 'GET') {
    add('method → GET', 'verb swapped to GET', { ...base, method: 'GET' });
  }
  add('X-HTTP-Method-Override', 'override header set to GET', {
    ...base,
    headers: { ...headers, 'X-HTTP-Method-Override': 'GET' },
  });
  add('method override (alt headers)', 'X-HTTP-Method / X-Method-Override → GET', {
    ...base,
    headers: { ...headers, 'X-HTTP-Method': 'GET', 'X-Method-Override': 'GET' },
  });

  // Authorization bypass via proxy/rewrite headers
  add('X-Original-URL', 'path bypass header (/)', {
    ...base,
    headers: { ...headers, 'X-Original-URL': '/', 'X-Rewrite-URL': '/' },
  });
  add('spoofed origin', 'internal source IP/host headers', {
    ...base,
    headers: {
      ...headers,
      'X-Forwarded-For': '127.0.0.1',
      'X-Forwarded-Host': 'localhost',
      'X-Real-IP': '127.0.0.1',
      'X-Originating-IP': '127.0.0.1',
    },
  });

  add('X-Forwarded-Proto http', 'scheme downgrade — defeat HTTPS-only redirects', {
    ...base,
    headers: { ...headers, 'X-Forwarded-Proto': 'http', 'X-Forwarded-Scheme': 'http' },
  });

  // Path normalization / ACL bypass
  add('trailing slash', 'toggle trailing slash on path', {
    ...base,
    url: toggleTrailingSlash(base.url),
  });
  add('trailing dot', 'append "/." — normalizes back, may skip the ACL', {
    ...base,
    url: rewritePath(base.url, (p) => p.replace(/\/+$/, '') + '/.'),
  });
  add('encoded slash', 'insert %2f before the last segment', {
    ...base,
    url: rewritePath(base.url, (p) => p.replace(/\/([^/]*)$/, '/%2f$1')),
  });
  add('case-swapped path', 'upper-case the path for case-insensitive routes', {
    ...base,
    url: rewritePath(base.url, (p) => p.toUpperCase()),
  });
  add('double slash', 'leading double slash on the path', {
    ...base,
    url: rewritePath(base.url, (p) => '//' + p.replace(/^\/+/, '')),
  });
  add('matrix param', 'append ;param — routers may ignore it while the ACL does not', {
    ...base,
    url: rewritePath(base.url, (p) => p.replace(/\/+$/, '') + ';x=1'),
  });
  add('semicolon traversal', 'insert /..;/ before the last segment (Tomcat/Spring)', {
    ...base,
    url: rewritePath(base.url, (p) => p.replace(/\/([^/]*)$/, '/..;/$1')),
  });
  add('extension append', 'append .json — extension-based ACL/route bypass', {
    ...base,
    url: rewritePath(base.url, (p) => p.replace(/\/+$/, '') + '.json'),
  });

  // Content negotiation
  add('Accept */*', 'wildcard Accept — bypass JSON-only filters', {
    ...base,
    headers: { ...headers, Accept: '*/*' },
  });

  // Content-type confusion (only meaningful with a body)
  if (base.body) {
    add('content-type → text/plain', 'parser confusion / filter bypass', {
      ...base,
      headers: { ...headers, 'Content-Type': 'text/plain' },
    });
    add('content-type → xml', 'force XML parsing of a JSON body', {
      ...base,
      headers: { ...headers, 'Content-Type': 'application/xml' },
    });
    add('content-type → form', 'force form-urlencoded parsing of a JSON body', {
      ...base,
      headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    // Mass-assignment: inject privileged fields into a JSON object body.
    const injected = injectPrivilegedFields(base.body);
    if (injected) {
      add('mass-assignment body', 'inject role/isAdmin/admin into the JSON body', {
        ...base,
        body: injected,
      });
    }
  }

  return variants;
}

module.exports = { buildVariants, stripAuth, rewritePath };
