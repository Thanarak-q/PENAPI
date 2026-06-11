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

  // Path normalization
  add('trailing slash', 'toggle trailing slash on path', {
    ...base,
    url: toggleTrailingSlash(base.url),
  });

  // Content-type confusion (only meaningful with a body)
  if (base.body) {
    add('content-type → text/plain', 'parser confusion / filter bypass', {
      ...base,
      headers: { ...headers, 'Content-Type': 'text/plain' },
    });
  }

  return variants;
}

module.exports = { buildVariants, stripAuth };
