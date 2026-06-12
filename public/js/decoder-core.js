// Decoder — pure, DOM-free transform core. Encode, decode, and smart-detect
// across the formats that show up constantly in API testing: Base64 /
// Base64URL, URL, hex, HTML entities, and JWT.
//
// Implemented over byte arrays with TextEncoder/TextDecoder so the exact same
// code runs in the browser and under `node --test` — no btoa/Buffer split.

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = (() => {
  const m = {};
  for (let i = 0; i < B64.length; i++) m[B64[i]] = i;
  return m;
})();

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8ToBytes(str) {
  return encoder.encode(str);
}
export function bytesToUtf8(bytes) {
  return decoder.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

// --- Base64 (standard + URL-safe) --------------------------------------

export function bytesToBase64(bytes, urlSafe = false) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64[b2 & 63] : '=';
  }
  if (urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return out;
}

export function base64ToBytes(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const bytes = [];
  for (let i = 0; i < s.length; i += 4) {
    const c0 = B64_LOOKUP[s[i]] ?? 0;
    const c1 = B64_LOOKUP[s[i + 1]] ?? 0;
    const p2 = s[i + 2] === '=' || s[i + 2] === undefined;
    const p3 = s[i + 3] === '=' || s[i + 3] === undefined;
    const c2 = p2 ? 0 : B64_LOOKUP[s[i + 2]] ?? 0;
    const c3 = p3 ? 0 : B64_LOOKUP[s[i + 3]] ?? 0;
    bytes.push((c0 << 2) | (c1 >> 4));
    if (!p2) bytes.push(((c1 & 15) << 4) | (c2 >> 2));
    if (!p3) bytes.push(((c2 & 3) << 6) | c3);
  }
  return new Uint8Array(bytes);
}

export const base64Encode = (s) => bytesToBase64(utf8ToBytes(s));
export const base64Decode = (s) => bytesToUtf8(base64ToBytes(s));
export const base64UrlEncode = (s) => bytesToBase64(utf8ToBytes(s), true);
export const base64UrlDecode = (s) => bytesToUtf8(base64ToBytes(s));

// --- Hex ---------------------------------------------------------------

export function hexEncode(str) {
  return [...utf8ToBytes(str)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export function hexDecode(hex) {
  const clean = String(hex).replace(/\s+/g, '');
  const bytes = [];
  for (let i = 0; i + 1 < clean.length; i += 2) {
    bytes.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return bytesToUtf8(new Uint8Array(bytes));
}

// --- URL ---------------------------------------------------------------

export function urlEncode(str) {
  return encodeURIComponent(str);
}
export function urlDecode(str) {
  try {
    return decodeURIComponent(String(str).replace(/\+/g, ' '));
  } catch {
    return String(str);
  }
}

// --- HTML entities -----------------------------------------------------

const HTML_ENC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const HTML_DEC = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", apos: "'", nbsp: ' ' };

export function htmlEncode(str) {
  return String(str).replace(/[&<>"']/g, (c) => HTML_ENC[c]);
}
export function htmlDecode(str) {
  return String(str).replace(/&(#x?[0-9a-fA-F]+|\w+);/g, (whole, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      return Number.isNaN(code) ? whole : String.fromCodePoint(code);
    }
    return Object.prototype.hasOwnProperty.call(HTML_DEC, body) ? HTML_DEC[body] : whole;
  });
}

// --- JWT ---------------------------------------------------------------

// Decode a JWT to a readable header+payload view (does not verify the signature).
export function jwtDecode(token) {
  const parts = String(token).trim().split('.');
  if (parts.length < 2) throw new Error('not a JWT (need header.payload[.signature])');
  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));
  return { header, payload, signature: parts[2] || '' };
}

export function jwtDecodePretty(token) {
  const { header, payload, signature } = jwtDecode(token);
  return [
    '// header',
    JSON.stringify(header, null, 2),
    '',
    '// payload',
    JSON.stringify(payload, null, 2),
    '',
    `// signature: ${signature || '(none)'}`,
  ].join('\n');
}

// --- Smart decode ------------------------------------------------------

// Best-effort: detect the most likely encoding and decode it once.
// Returns { format, output }.
export function smartDecode(input) {
  const s = String(input).trim();
  if (!s) return { format: 'none', output: '' };

  if (s.split('.').length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./.test(s)) {
    try {
      return { format: 'jwt', output: jwtDecodePretty(s) };
    } catch { /* fall through */ }
  }
  if (/%[0-9a-fA-F]{2}/.test(s)) {
    return { format: 'url', output: urlDecode(s) };
  }
  if (/&(#x?[0-9a-fA-F]+|\w+);/.test(s)) {
    return { format: 'html', output: htmlDecode(s) };
  }
  if (/^[0-9a-fA-F\s]+$/.test(s) && s.replace(/\s+/g, '').length % 2 === 0) {
    const out = hexDecode(s);
    if (isPrintable(out)) return { format: 'hex', output: out };
  }
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(s) && s.replace(/=+$/, '').length % 4 !== 1) {
    const out = base64Decode(s);
    if (isPrintable(out)) return { format: 'base64', output: out };
  }
  return { format: 'plain', output: s };
}

function isPrintable(str) {
  if (!str) return false;
  // Reject if it contains many control chars (likely a wrong guess).
  let control = 0;
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if (code < 9 || (code > 13 && code < 32)) control++;
  }
  return control / str.length < 0.1;
}
