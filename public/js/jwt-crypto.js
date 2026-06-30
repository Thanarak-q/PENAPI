// jwt-crypto.js — DOM-free JWT crypto primitives: base64url, HMAC, and
// asymmetric (RSA / ECDSA) sign+verify via Web Crypto, plus algorithm
// classification. Used by the JWT inspector UI and testable under `node --test`
// (Node exposes globalThis.crypto.subtle).

export const HASH = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
export const RSA_HASH = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' };
export const EC_PARAMS = {
  ES256: { hash: 'SHA-256', namedCurve: 'P-256' },
  ES384: { hash: 'SHA-384', namedCurve: 'P-384' },
};

export function algFamily(alg) {
  if (HASH[alg]) return 'HMAC';
  if (RSA_HASH[alg]) return 'RSA';
  if (EC_PARAMS[alg]) return 'EC';
  return null;
}

// ---- base64url ---------------------------------------------------------

export function b64urlDecode(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return decodeURIComponent(
    atob(b64).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  );
}

export function b64urlEncode(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlBytes(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlToBytes(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---- HMAC --------------------------------------------------------------

export async function hmacSig(secret, alg, signingInput) {
  if (!crypto.subtle) throw new Error('Web Crypto unavailable (needs https or localhost)');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: HASH[alg] }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput));
  return b64urlBytes(new Uint8Array(sig));
}

// ---- asymmetric (RSA / ECDSA) ------------------------------------------

// Decode a PEM block (private PKCS#8 or public SPKI) to an ArrayBuffer.
export function pemToArrayBuffer(pem) {
  const b64 = String(pem || '')
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!b64) throw new Error('no PEM key provided');
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function importParams(alg) {
  if (algFamily(alg) === 'RSA') return { name: 'RSASSA-PKCS1-v1_5', hash: RSA_HASH[alg] };
  return { name: 'ECDSA', namedCurve: EC_PARAMS[alg].namedCurve };
}

function signParams(alg) {
  if (algFamily(alg) === 'RSA') return 'RSASSA-PKCS1-v1_5';
  return { name: 'ECDSA', hash: EC_PARAMS[alg].hash };
}

export async function asymSign(alg, signingInput, pem) {
  if (!crypto.subtle) throw new Error('Web Crypto unavailable (needs https or localhost)');
  const key = await crypto.subtle.importKey('pkcs8', pemToArrayBuffer(pem), importParams(alg), false, ['sign']);
  const sig = await crypto.subtle.sign(signParams(alg), key, new TextEncoder().encode(signingInput));
  return b64urlBytes(new Uint8Array(sig));
}

export async function asymVerify(alg, signingInput, sigB64url, pem) {
  if (!crypto.subtle) throw new Error('Web Crypto unavailable (needs https or localhost)');
  const key = await crypto.subtle.importKey('spki', pemToArrayBuffer(pem), importParams(alg), false, ['verify']);
  return crypto.subtle.verify(signParams(alg), key, b64urlToBytes(sigB64url), new TextEncoder().encode(signingInput));
}
