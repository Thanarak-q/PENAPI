// Random Generator — DOM-free core. Produces UUIDs and random hex/base64/string
// values (nonces, cache-busters, test data) using the platform CSPRNG. Works in
// the browser and under `node --test` (both expose globalThis.crypto).

function randomBytes(n) {
  const arr = new Uint8Array(Math.max(0, n));
  crypto.getRandomValues(arr);
  return arr;
}

export function randomHex(byteLen = 16) {
  return [...randomBytes(byteLen)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export function randomToken(byteLen = 24) {
  // URL-safe token (base64url-ish over random bytes).
  return [...randomBytes(byteLen)].map((b) => B64[b & 63]).join('');
}

export function uuidv4() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant
  const hex = [...b].map((x) => x.toString(16).padStart(2, '0'));
  return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
}

export function randomString(len = 16, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
  if (!charset) return '';
  const bytes = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += charset[bytes[i] % charset.length];
  return out;
}
