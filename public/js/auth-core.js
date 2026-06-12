// Auth Builder — pure, DOM-free core. Constructs and parses Authorization
// header values. Reuses the Decoder's Base64 so behavior matches and stays
// unit-tested. DOM-free for `node --test`.

import { base64Encode, base64Decode } from './decoder-core.js';

// Build "Basic <base64(user:pass)>".
export function buildBasic(user, pass) {
  return 'Basic ' + base64Encode(`${user ?? ''}:${pass ?? ''}`);
}

// Build "Bearer <token>".
export function buildBearer(token) {
  return 'Bearer ' + String(token ?? '').trim();
}

// Decode a "Basic ..." header back to { user, pass }, or null if not Basic.
export function parseBasic(header) {
  const m = /^\s*Basic\s+(\S+)\s*$/i.exec(String(header || ''));
  if (!m) return null;
  const decoded = base64Decode(m[1]);
  const i = decoded.indexOf(':');
  if (i === -1) return { user: decoded, pass: '' };
  return { user: decoded.slice(0, i), pass: decoded.slice(i + 1) };
}
