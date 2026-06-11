// JWT inspector + tamperer. Decode/edit happens entirely in the browser.

import { $, toast, copy } from './util.js';
import { state, identityHeaders } from './state.js';

export function initJwt() {
  $('#jwtBtn').addEventListener('click', () => {
    $('#jwtModal').hidden = false;
  });
  $('#closeJwt').addEventListener('click', () => ($('#jwtModal').hidden = true));
  $('#jwtInput').addEventListener('input', decode);
  $('#jwtLoadActive').addEventListener('click', loadActive);
  $('#jwtForgeNone').addEventListener('click', forgeNone);
  $('#jwtCopy').addEventListener('click', copyRebuilt);
}

function b64urlDecode(str) {
  const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return decodeURIComponent(
    atob(b64)
      .split('')
      .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('')
  );
}

function b64urlEncode(str) {
  return btoa(unescape(encodeURIComponent(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function decode() {
  const token = $('#jwtInput').value.trim();
  $('#jwtMeta').textContent = '';
  if (!token) {
    $('#jwtHeader').value = '';
    $('#jwtPayload').value = '';
    return;
  }
  const parts = token.replace(/^Bearer\s+/i, '').split('.');
  if (parts.length < 2) {
    $('#jwtMeta').textContent = 'Not a JWT (need header.payload.signature).';
    return;
  }
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const payload = JSON.parse(b64urlDecode(parts[1]));
    $('#jwtHeader').value = JSON.stringify(header, null, 2);
    $('#jwtPayload').value = JSON.stringify(payload, null, 2);
    renderMeta(header, payload);
  } catch (e) {
    $('#jwtMeta').textContent = 'Decode failed: ' + e.message;
  }
}

function renderMeta(header, payload) {
  const bits = [`alg: ${header.alg}`];
  if (payload.exp) {
    const d = new Date(payload.exp * 1000);
    const expired = d < new Date();
    bits.push(`exp: ${d.toISOString()}${expired ? ' (EXPIRED)' : ''}`);
  }
  if (payload.iat) bits.push(`iat: ${new Date(payload.iat * 1000).toISOString()}`);
  for (const k of ['sub', 'role', 'roles', 'scope', 'scopes', 'admin', 'isAdmin', 'aud']) {
    if (payload[k] !== undefined) bits.push(`${k}: ${JSON.stringify(payload[k])}`);
  }
  if (header.alg && header.alg.toLowerCase() === 'none') {
    bits.push('⚠ alg:none — unsigned');
  }
  $('#jwtMeta').textContent = bits.join('  ·  ');
}

function loadActive() {
  const headers = identityHeaders();
  const authKey = Object.keys(headers).find((k) => k.toLowerCase() === 'authorization');
  const val = authKey ? headers[authKey] : null;
  if (!val || val === null) {
    return toast('Active identity has no Authorization header', true);
  }
  $('#jwtInput').value = String(val).replace(/^Bearer\s+/i, '');
  decode();
}

// Rebuild a token from the edited header+payload (signature left empty).
function rebuild(forceNone) {
  let header, payload;
  try {
    header = JSON.parse($('#jwtHeader').value || '{}');
    payload = JSON.parse($('#jwtPayload').value || '{}');
  } catch (e) {
    toast('Header/payload is not valid JSON', true);
    return null;
  }
  if (forceNone) header.alg = 'none';
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}.`;
}

function forgeNone() {
  const token = rebuild(true);
  if (!token) return;
  $('#jwtHeader').value = JSON.stringify({ ...JSON.parse($('#jwtHeader').value || '{}'), alg: 'none' }, null, 2);
  copy(token);
  toast('alg:none token copied');
}

function copyRebuilt() {
  const token = rebuild(false);
  if (token) copy(token);
}
