// Pure PII / secret-exposure analyzer. LOG-DRIVEN — only scans ctx.records.
// Returns an array of finding spec objects (do NOT call makeFinding here);
// the orchestrator in static-analysis.js normalises them.

import { dedupeFindings, tryParseJson } from './shared.js';

// ---- pattern constants -------------------------------------------------------

const RE_EMAIL        = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
// Candidate card sequences: first digit + 11-21 chars (digits/spaces/dashes) + final digit.
// Separators are stripped and Luhn-validated before emitting.
const RE_CARD         = /\b\d[\d\s-]{11,21}\d\b/g;
const RE_SSN          = /\b\d{3}-\d{2}-\d{4}\b/g;
const RE_JWT          = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
const RE_AWS_AKIA     = /\bAKIA[0-9A-Z]{16}\b/g;
const RE_AWS_ASIA     = /\bASIA[0-9A-Z]{16}\b/g;
const RE_GOOGLE_KEY   = /\bAIza[0-9A-Za-z_-]{35}\b/g;
const RE_SLACK        = /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g;
const RE_PRIV_KEY     = /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g;
const RE_BEARER       = /bearer\s+[A-Za-z0-9._-]{16,}/gi;
const RE_IPV4         = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const RE_PHONE        = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/g;
const RE_SECRET_FIELD = /(secret|token|api[_-]?key|password|passwd|private[_-]?key|access[_-]?key)/i;

// Credential patterns checked when scanning request URL and body (subset 4-9).
const CRED_CHECKS = [
  { re: RE_JWT,        label: 'JWT' },
  { re: RE_AWS_AKIA,   label: 'AWS key (AKIA)' },
  { re: RE_AWS_ASIA,   label: 'AWS key (ASIA)' },
  { re: RE_GOOGLE_KEY, label: 'Google API key' },
  { re: RE_SLACK,      label: 'Slack token' },
  { re: RE_PRIV_KEY,   label: 'Private key' },
  { re: RE_BEARER,     label: 'Bearer token' },
];

// ---- utility helpers ---------------------------------------------------------

// Luhn check — returns true when the digit string passes.
function luhn(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Show at most 2 leading + 2 trailing chars with up to 10 stars in between.
function mask(s) {
  const str = String(s || '');
  if (str.length <= 4) return '***';
  return str.slice(0, 2) + '*'.repeat(Math.min(str.length - 4, 10)) + str.slice(-2);
}

// Retain only the @domain part of an email address.
function maskEmail(email) {
  const at = email.indexOf('@');
  if (at < 0) return mask(email);
  return '***' + email.slice(at);
}

// Show first 4 and last 4 digits of a card number.
function maskCard(digits) {
  return digits.slice(0, 4) + '*'.repeat(Math.max(1, digits.length - 8)) + digits.slice(-4);
}

// Cap body text to first 50 000 chars before scanning.
function cap(text) {
  return typeof text === 'string' ? text.slice(0, 50000) : '';
}

// Derive the canonical endpoint object from a record.
function endpointOf(record) {
  return record.endpoint || {
    method: record.method,
    path: record.path,
    id: record.method + ' ' + record.path,
  };
}

// Run a global regex against text; return all full-match strings.
// Clones the regex each call to avoid lastIndex state leaking.
function all(text, re) {
  return [...text.matchAll(new RegExp(re.source, re.flags))].map((m) => m[0]);
}

// Clip evidence strings to at most n chars.
function shorten(s, n = 80) {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

// Build a finding spec with the shared fields pre-filled.
function finding(sev, title, record, ev, action, cwe, confidence = 'firm') {
  return {
    sev,
    category: 'data',
    title,
    endpoint: endpointOf(record),
    evidence: shorten(ev),
    action,
    owasp: 'API3:2023',
    cwe,
    confidence,
  };
}

// ---- response-body detectors ------------------------------------------------

function scanEmails(text, record, out) {
  const hits = all(text, RE_EMAIL);
  if (!hits.length) return;
  const sample = maskEmail(hits[0]);
  const suffix = hits.length > 1 ? ` (${hits.length} matches)` : '';
  out.push(finding(
    'medium',
    'Email addresses in response body',
    record,
    `Email: ${sample}${suffix}`,
    'Mask or omit email addresses in API responses.',
    'CWE-359',
  ));
}

function scanCards(text, record, out) {
  const valid = [];
  for (const raw of all(text, RE_CARD)) {
    const digits = raw.replace(/[\s-]/g, '');
    if (digits.length >= 13 && digits.length <= 19 && /^\d+$/.test(digits) && luhn(digits)) {
      valid.push(digits);
    }
  }
  if (!valid.length) return;
  const suffix = valid.length > 1 ? ` (${valid.length} matches)` : '';
  out.push(finding(
    'high',
    'Luhn-valid card number in response body',
    record,
    `Card: ${maskCard(valid[0])}${suffix}`,
    'Never return raw card numbers. Use a payment tokenization service.',
    'CWE-312',
  ));
}

function scanSsn(text, record, out) {
  const hits = all(text, RE_SSN);
  if (!hits.length) return;
  const masked = '***-**-' + hits[0].slice(-4);
  const suffix = hits.length > 1 ? ` (${hits.length} matches)` : '';
  out.push(finding(
    'high',
    'US SSN pattern in response body',
    record,
    `SSN: ${masked}${suffix}`,
    'Remove SSNs from API responses. Return only the last 4 digits if display is required.',
    'CWE-359',
  ));
}

function scanJwt(text, record, out) {
  const hits = all(text, RE_JWT);
  if (!hits.length) return;
  out.push(finding(
    'high',
    'JWT present in response/log',
    record,
    `JWT: ${mask(hits[0])}`,
    'Do not return JWTs in response bodies. Issue once at auth and never re-expose.',
    'CWE-312',
  ));
}

function scanAwsKey(text, record, out) {
  for (const re of [RE_AWS_AKIA, RE_AWS_ASIA]) {
    const hits = all(text, re);
    if (!hits.length) continue;
    out.push(finding(
      'high',
      'AWS access key id exposed',
      record,
      `AWS key: ${mask(hits[0])}`,
      'Rotate the exposed AWS key immediately. Prefer IAM roles over static credentials.',
      'CWE-312',
    ));
  }
}

function scanGoogleKey(text, record, out) {
  const hits = all(text, RE_GOOGLE_KEY);
  if (!hits.length) return;
  out.push(finding(
    'high',
    'Google API key exposed',
    record,
    `Google key: ${mask(hits[0])}`,
    'Rotate the exposed Google API key and restrict it to required APIs and IP ranges.',
    'CWE-312',
  ));
}

function scanSlack(text, record, out) {
  const hits = all(text, RE_SLACK);
  if (!hits.length) return;
  out.push(finding(
    'high',
    'Slack token exposed',
    record,
    `Slack token: ${mask(hits[0])}`,
    'Revoke and rotate the Slack token immediately.',
    'CWE-312',
  ));
}

function scanPrivKey(text, record, out) {
  const hits = all(text, RE_PRIV_KEY);
  if (!hits.length) return;
  const plural = hits.length > 1 ? 'es' : '';
  out.push(finding(
    'high',
    'Private key material in response',
    record,
    `Private key header found (${hits.length} match${plural})`,
    'Remove private key material from API responses. Rotate the affected key pair immediately.',
    'CWE-312',
  ));
}

function scanBearer(text, record, out) {
  const hits = all(text, RE_BEARER);
  if (!hits.length) return;
  out.push(finding(
    'medium',
    'Bearer/Authorization token in response body',
    record,
    `Bearer token: ${mask(hits[0])}`,
    'Do not return bearer tokens in response bodies.',
    'CWE-312',
  ));
}

const IPV4_NOISE = new Set(['0.0.0.0', '127.0.0.1', '255.255.255.255']);

function scanIpv4(text, record, out) {
  const hits = all(text, RE_IPV4).filter((ip) => !IPV4_NOISE.has(ip));
  if (!hits.length) return;
  const suffix = hits.length > 1 ? ` (${hits.length} addresses)` : '';
  out.push(finding(
    'info',
    'IPv4 address in response body',
    record,
    `IPv4: ${hits[0]}${suffix}`,
    'Review whether internal IP addresses should be exposed in API responses.',
    'CWE-200',
    'tentative',
  ));
}

function scanPhone(text, record, out) {
  const hits = all(text, RE_PHONE);
  if (!hits.length) return;
  const masked = mask(hits[0].replace(/\D/g, ''));
  const suffix = hits.length > 1 ? ` (${hits.length} matches)` : '';
  out.push(finding(
    'low',
    'Phone number in response body',
    record,
    `Phone: ${masked}${suffix}`,
    'Mask phone numbers in API responses unless the caller has explicit access rights.',
    'CWE-359',
    'tentative',
  ));
}

function scanSecretFields(text, record, out) {
  const obj = tryParseJson(text);
  if (!obj || typeof obj !== 'object') return;

  const keys = [];

  function walk(o) {
    if (!o || typeof o !== 'object') return;
    if (Array.isArray(o)) { o.forEach(walk); return; }
    for (const [key, val] of Object.entries(o)) {
      if (
        RE_SECRET_FIELD.test(key) &&
        val !== null &&
        val !== undefined &&
        String(val).length >= 8
      ) {
        keys.push(key);
      }
      if (val && typeof val === 'object') walk(val);
    }
  }

  walk(obj);
  if (!keys.length) return;

  const label = keys[0];
  const extra = keys.length > 1 ? ` (+${keys.length - 1} more)` : '';
  out.push(finding(
    'low',
    'Secret-like field returned in response body',
    record,
    `Field: "${label}"${extra}`,
    'Ensure secret-like fields are stripped server-side before sending the response.',
    'CWE-312',
    'tentative',
  ));
}

// ---- credential scan for URL / reqBody (detectors 4-9 only) -----------------

function scanCredentials(text, record, out, where) {
  if (!text) return;
  const title = where === 'url'
    ? 'Credential value carried in request URL'
    : 'Credential value in request body';
  const cwe = where === 'url' ? 'CWE-598' : 'CWE-312';
  const action = where === 'url'
    ? 'Never embed credentials in the URL; use the Authorization header instead.'
    : 'Credentials should not appear in the request body unless required by the protocol.';

  for (const { re, label } of CRED_CHECKS) {
    const hits = all(text, re);
    if (!hits.length) continue;
    out.push({
      sev: 'high',
      category: 'data',
      title,
      endpoint: endpointOf(record),
      evidence: shorten(`${label}: ${mask(hits[0])}`),
      action,
      owasp: 'API3:2023',
      cwe,
      confidence: 'firm',
    });
  }
}

// ---- main export ------------------------------------------------------------

export function analyzePii(ctx) {
  const records = ctx.records;
  if (!Array.isArray(records) || records.length === 0) return [];

  const out = [];

  for (const record of records) {
    const resBody = cap(record.resBody);
    const reqBody = cap(record.reqBody);
    const url     = String(record.url || '');

    // Primary: all detectors against the response body.
    if (resBody) {
      scanEmails(resBody, record, out);
      scanCards(resBody, record, out);
      scanSsn(resBody, record, out);
      scanJwt(resBody, record, out);
      scanAwsKey(resBody, record, out);
      scanGoogleKey(resBody, record, out);
      scanSlack(resBody, record, out);
      scanPrivKey(resBody, record, out);
      scanBearer(resBody, record, out);
      scanIpv4(resBody, record, out);
      scanPhone(resBody, record, out);
      scanSecretFields(resBody, record, out);
    }

    // Secondary: credential-class patterns only against request URL and body.
    if (url)     scanCredentials(url,     record, out, 'url');
    if (reqBody) scanCredentials(reqBody, record, out, 'reqBody');
  }

  return dedupeFindings(out);
}
