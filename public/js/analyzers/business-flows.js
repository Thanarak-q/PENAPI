// Passive analyzer for API6:2023 — Unrestricted Access to Sensitive Business Flows.
//
// Pure module: receives a ctx object and returns an array of finding-spec objects.
// The orchestrator calls makeFinding on each spec; do NOT call it here.
//
// ctx = { spec, endpoints, securitySchemes, history, records }
// This analyzer is endpoint-driven: it uses ctx.endpoints only.

import { MUTATING } from './shared.js';

// ---- named regex constants --------------------------------------------------

const PAYMENT_RE     = /(payment|checkout|purchase|order|pay\b|billing|charge|invoice|transfer|withdraw|topup|top-up|deposit|payout|refund)/i;
const PROMO_RE       = /(coupon|promo|voucher|discount|gift[_-]?card|reward|loyalty|referral|invite|credit)/i;
const BOOKING_RE     = /(booking|reservation|reserve|seat|ticket|slot|appointment|stock|inventory)/i;
const ACCOUNT_SEC_RE = /(change[_-]?password|reset[_-]?password|forgot|email[_-]?change|change[_-]?email|update[_-]?email|2fa|mfa|disable[_-]?mfa|delete[_-]?account|deactivate|close[_-]?account)/i;
const SOCIAL_RE      = /(vote|like|rating|review|follow|subscribe|comment|poll)/i;
const QUANTITY_RE    = /(qty|quantity|amount|count|units)/i;

// ---- helpers ----------------------------------------------------------------

// True when re matches the endpoint's path, operationId, or summary.
function matchAny(re, ep) {
  return re.test(ep.path || '') || re.test(ep.operationId || '') || re.test(ep.summary || '');
}

// Collect all keys (at every level) from a plain object or array.
function collectKeys(value, out = []) {
  if (!value || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, out);
    return out;
  }
  for (const [key, child] of Object.entries(value)) {
    out.push(key);
    collectKeys(child, out);
  }
  return out;
}

// True when the endpoint exposes a quantity-like query param or body example key.
function hasQuantityParam(ep) {
  const queryParams = ep.params?.query || [];
  if (queryParams.some((p) => QUANTITY_RE.test(p.name || ''))) return true;
  if (ep.body?.example != null) {
    return collectKeys(ep.body.example).some((k) => QUANTITY_RE.test(k));
  }
  return false;
}

// ---- main export ------------------------------------------------------------

export function analyzeBusinessFlows(ctx) {
  const endpoints = Array.isArray(ctx?.endpoints) ? ctx.endpoints : [];
  const findings = [];

  for (const ep of endpoints) {
    const method = ep.method || 'GET';
    const isMutating = MUTATING.has(method);

    // 1. Payment / money movement
    if (matchAny(PAYMENT_RE, ep) && isMutating) {
      findings.push({
        sev: 'medium',
        category: 'security',
        title: 'Sensitive payment/money-movement flow — verify anti-automation',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Test for missing rate limiting, idempotency keys, replay/race conditions, and step-up auth.',
        owasp: 'API6:2023',
        cwe: 'CWE-799',
        confidence: 'tentative',
      });
    }

    // 2. Discount / promo abuse (no mutating requirement — GET redemption flows exist)
    if (matchAny(PROMO_RE, ep)) {
      findings.push({
        sev: 'low',
        category: 'security',
        title: 'Promo/coupon flow — verify abuse & enumeration controls',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Test bulk redemption, code enumeration, and per-account limits.',
        owasp: 'API6:2023',
        cwe: 'CWE-799',
        confidence: 'tentative',
      });
    }

    // 3. Booking / inventory reservation
    if (matchAny(BOOKING_RE, ep) && isMutating) {
      findings.push({
        sev: 'low',
        category: 'security',
        title: 'Reservation/inventory flow — verify hold limits & race conditions',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Test maximum hold counts per user, race-condition seat conflicts, and expiry enforcement.',
        owasp: 'API6:2023',
        cwe: 'CWE-799',
        confidence: 'tentative',
      });
    }

    // 4. Account-security flow (needs re-auth; no mutating requirement)
    if (matchAny(ACCOUNT_SEC_RE, ep)) {
      findings.push({
        sev: 'medium',
        category: 'security',
        title: 'Account-security flow — verify step-up re-authentication & rate limiting',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Confirm current-password/OTP re-auth, rate limiting, and notification on change.',
        owasp: 'API6:2023',
        cwe: 'CWE-306',
        confidence: 'tentative',
      });
    }

    // 5. Voting / rating / social abuse
    if (matchAny(SOCIAL_RE, ep) && isMutating) {
      findings.push({
        sev: 'info',
        category: 'security',
        title: 'Engagement/voting flow — verify per-identity limits',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Test per-user/IP vote limits, duplicate detection, and cooldown enforcement.',
        owasp: 'API6:2023',
        cwe: 'CWE-799',
        confidence: 'tentative',
      });
    }

    // 6. Bulk-purchase / scalping signal: payment endpoint that also carries a quantity param
    if (matchAny(PAYMENT_RE, ep) && isMutating && hasQuantityParam(ep)) {
      findings.push({
        sev: 'low',
        category: 'security',
        title: 'Quantity-bearing purchase flow — verify max-per-order & scalping controls',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Verify per-order quantity caps, per-account purchase limits, and velocity controls.',
        owasp: 'API6:2023',
        cwe: 'CWE-799',
        confidence: 'tentative',
      });
    }
  }

  return findings;
}
