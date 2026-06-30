import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeBusinessFlows } from '../public/js/analyzers/business-flows.js';

// ---- factory ----------------------------------------------------------------

function endpoint(overrides = {}) {
  return {
    id: `${overrides.method || 'GET'} ${overrides.path || '/health'}`,
    method: overrides.method || 'GET',
    path: overrides.path || '/health',
    operationId: overrides.operationId ?? null,
    summary: overrides.summary || '',
    description: overrides.description || '',
    tags: overrides.tags || [],
    deprecated: !!overrides.deprecated,
    params: {
      path: [],
      query: [],
      header: [],
      cookie: [],
      ...(overrides.params || {}),
    },
    body: overrides.body || null,
    security: overrides.security ?? [],
  };
}

function ctx(endpoints) {
  return { endpoints };
}

// ---- check 1: payment / money movement --------------------------------------

test('POST /checkout emits medium payment finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/checkout' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Sensitive payment/money-movement flow — verify anti-automation'),
    'expected payment finding for POST /checkout'
  );
  const found = findings.find((f) => f.title === 'Sensitive payment/money-movement flow — verify anti-automation');
  assert.equal(found.sev, 'medium');
  assert.equal(found.owasp, 'API6:2023');
  assert.equal(found.cwe, 'CWE-799');
  assert.equal(found.confidence, 'tentative');
  assert.equal(found.category, 'security');
});

test('GET /checkout does not emit payment finding (non-mutating)', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/checkout' }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Sensitive payment/money-movement flow — verify anti-automation'),
    'GET /checkout should not emit payment finding'
  );
});

test('POST /payments/transfer emits payment finding via path', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/payments/transfer' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Sensitive payment/money-movement flow — verify anti-automation'),
    'expected payment finding for /payments/transfer'
  );
});

// ---- check 2: discount / promo abuse ----------------------------------------

test('POST /coupons/redeem emits low promo finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/coupons/redeem' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Promo/coupon flow — verify abuse & enumeration controls'),
    'expected promo finding for /coupons/redeem'
  );
  const found = findings.find((f) => f.title === 'Promo/coupon flow — verify abuse & enumeration controls');
  assert.equal(found.sev, 'low');
  assert.equal(found.cwe, 'CWE-799');
});

test('GET /promo/apply also emits promo finding (no mutating requirement)', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/promo/apply' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Promo/coupon flow — verify abuse & enumeration controls'),
    'GET promo endpoint should still emit promo finding'
  );
});

// ---- check 3: booking / inventory reservation -------------------------------

test('POST /bookings emits low reservation finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/bookings' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Reservation/inventory flow — verify hold limits & race conditions'),
    'expected reservation finding for POST /bookings'
  );
  const found = findings.find((f) => f.title === 'Reservation/inventory flow — verify hold limits & race conditions');
  assert.equal(found.sev, 'low');
  assert.equal(found.owasp, 'API6:2023');
  assert.equal(found.cwe, 'CWE-799');
});

test('GET /bookings does not emit reservation finding (non-mutating)', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/bookings' }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Reservation/inventory flow — verify hold limits & race conditions'),
    'GET /bookings should not emit reservation finding'
  );
});

// ---- check 4: account-security flow -----------------------------------------

test('POST /account/change-password emits medium account-security finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/account/change-password' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Account-security flow — verify step-up re-authentication & rate limiting'),
    'expected account-security finding'
  );
  const found = findings.find(
    (f) => f.title === 'Account-security flow — verify step-up re-authentication & rate limiting'
  );
  assert.equal(found.sev, 'medium');
  assert.equal(found.cwe, 'CWE-306');
  assert.equal(found.owasp, 'API6:2023');
});

test('GET /forgot-password emits account-security finding (no mutating requirement)', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/forgot-password' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Account-security flow — verify step-up re-authentication & rate limiting'),
    'expected account-security finding for /forgot-password'
  );
});

test('DELETE /account/mfa endpoint emits account-security finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'DELETE', path: '/account/mfa', operationId: 'disableMfa' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Account-security flow — verify step-up re-authentication & rate limiting'),
    'expected account-security finding for MFA disable'
  );
});

// ---- check 5: voting / rating / social abuse --------------------------------

test('POST /posts/{id}/vote emits info engagement finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/posts/{id}/vote' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Engagement/voting flow — verify per-identity limits'),
    'expected engagement finding for /posts/{id}/vote'
  );
  const found = findings.find((f) => f.title === 'Engagement/voting flow — verify per-identity limits');
  assert.equal(found.sev, 'info');
  assert.equal(found.cwe, 'CWE-799');
});

test('GET /ratings does not emit engagement finding (non-mutating)', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/ratings' }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Engagement/voting flow — verify per-identity limits'),
    'GET /ratings should not emit engagement finding'
  );
});

// ---- check 6: bulk-purchase / scalping signal --------------------------------

test('POST /orders with quantity body key emits scalping finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({
      method: 'POST',
      path: '/orders',
      body: {
        contentType: 'application/json',
        required: true,
        example: { product_id: 'abc', quantity: 10 },
      },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Quantity-bearing purchase flow — verify max-per-order & scalping controls'),
    'expected scalping finding for /orders with quantity body'
  );
  const found = findings.find(
    (f) => f.title === 'Quantity-bearing purchase flow — verify max-per-order & scalping controls'
  );
  assert.equal(found.sev, 'low');
  assert.equal(found.cwe, 'CWE-799');
});

test('POST /checkout with qty query param emits scalping finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({
      method: 'POST',
      path: '/checkout',
      params: { query: [{ name: 'qty', in: 'query', required: false, description: '' }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Quantity-bearing purchase flow — verify max-per-order & scalping controls'),
    'expected scalping finding for /checkout with qty param'
  );
});

test('POST /orders without quantity param does not emit scalping finding', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/orders' }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Quantity-bearing purchase flow — verify max-per-order & scalping controls'),
    'no quantity param → no scalping finding'
  );
});

// ---- boring endpoint: no findings -------------------------------------------

test('GET /health emits no business-flow findings', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'GET', path: '/health' }),
  ]));
  assert.equal(findings.length, 0, 'expected no findings for GET /health');
});

// ---- edge cases -------------------------------------------------------------

test('returns empty array when ctx has no endpoints', () => {
  assert.deepEqual(analyzeBusinessFlows({}), []);
  assert.deepEqual(analyzeBusinessFlows({ endpoints: [] }), []);
  assert.deepEqual(analyzeBusinessFlows(null), []);
});

// ---- cross-cutting: all findings carry correct metadata ---------------------

test('all findings carry category security and owasp API6:2023', () => {
  const findings = analyzeBusinessFlows(ctx([
    endpoint({ method: 'POST', path: '/checkout' }),
    endpoint({ method: 'POST', path: '/coupons/redeem' }),
    endpoint({ method: 'POST', path: '/bookings' }),
    endpoint({ method: 'POST', path: '/account/change-password' }),
    endpoint({ method: 'POST', path: '/posts/{id}/vote' }),
    endpoint({
      method: 'POST',
      path: '/orders',
      body: { contentType: 'application/json', required: true, example: { quantity: 2 } },
    }),
  ]));
  assert.ok(findings.length > 0, 'expected at least one finding');
  for (const f of findings) {
    assert.equal(f.owasp, 'API6:2023', `finding "${f.title}" should reference API6:2023`);
    assert.equal(f.category, 'security', `finding "${f.title}" should have category 'security'`);
    assert.equal(f.confidence, 'tentative', `finding "${f.title}" should have confidence 'tentative'`);
  }
});
