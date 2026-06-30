import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeCsrfRisk } from '../public/js/analyzers/csrf-risk.js';
import { eachHistory } from '../public/js/analyzers/shared.js';

// ---- helpers -----------------------------------------------------------------

function entry({
  url = 'https://api.example.test/api/data',
  method = 'POST',
  reqHeaders = {},
  reqBody = '',
  resHeaders = {},
  resBody = '',
  status = 200,
} = {}) {
  return {
    request: { method, url, headers: reqHeaders, body: reqBody },
    response: { status, headers: resHeaders, body: resBody },
  };
}

function makeCtx(entries = []) {
  return {
    spec: {},
    endpoints: [],
    securitySchemes: {},
    history: entries,
    records: eachHistory(entries, []),
  };
}

function titles(findings) {
  return findings.map(f => f.title);
}

// ---- primary finding: JSON body, no token ------------------------------------

test('POST with Cookie + JSON body and no CSRF token emits medium primary finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=s3cr3tv4lu3; Path=/',
        'content-type': 'application/json',
      },
      reqBody: JSON.stringify({ username: 'alice', action: 'delete' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(
    titles(findings).includes('State-changing request authenticated by cookie without CSRF token'),
    'primary title expected',
  );
  const f = findings.find(x => x.title === 'State-changing request authenticated by cookie without CSRF token');
  assert.equal(f.sev, 'medium');
  assert.equal(f.category, 'security');
  assert.equal(f.owasp, 'API8:2023');
  assert.equal(f.cwe, 'CWE-352');
  assert.equal(f.confidence, 'firm');
  assert.ok(f.evidence.includes('POST'), 'evidence should include method');
  assert.ok(f.evidence.includes('application/json'), 'evidence should include content-type');
  // Cookie value must never appear in evidence
  assert.ok(!f.evidence.includes('s3cr3tv4lu3'), 'cookie value must not appear in evidence');
});

// ---- simple-request escalation: form-urlencoded ------------------------------

test('POST with Cookie + form-urlencoded body and no CSRF token emits simple-request finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      url: 'https://api.example.test/api/transfer',
      reqHeaders: {
        'cookie': 'auth=mys3ss10nval; SameSite=Lax',
        'content-type': 'application/x-www-form-urlencoded',
      },
      reqBody: 'amount=1000&to=attacker',
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(
    titles(findings).includes('CSRF-able simple request (no preflight content-type)'),
    'simple-request title expected',
  );
  const f = findings.find(x => x.title === 'CSRF-able simple request (no preflight content-type)');
  assert.equal(f.sev, 'medium');
  assert.equal(f.category, 'security');
  assert.equal(f.owasp, 'API8:2023');
  assert.equal(f.cwe, 'CWE-352');
  assert.equal(f.confidence, 'firm');
  assert.ok(f.evidence.includes('application/x-www-form-urlencoded'), 'content-type in evidence');
  assert.ok(!f.evidence.includes('mys3ss10nval'), 'cookie value must not appear in evidence');
  // Should NOT also emit the primary finding for the same record
  assert.ok(
    !titles(findings).includes('State-changing request authenticated by cookie without CSRF token'),
    'primary finding must not double-fire for simple content-type',
  );
});

// ---- no finding: real CSRF token in header -----------------------------------

test('POST with Cookie + X-CSRF-Token header produces NO finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'application/json',
        'x-csrf-token': 'rand0mt0k3n',
      },
      reqBody: JSON.stringify({ action: 'update' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, 'x-csrf-token header should suppress all findings');
});

// ---- no finding: CSRF field in JSON body (_csrf) ----------------------------

test('POST with Cookie + _csrf field in JSON body produces NO finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'application/json',
      },
      reqBody: JSON.stringify({ _csrf: 'tok', data: 'value' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, '_csrf body field should suppress all findings');
});

// ---- no finding: Authorization: Bearer (token auth, not CSRF-able) ----------

test('POST with Authorization Bearer + Cookie produces NO finding (bearer not browser-auto-attached)', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'authorization': 'Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig',
        'content-type': 'application/json',
      },
      reqBody: JSON.stringify({ action: 'delete' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, 'bearer token auth makes request non-CSRF-able');
});

// ---- no finding: GET with Cookie (not state-changing) -----------------------

test('GET with Cookie produces NO finding (GET is not state-changing)', () => {
  const ctx = makeCtx([
    entry({
      method: 'GET',
      url: 'https://api.example.test/api/profile',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
      },
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, 'GET is not a mutating method');
});

// ---- weak defense: only X-Requested-With ------------------------------------

test('POST with Cookie + only X-Requested-With emits low tentative weak-defense finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=weakdefense; Path=/',
        'content-type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      },
      reqBody: JSON.stringify({ action: 'update' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(
    titles(findings).includes('CSRF defense relies only on X-Requested-With'),
    'weak-defense title expected',
  );
  const f = findings.find(x => x.title === 'CSRF defense relies only on X-Requested-With');
  assert.equal(f.sev, 'low');
  assert.equal(f.category, 'security');
  assert.equal(f.owasp, 'API8:2023');
  assert.equal(f.cwe, 'CWE-352');
  assert.equal(f.confidence, 'tentative');
  assert.ok(!f.evidence.includes('weakdefense'), 'cookie value must not appear in evidence');
});

// ---- empty records -----------------------------------------------------------

test('empty records returns empty array', () => {
  assert.deepEqual(analyzeCsrfRisk({ records: [], securitySchemes: {} }), []);
  assert.deepEqual(analyzeCsrfRisk({}), []);
  assert.deepEqual(analyzeCsrfRisk(makeCtx([])), []);
});

// ---- x-api-key disqualifies CSRF risk ----------------------------------------

test('POST with Cookie + x-api-key header produces NO finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'DELETE',
      url: 'https://api.example.test/api/resource/42',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'x-api-key': 'supersecretapikey',
        'content-type': 'application/json',
      },
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, 'x-api-key makes request non-CSRF-able');
});

// ---- simple content-type: absent (no content-type header) -------------------

test('POST with Cookie and no content-type header emits simple-request finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'PUT',
      url: 'https://api.example.test/api/settings',
      reqHeaders: {
        'cookie': 'session=noctype; Path=/',
      },
      reqBody: 'some body',
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(
    titles(findings).includes('CSRF-able simple request (no preflight content-type)'),
    'absent content-type should be treated as simple',
  );
  const f = findings.find(x => x.title === 'CSRF-able simple request (no preflight content-type)');
  assert.ok(f.evidence.includes('(no content-type)'), 'evidence should note absent content-type');
  assert.ok(!f.evidence.includes('noctype'), 'cookie value must not appear in evidence');
});

// ---- CSRF field in query string suppresses finding ---------------------------

test('POST with Cookie + csrf_token query param produces NO finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      url: 'https://api.example.test/api/action?csrf_token=abc123',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'application/json',
      },
      reqBody: JSON.stringify({ data: 'value' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.equal(findings.length, 0, 'csrf_token query param should suppress findings');
});

// ---- DELETE is also a mutating method ----------------------------------------

test('DELETE with Cookie + JSON body and no CSRF token emits primary finding', () => {
  const ctx = makeCtx([
    entry({
      method: 'DELETE',
      url: 'https://api.example.test/api/account/99',
      reqHeaders: {
        'cookie': 'session=delsession; Path=/',
        'content-type': 'application/json',
      },
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(
    titles(findings).includes('State-changing request authenticated by cookie without CSRF token'),
    'DELETE should also be flagged',
  );
  const f = findings.find(x => x.title === 'State-changing request authenticated by cookie without CSRF token');
  assert.ok(f.evidence.includes('DELETE'), 'evidence should include method');
  assert.ok(!f.evidence.includes('delsession'), 'cookie value must not appear in evidence');
});

// ---- cross-cutting: all findings carry required metadata --------------------

test('all emitted findings carry category "security", owasp "API8:2023", cwe "CWE-352"', () => {
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'application/json',
      },
      reqBody: JSON.stringify({ action: 'submit' }),
    }),
    entry({
      method: 'PUT',
      url: 'https://api.example.test/api/upload',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'multipart/form-data; boundary=----boundary',
      },
      reqBody: '----boundary\r\nContent-Disposition: form-data; name="file"\r\n\r\ndata',
    }),
    entry({
      method: 'PATCH',
      url: 'https://api.example.test/api/prefs',
      reqHeaders: {
        'cookie': 'session=abc; Path=/',
        'content-type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      },
      reqBody: JSON.stringify({ theme: 'dark' }),
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(findings.length > 0, 'should produce findings');
  for (const f of findings) {
    assert.equal(f.category, 'security', `"${f.title}" must have category "security"`);
    assert.equal(f.owasp, 'API8:2023', `"${f.title}" must have owasp "API8:2023"`);
    assert.equal(f.cwe, 'CWE-352', `"${f.title}" must have cwe "CWE-352"`);
  }
});

// ---- masking: no cookie value ever appears in any evidence ------------------

test('no finding evidence ever contains a raw cookie value', () => {
  const SECRET_COOKIE = 'verysecretcookievalue99';
  const ctx = makeCtx([
    entry({
      method: 'POST',
      reqHeaders: {
        'cookie': `session=${SECRET_COOKIE}; Path=/`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      reqBody: 'field=value',
    }),
    entry({
      method: 'DELETE',
      url: 'https://api.example.test/api/item/1',
      reqHeaders: {
        'cookie': `token=${SECRET_COOKIE}; HttpOnly`,
        'content-type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      },
    }),
  ]);
  const findings = analyzeCsrfRisk(ctx);
  assert.ok(findings.length > 0, 'should have findings for these requests');
  for (const f of findings) {
    assert.ok(
      !String(f.evidence).includes(SECRET_COOKIE),
      `finding "${f.title}" must not expose raw cookie value in evidence`,
    );
  }
});
