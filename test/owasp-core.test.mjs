import test from 'node:test';
import assert from 'node:assert/strict';

import { classify, enrich, owaspLabel, OWASP_API } from '../public/js/analyzers/owasp.js';

test('preserves an analyzer-supplied owasp/cwe instead of re-classifying', () => {
  const f = { category: 'data', title: 'whatever', owasp: 'API3:2023', cwe: 'CWE-312' };
  assert.deepEqual(classify(f), { owasp: 'API3:2023', cwe: 'CWE-312' });
});

test('classifies plaintext-credential findings as API2 (transport)', () => {
  const f = { category: 'security', title: 'Credentials may be sent over plaintext HTTP', evidence: 'http://staging.example/v1' };
  const { owasp, cwe } = classify(f);
  assert.equal(owasp, 'API2:2023');
  assert.equal(cwe, 'CWE-319');
});

test('ignores incidental keywords in evidence when classifying', () => {
  // Evidence mentions "staging" (an API9 keyword) but the finding is an IDOR.
  const f = { category: 'idor', title: 'Object identifier in path', evidence: 'id on staging host' };
  assert.equal(classify(f).owasp, 'API1:2023');
});

test('classifies common categories sensibly', () => {
  assert.equal(classify({ category: 'config', title: 'CORS allows any origin' }).owasp, 'API8:2023');
  assert.equal(classify({ category: 'inventory', title: 'Older API version still exposed' }).owasp, 'API9:2023');
  assert.equal(classify({ category: 'resource', title: 'Bulk/batch operation may amplify resource use' }).owasp, 'API4:2023');
  assert.equal(classify({ category: 'security', title: 'JWT without expiry' }).owasp, 'API2:2023');
});

test('returns empty mapping when nothing matches', () => {
  assert.deepEqual(classify({ category: 'quality', title: 'Missing operationId' }), { owasp: '', cwe: '' });
});

test('enrich fills owasp/cwe immutably and leaves the original untouched', () => {
  const original = { category: 'config', title: 'CORS allows any origin', owasp: '', cwe: '' };
  const enriched = enrich(original);
  assert.equal(enriched.owasp, 'API8:2023');
  assert.equal(original.owasp, '');
  assert.notEqual(enriched, original);
});

test('owaspLabel produces a short badge string', () => {
  assert.equal(owaspLabel('API8:2023'), 'API8 Misconfig');
  assert.equal(owaspLabel(''), '');
  assert.ok(Object.keys(OWASP_API).length === 10);
});
