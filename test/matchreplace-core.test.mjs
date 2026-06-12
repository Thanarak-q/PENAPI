import test from 'node:test';
import assert from 'node:assert/strict';

import { applyRules, activeRuleCount } from '../public/js/matchreplace-core.js';

const base = () => ({
  method: 'POST',
  url: 'https://api.test/v1/users',
  headers: { 'Content-Type': 'application/json' },
  body: '{"role":"user"}',
});

test('disabled rules are ignored', () => {
  const out = applyRules(base(), [{ enabled: false, target: 'body', match: 'user', replace: 'admin' }]);
  assert.equal(out.body, '{"role":"user"}');
});

test('literal body replace swaps every occurrence', () => {
  const out = applyRules(base(), [{ enabled: true, target: 'body', match: 'user', replace: 'admin' }]);
  assert.equal(out.body, '{"role":"admin"}');
});

test('regex url replace rewrites the version segment', () => {
  const out = applyRules(base(), [{ enabled: true, target: 'url', match: '/v1/', replace: '/v2/', regex: true }]);
  assert.equal(out.url, 'https://api.test/v2/users');
});

test('header rule sets a new header', () => {
  const out = applyRules(base(), [{ enabled: true, target: 'header', match: 'X-Forwarded-For', replace: '127.0.0.1' }]);
  assert.equal(out.headers['X-Forwarded-For'], '127.0.0.1');
});

test('header rule with empty replace removes the header', () => {
  const out = applyRules(base(), [{ enabled: true, target: 'header', match: 'Content-Type', replace: '' }]);
  assert.equal('Content-Type' in out.headers, false);
});

test('invalid regex leaves the text unchanged instead of throwing', () => {
  const out = applyRules(base(), [{ enabled: true, target: 'body', match: '(', replace: 'x', regex: true }]);
  assert.equal(out.body, '{"role":"user"}');
});

test('input request is not mutated', () => {
  const req = base();
  applyRules(req, [{ enabled: true, target: 'header', match: 'X', replace: 'y' }]);
  assert.equal('X' in req.headers, false);
});

test('activeRuleCount counts only enabled rules with a match', () => {
  assert.equal(activeRuleCount([
    { enabled: true, target: 'url', match: 'a' },
    { enabled: false, target: 'url', match: 'b' },
    { enabled: true, target: 'url', match: '' },
  ]), 1);
});
