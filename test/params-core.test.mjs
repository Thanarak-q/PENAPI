import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseQuery,
  classifyParam,
  analyzeParams,
} from '../public/js/params-core.js';

test('parseQuery strips scheme/host and splits pairs', () => {
  const ps = parseQuery('https://x.com/a?id=5&next=/home#frag');
  assert.deepEqual(ps, [
    { name: 'id', value: '5' },
    { name: 'next', value: '/home' },
  ]);
});

test('parseQuery URL-decodes names and values', () => {
  const ps = parseQuery('?q=hello%20world&a%2Bb=1');
  assert.equal(ps[0].value, 'hello world');
  assert.equal(ps[1].name, 'a+b');
});

test('classifies redirect-like params as open-redirect', () => {
  const c = classifyParam({ name: 'returnUrl', value: '/dashboard' });
  assert.ok(c.categories.some((x) => x.category === 'open-redirect'));
});

test('classifies a numeric id as idor', () => {
  const c = classifyParam({ name: 'user_id', value: '1001' });
  assert.ok(c.categories.some((x) => x.category === 'idor'));
});

test('value heuristic catches a URL value under a generic name', () => {
  const c = classifyParam({ name: 'data', value: 'https://internal/admin' });
  assert.ok(c.categories.some((x) => x.category === 'ssrf'));
});

test('detects a JWT-looking value as auth-secret', () => {
  const c = classifyParam({ name: 'x', value: 'eyJhbGciOiJIUzI1Ni00.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT' });
  assert.ok(c.categories.some((x) => x.category === 'auth-secret'));
});

test('flags an existing traversal sequence in the value', () => {
  const c = classifyParam({ name: 'page', value: '../../etc/passwd' });
  assert.ok(c.categories.some((x) => x.category === 'path-traversal'));
});

test('analyzeParams sorts most-interesting params first', () => {
  const out = analyzeParams('?boring=hi&url=https://evil.com');
  assert.equal(out[0].name, 'url');
  assert.ok(out[0].categories.length >= out[out.length - 1].categories.length);
});

test('empty query yields no params', () => {
  assert.deepEqual(analyzeParams('https://x.com/path'), []);
});
