import test from 'node:test';
import assert from 'node:assert/strict';

import { randomHex, randomToken, uuidv4, randomString } from '../public/js/random-core.js';

test('randomHex returns 2 hex chars per byte', () => {
  const h = randomHex(8);
  assert.equal(h.length, 16);
  assert.match(h, /^[0-9a-f]+$/);
});

test('uuidv4 matches the canonical UUID v4 shape', () => {
  assert.match(uuidv4(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('randomToken is URL-safe and the requested length', () => {
  const t = randomToken(24);
  assert.equal(t.length, 24);
  assert.match(t, /^[A-Za-z0-9_-]+$/);
});

test('randomString honors length and charset', () => {
  const s = randomString(32, 'ab');
  assert.equal(s.length, 32);
  assert.match(s, /^[ab]+$/);
  assert.equal(randomString(10, ''), '');
});

test('successive values differ (CSPRNG sanity)', () => {
  assert.notEqual(uuidv4(), uuidv4());
  assert.notEqual(randomHex(16), randomHex(16));
});
