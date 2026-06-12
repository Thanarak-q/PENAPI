import test from 'node:test';
import assert from 'node:assert/strict';

import { buildBasic, buildBearer, parseBasic } from '../public/js/auth-core.js';

test('buildBasic base64-encodes user:pass', () => {
  // base64("alice:secret") = YWxpY2U6c2VjcmV0
  assert.equal(buildBasic('alice', 'secret'), 'Basic YWxpY2U6c2VjcmV0');
});

test('buildBearer trims and prefixes the token', () => {
  assert.equal(buildBearer('  abc.def.ghi  '), 'Bearer abc.def.ghi');
});

test('parseBasic round-trips a built header', () => {
  const header = buildBasic('bob', 'p@ss:word');
  assert.deepEqual(parseBasic(header), { user: 'bob', pass: 'p@ss:word' });
});

test('parseBasic returns null for non-Basic headers', () => {
  assert.equal(parseBasic('Bearer xyz'), null);
  assert.equal(parseBasic(''), null);
});

test('buildBasic tolerates empty credentials', () => {
  assert.equal(buildBasic('', ''), 'Basic ' + 'Og=='); // base64(":")
});
