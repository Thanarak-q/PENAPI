import test from 'node:test';
import assert from 'node:assert/strict';

import {
  numericRange,
  affix,
  caseMutations,
  leet,
  mutateWords,
  MAX_OUTPUT,
} from '../public/js/wordlist-core.js';

test('numericRange produces an inclusive range', () => {
  assert.deepEqual(numericRange(1, 5), ['1', '2', '3', '4', '5']);
});

test('numericRange honors step and zero-padding', () => {
  assert.deepEqual(numericRange(0, 6, 2, 3), ['000', '002', '004', '006']);
});

test('numericRange counts down when end < start', () => {
  assert.deepEqual(numericRange(3, 1), ['3', '2', '1']);
});

test('numericRange caps runaway output at MAX_OUTPUT', () => {
  const r = numericRange(1, 1e9);
  assert.equal(r.length, MAX_OUTPUT);
});

test('affix wraps each word', () => {
  assert.deepEqual(affix(['1', '2'], 'user', '.json'), ['user1.json', 'user2.json']);
});

test('caseMutations returns unique case variants', () => {
  const m = caseMutations('Admin');
  assert.ok(m.includes('admin'));
  assert.ok(m.includes('ADMIN'));
  assert.ok(m.includes('Admin'));
});

test('leet substitutes characters', () => {
  assert.equal(leet('password'), 'p455w0rd');
});

test('mutateWords expands base words and dedupes', () => {
  const out = mutateWords(['root']);
  assert.ok(out.includes('root'));
  assert.ok(out.includes('ROOT'));
  assert.equal(new Set(out).size, out.length);
});

test('mutateWords adds leet variants when requested', () => {
  const out = mutateWords(['test'], true);
  assert.ok(out.includes('7357'));
});
