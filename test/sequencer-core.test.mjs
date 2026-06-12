import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeTokens, detectSequential } from '../public/js/sequencer-core.js';

test('detectSequential flags constant-step numeric tokens', () => {
  assert.equal(detectSequential(['1', '2', '3', '4']), true);
  assert.equal(detectSequential(['100', '110', '120']), true);
  assert.equal(detectSequential(['1', '2', '4']), false);
  assert.equal(detectSequential(['a1', 'a2', 'a3']), false);
});

test('analyzeTokens reports counts, uniqueness, and length', () => {
  const r = analyzeTokens(['abcd', 'efgh', 'abcd']);
  assert.equal(r.total, 3);
  assert.equal(r.unique, 2);
  assert.equal(r.duplicates, 1);
  assert.equal(r.minLen, 4);
  assert.equal(r.sameLength, true);
});

test('sequential tokens are graded predictable', () => {
  const r = analyzeTokens(['1000', '1001', '1002', '1003', '1004']);
  assert.equal(r.sequential, true);
  assert.equal(r.verdict.level, 'predictable');
});

test('duplicates among enough samples are graded weak', () => {
  const r = analyzeTokens(['aaa', 'bbb', 'ccc', 'aaa', 'ddd']);
  assert.equal(r.duplicates, 1);
  assert.equal(r.verdict.level, 'weak');
});

test('a fixed shared prefix contributes zero entropy at that position', () => {
  // Every token starts with 'X' → position 0 entropy is 0.
  const r = analyzeTokens(['Xa', 'Xb', 'Xc', 'Xd']);
  assert.equal(r.perPosition[0], 0);
  assert.ok(r.perPosition[1] > 0);
});

test('empty input returns a none verdict', () => {
  const r = analyzeTokens([]);
  assert.equal(r.total, 0);
  assert.equal(r.verdict.level, 'none');
});

test('high-variety distinct tokens accumulate entropy across positions', () => {
  const tokens = ['9f3a', '2b7c', 'd14e', '7c8a', 'e0b1', '4a9d'];
  const r = analyzeTokens(tokens);
  assert.equal(r.duplicates, 0);
  assert.ok(r.totalEntropyBits > 0);
  assert.equal(r.charsetSize > 0, true);
});
