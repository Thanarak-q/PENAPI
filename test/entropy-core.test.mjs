import test from 'node:test';
import assert from 'node:assert/strict';

import {
  shannonPerChar,
  charsetOf,
  analyzeEntropy,
  verdictFor,
} from '../public/js/entropy-core.js';

test('shannonPerChar is 0 for empty and for a single repeated char', () => {
  assert.equal(shannonPerChar(''), 0);
  assert.equal(shannonPerChar('aaaaaa'), 0);
});

test('shannonPerChar is 1 bit for a balanced two-symbol string', () => {
  assert.equal(shannonPerChar('abab'), 1);
});

test('charsetOf detects classes and alphabet size', () => {
  const c = charsetOf('Abc123');
  assert.equal(c.classes.lower, true);
  assert.equal(c.classes.upper, true);
  assert.equal(c.classes.digit, true);
  assert.equal(c.alphabet, 62);
});

test('charsetOf recognizes lowercase hex', () => {
  const c = charsetOf('deadbeef');
  assert.equal(c.classes.hex, true);
});

test('analyzeEntropy reports length, unique and bit estimates', () => {
  const r = analyzeEntropy('abcdefgh');
  assert.equal(r.length, 8);
  assert.equal(r.unique, 8);
  assert.ok(r.bitsTotal > 0);
  assert.ok(r.keyspaceBits > 0);
});

test('a short numeric value gets a weak verdict', () => {
  const r = analyzeEntropy('1234');
  assert.equal(r.verdict.level, 'weak');
});

test('a long random base64url token gets a strong verdict', () => {
  const r = analyzeEntropy('Xa9Kd2Lp7Qr4Tn1Vb8Zc3Mw6Ye0Hs5Jf');
  assert.ok(['good', 'strong'].includes(r.verdict.level));
});

test('verdictFor brackets keyspace into levels', () => {
  assert.equal(verdictFor(0, 0).level, 'empty');
  assert.equal(verdictFor(20, 4).level, 'weak');
  assert.equal(verdictFor(50, 10).level, 'fair');
  assert.equal(verdictFor(100, 20).level, 'good');
  assert.equal(verdictFor(200, 40).level, 'strong');
});

test('empty input is handled without throwing', () => {
  const r = analyzeEntropy('');
  assert.equal(r.length, 0);
  assert.equal(r.verdict.level, 'empty');
});
