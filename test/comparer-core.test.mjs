import test from 'node:test';
import assert from 'node:assert/strict';

import { tokenizeWords, diffTokens, diff } from '../public/js/comparer-core.js';

test('identical text reports no changes', () => {
  const r = diff('a\nb\nc', 'a\nb\nc');
  assert.equal(r.identical, true);
  assert.equal(r.added, 0);
  assert.equal(r.removed, 0);
  assert.equal(r.equal, 3);
});

test('a changed line shows one del and one add', () => {
  const r = diff('a\nb\nc', 'a\nX\nc');
  assert.equal(r.added, 1);
  assert.equal(r.removed, 1);
  assert.equal(r.identical, false);
  // order preserved: equal a, then the swap, then equal c
  assert.equal(r.ops[0].type, 'equal');
  assert.equal(r.ops.at(-1).value, 'c');
});

test('an appended line is a single add', () => {
  const r = diff('a\nb', 'a\nb\nc');
  assert.equal(r.added, 1);
  assert.equal(r.removed, 0);
  assert.deepEqual(r.ops.at(-1), { type: 'add', value: 'c' });
});

test('word mode keeps whitespace tokens so output rejoins exactly', () => {
  const tokens = tokenizeWords('the quick fox');
  assert.equal(tokens.join(''), 'the quick fox');
  const r = diff('the quick fox', 'the slow fox', 'word');
  assert.ok(r.added >= 1 && r.removed >= 1);
});

test('diffTokens reconstructs both inputs from its ops', () => {
  const a = ['x', 'y', 'z'];
  const b = ['x', 'q', 'z'];
  const ops = diffTokens(a, b);
  const left = ops.filter((o) => o.type !== 'add').map((o) => o.value);
  const right = ops.filter((o) => o.type !== 'del').map((o) => o.value);
  assert.deepEqual(left, a);
  assert.deepEqual(right, b);
});
