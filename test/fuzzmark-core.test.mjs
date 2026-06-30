import test from 'node:test';
import assert from 'node:assert/strict';

import { wrapMarker, autoMarkUrl, autoMarkBody } from '../public/js/fuzzmark-core.js';

test('wrapMarker wraps a selection range', () => {
  assert.deepEqual(wrapMarker('abc', 0, 2), { value: '§ab§c', caret: 4 });
});

test('wrapMarker inserts an empty marker at the caret', () => {
  assert.deepEqual(wrapMarker('abc', 1, 1), { value: 'a§§bc', caret: 2 });
});

test('autoMarkUrl marks the last path segment when there is no query', () => {
  assert.equal(autoMarkUrl('https://x/api/users/123'), 'https://x/api/users/§123§');
});

test('autoMarkUrl marks the first query value when present', () => {
  assert.equal(autoMarkUrl('https://x/api/u?id=5&q=a'), 'https://x/api/u?id=§5§&q=a');
});

test('autoMarkUrl leaves an already-marked URL untouched', () => {
  const marked = 'https://x/§a§';
  assert.equal(autoMarkUrl(marked), marked);
});

test('autoMarkBody marks the first JSON string value', () => {
  assert.equal(autoMarkBody('{"name": "bob", "age": 30}'), '{"name": "§bob§", "age": 30}');
});

test('autoMarkBody falls back to the first JSON number value', () => {
  assert.equal(autoMarkBody('{"age": 30}'), '{"age": §30§}');
});

test('autoMarkBody marks a urlencoded value', () => {
  assert.equal(autoMarkBody('a=1&b=2'), 'a=§1§&b=2');
});

test('autoMarkBody returns null when there is nothing scalar to mark', () => {
  assert.equal(autoMarkBody('{}'), null);
});
