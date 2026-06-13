import test from 'node:test';
import assert from 'node:assert/strict';

import {
  methodClass,
  statusClass,
  fmtBytes,
  prettyJson,
  headersToText,
  textToHeaders,
} from '../public/js/util.js';

test('methodClass lower-cases and defaults to get', () => {
  assert.equal(methodClass('POST'), 'm-post');
  assert.equal(methodClass(''), 'm-get');
  assert.equal(methodClass(undefined), 'm-get');
});

test('statusClass buckets by status range', () => {
  assert.equal(statusClass(0), '');
  assert.equal(statusClass(200), 's-2xx');
  assert.equal(statusClass(301), 's-3xx');
  assert.equal(statusClass(404), 's-4xx');
  assert.equal(statusClass(500), 's-5xx');
});

test('fmtBytes formats B / KB / MB and guards bad input', () => {
  assert.equal(fmtBytes(0), '0 B');
  assert.equal(fmtBytes(512), '512 B');
  assert.equal(fmtBytes(2048), '2.0 KB');
  assert.equal(fmtBytes(1048576), '1.00 MB');
  assert.equal(fmtBytes(null), '–');
  assert.equal(fmtBytes(NaN), '–');
  assert.equal(fmtBytes(undefined), '–');
});

test('prettyJson pretty-prints valid JSON and passes through invalid', () => {
  assert.equal(prettyJson('{"a":1}'), '{\n  "a": 1\n}');
  assert.equal(prettyJson('not json'), 'not json');
});

test('headersToText joins name: value lines', () => {
  assert.equal(headersToText({ A: '1', B: '2' }), 'A: 1\nB: 2');
  assert.equal(headersToText(null), '');
});

test('textToHeaders parses lines and round-trips with headersToText', () => {
  const headers = textToHeaders('Content-Type: application/json\nX-Token: abc');
  assert.deepEqual(headers, { 'Content-Type': 'application/json', 'X-Token': 'abc' });
  assert.deepEqual(textToHeaders(headersToText(headers)), headers);
});

test('textToHeaders ignores blank and malformed lines, trims values', () => {
  const headers = textToHeaders('\n  Authorization:   Bearer x  \nnocolon\n');
  assert.deepEqual(headers, { Authorization: 'Bearer x' });
});

test('textToHeaders keeps colons in the value (e.g. a URL)', () => {
  assert.deepEqual(textToHeaders('Location: https://x.test/a'), { Location: 'https://x.test/a' });
});
