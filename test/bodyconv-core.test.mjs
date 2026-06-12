import test from 'node:test';
import assert from 'node:assert/strict';

import {
  toEntries,
  toFormUrlencoded,
  toQueryString,
  toMultipart,
  convertBody,
} from '../public/js/bodyconv-core.js';

test('toEntries stringifies primitives and JSON-encodes nested values', () => {
  const e = toEntries({ a: 1, b: true, c: { d: 2 }, e: [1, 2] });
  const map = Object.fromEntries(e);
  assert.equal(map.a, '1');
  assert.equal(map.b, 'true');
  assert.equal(map.c, '{"d":2}');
  assert.equal(map.e, '[1,2]');
});

test('toEntries rejects non-object top level', () => {
  assert.throws(() => toEntries([1, 2]));
  assert.throws(() => toEntries('x'));
});

test('toFormUrlencoded percent-encodes keys and values', () => {
  const s = toFormUrlencoded({ 'a b': 'c&d', x: 1 });
  assert.equal(s, 'a%20b=c%26d&x=1');
});

test('toQueryString prefixes ? and is empty for {}', () => {
  assert.equal(toQueryString({ x: 1 }), '?x=1');
  assert.equal(toQueryString({}), '');
});

test('toMultipart builds parts with the boundary and trailer', () => {
  const { boundary, body } = toMultipart({ user: 'ada' }, 'BND');
  assert.equal(boundary, 'BND');
  assert.ok(body.includes('--BND\r\nContent-Disposition: form-data; name="user"\r\n\r\nada\r\n'));
  assert.ok(body.endsWith('--BND--\r\n'));
});

test('convertBody returns all encodings for valid JSON', () => {
  const r = convertBody('{"id":7,"q":"a b"}');
  assert.equal(r.ok, true);
  assert.equal(r.formUrlencoded, 'id=7&q=a%20b');
  assert.equal(r.queryString, '?id=7&q=a%20b');
  assert.ok(r.multipart.includes('name="id"'));
});

test('convertBody reports invalid JSON', () => {
  const r = convertBody('{ bad');
  assert.equal(r.ok, false);
  assert.ok(/Invalid JSON/.test(r.error));
});

test('convertBody rejects a top-level array with a clear error', () => {
  const r = convertBody('[1,2,3]');
  assert.equal(r.ok, false);
  assert.ok(/object/.test(r.error));
});
