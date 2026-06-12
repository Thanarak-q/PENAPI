import test from 'node:test';
import assert from 'node:assert/strict';

import {
  allHeaders,
  categories,
  searchHeaders,
  toHeaderLine,
} from '../public/js/attackhdr-core.js';

test('allHeaders returns a populated table with required fields', () => {
  const all = allHeaders();
  assert.ok(all.length > 10);
  assert.ok(all.every((e) => e.category && e.name && e.sample && e.note));
});

test('categories lists distinct groups in order', () => {
  const cats = categories();
  assert.ok(cats.includes('IP spoofing'));
  assert.ok(cats.includes('Auth context'));
  assert.equal(new Set(cats).size, cats.length);
});

test('searchHeaders matches header name', () => {
  const r = searchHeaders('x-original-url');
  assert.equal(r.length, 1);
  assert.equal(r[0].name, 'X-Original-URL');
});

test('searchHeaders matches note keywords', () => {
  const r = searchHeaders('cache poisoning');
  assert.ok(r.some((e) => e.name === 'X-Forwarded-Host'));
});

test('searchHeaders matches a category', () => {
  const r = searchHeaders('ip spoofing');
  assert.ok(r.length >= 4);
  assert.ok(r.every((e) => e.category === 'IP spoofing'));
});

test('empty query returns everything', () => {
  assert.equal(searchHeaders('').length, allHeaders().length);
});

test('toHeaderLine formats a Name: value pair', () => {
  assert.equal(toHeaderLine({ name: 'X-Real-IP', sample: '127.0.0.1' }), 'X-Real-IP: 127.0.0.1');
});
