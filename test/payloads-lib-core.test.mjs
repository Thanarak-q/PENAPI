import test from 'node:test';
import assert from 'node:assert/strict';

import {
  categories,
  payloadsFor,
  allPayloads,
} from '../public/js/payloads-lib-core.js';

test('categories lists the expected attack classes', () => {
  const cats = categories();
  assert.ok(cats.includes('XSS'));
  assert.ok(cats.includes('SQLi'));
  assert.ok(cats.includes('SSTI'));
  assert.ok(cats.includes('Command injection'));
});

test('payloadsFor returns a non-empty list for a known category', () => {
  const xss = payloadsFor('XSS');
  assert.ok(xss.length > 3);
  assert.ok(xss.some((p) => /script/i.test(p)));
});

test('payloadsFor returns [] for an unknown category', () => {
  assert.deepEqual(payloadsFor('Nope'), []);
});

test('marker substitution replaces every {{M}} occurrence', () => {
  const ci = payloadsFor('Command injection', 'oob.test');
  assert.ok(ci.some((p) => p.includes('oob.test')));
  assert.ok(!ci.some((p) => p.includes('{{M}}')));
});

test('default marker leaves {{M}} untouched', () => {
  const xss = payloadsFor('XSS');
  assert.ok(xss.some((p) => p.includes('{{M}}')));
});

test('empty marker is treated as no substitution', () => {
  const xss = payloadsFor('XSS', '');
  assert.ok(xss.some((p) => p.includes('{{M}}')));
});

test('allPayloads returns every category keyed', () => {
  const all = allPayloads('h.example');
  assert.deepEqual(Object.keys(all).sort(), categories().slice().sort());
  for (const list of Object.values(all)) assert.ok(Array.isArray(list) && list.length > 0);
});
