import test from 'node:test';
import assert from 'node:assert/strict';

import {
  flatten,
  flattenJson,
  sensitiveRows,
} from '../public/js/jsonflat-core.js';

test('flatten produces dot paths for nested objects', () => {
  const rows = flatten({ user: { id: 7, name: 'ada' } });
  const paths = rows.map((r) => r.path);
  assert.deepEqual(paths, ['user.id', 'user.name']);
});

test('flatten uses bracket indices for arrays', () => {
  const rows = flatten({ items: [{ id: 1 }, { id: 2 }] });
  assert.deepEqual(rows.map((r) => r.path), ['items[0].id', 'items[1].id']);
});

test('flatten records leaf type and stringifies value', () => {
  const rows = flatten({ active: true, count: 3, note: null });
  const byPath = Object.fromEntries(rows.map((r) => [r.path, r]));
  assert.equal(byPath.active.type, 'boolean');
  assert.equal(byPath.count.value, '3');
  assert.equal(byPath.note.type, 'null');
});

test('flatten marks empty object/array leaves', () => {
  const rows = flatten({ a: {}, b: [] });
  const byPath = Object.fromEntries(rows.map((r) => [r.path, r]));
  assert.equal(byPath.a.value, '{}');
  assert.equal(byPath.b.value, '[]');
});

test('sensitive keys are flagged', () => {
  const rows = flatten({ password: 'x', api_key: 'y', name: 'z' });
  const byPath = Object.fromEntries(rows.map((r) => [r.path, r]));
  assert.equal(byPath.password.sensitive, true);
  assert.equal(byPath.api_key.sensitive, true);
  assert.equal(byPath.name.sensitive, false);
});

test('flattenJson reports parse errors', () => {
  const r = flattenJson('{ not json ');
  assert.equal(r.ok, false);
  assert.ok(r.error);
});

test('flattenJson parses and flattens valid input', () => {
  const r = flattenJson('{"a":{"b":1}}');
  assert.equal(r.ok, true);
  assert.equal(r.rows[0].path, 'a.b');
});

test('sensitiveRows returns only flagged leaves', () => {
  const { rows } = flattenJson('{"token":"abc","public":"ok"}');
  const s = sensitiveRows(rows);
  assert.equal(s.length, 1);
  assert.equal(s[0].path, 'token');
});
