import test from 'node:test';
import assert from 'node:assert/strict';

import {
  allStatuses,
  lookupStatus,
  searchStatuses,
} from '../public/js/status-core.js';

test('allStatuses returns the full table', () => {
  const all = allStatuses();
  assert.ok(all.length > 15);
  assert.ok(all.every((e) => typeof e.code === 'number' && e.phrase && e.note));
});

test('lookupStatus finds an exact code', () => {
  const e = lookupStatus(403);
  assert.equal(e.phrase, 'Forbidden');
  assert.ok(/verb tampering/i.test(e.note));
});

test('lookupStatus accepts a numeric string', () => {
  assert.equal(lookupStatus('500').phrase, 'Internal Server Error');
});

test('lookupStatus returns null for unknown codes', () => {
  assert.equal(lookupStatus(999), null);
});

test('searchStatuses matches by code prefix', () => {
  const r = searchStatuses('40');
  assert.ok(r.every((e) => String(e.code).startsWith('40')));
  assert.ok(r.some((e) => e.code === 403));
});

test('searchStatuses matches phrase text case-insensitively', () => {
  const r = searchStatuses('forbidden');
  assert.equal(r.length, 1);
  assert.equal(r[0].code, 403);
});

test('searchStatuses matches note keywords', () => {
  const r = searchStatuses('ssrf');
  assert.ok(r.some((e) => e.code === 502));
});

test('empty query returns everything', () => {
  assert.equal(searchStatuses('').length, allStatuses().length);
});
