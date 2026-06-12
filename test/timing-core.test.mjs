import test from 'node:test';
import assert from 'node:assert/strict';

import { aggregateTimings, median } from '../public/js/timing-core.js';

test('median handles odd and even counts', () => {
  assert.equal(median([1, 2, 3]), 2);
  assert.equal(median([1, 2, 3, 4]), 2.5);
  assert.equal(median([]), 0);
});

test('aggregateTimings groups by method+url and computes stats', () => {
  const rows = aggregateTimings([
    { method: 'GET', url: '/a', timeMs: 10 },
    { method: 'GET', url: '/a', timeMs: 30 },
    { method: 'GET', url: '/a', timeMs: 20 },
  ]);
  assert.equal(rows.length, 1);
  assert.deepEqual(
    { count: rows[0].count, min: rows[0].min, max: rows[0].max, avg: rows[0].avg, median: rows[0].median },
    { count: 3, min: 10, max: 30, avg: 20, median: 20 }
  );
});

test('different endpoints form separate rows sorted by avg desc', () => {
  const rows = aggregateTimings([
    { method: 'GET', url: '/fast', timeMs: 5 },
    { method: 'POST', url: '/slow', timeMs: 500 },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].url, '/slow'); // slowest first
});

test('entries without a timeMs are ignored', () => {
  const rows = aggregateTimings([
    { method: 'GET', url: '/a', timeMs: null },
    { method: 'GET', url: '/a', timeMs: 12 },
    { method: 'GET', url: '/a' },
  ]);
  assert.equal(rows[0].count, 1);
});

test('empty history yields no rows', () => {
  assert.deepEqual(aggregateTimings([]), []);
});
