import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseTimestamp,
  describeTimestamp,
  relativeTime,
  nowStamps,
} from '../public/js/timestamp-core.js';

const REF = Date.UTC(2025, 0, 1, 0, 0, 0); // 1735689600000

test('parses 10-digit integer as Unix seconds', () => {
  const p = parseTimestamp('1735689600');
  assert.equal(p.kind, 'unix-s');
  assert.equal(p.ms, 1735689600000);
});

test('parses 13-digit integer as Unix milliseconds', () => {
  const p = parseTimestamp('1735689600000');
  assert.equal(p.kind, 'unix-ms');
  assert.equal(p.ms, 1735689600000);
});

test('parses ISO 8601 string', () => {
  const p = parseTimestamp('2025-01-01T00:00:00Z');
  assert.equal(p.kind, 'iso');
  assert.equal(p.ms, REF);
});

test('returns null for empty or garbage input', () => {
  assert.equal(parseTimestamp(''), null);
  assert.equal(parseTimestamp('not a date'), null);
});

test('describeTimestamp gives every representation', () => {
  const d = describeTimestamp('1735689600', REF);
  assert.equal(d.unixSeconds, 1735689600);
  assert.equal(d.unixMillis, 1735689600000);
  assert.equal(d.iso, '2025-01-01T00:00:00.000Z');
  assert.equal(d.detectedAs, 'unix-s');
});

test('relativeTime reports future and past', () => {
  assert.equal(relativeTime(REF + 2 * 3600000, REF), 'in 2 hours');
  assert.equal(relativeTime(REF - 3 * 86400000, REF), '3 days ago');
  assert.equal(relativeTime(REF, REF), 'now');
});

test('describeTimestamp flags an expired (past) timestamp', () => {
  const d = describeTimestamp('1735689600', REF + 86400000);
  assert.equal(d.isPast, true);
});

test('describeTimestamp flags a not-yet timestamp as future', () => {
  const d = describeTimestamp(String(Math.floor((REF + 86400000) / 1000)), REF);
  assert.equal(d.isPast, false);
});

test('nowStamps returns consistent forms', () => {
  const s = nowStamps(REF);
  assert.equal(s.unixSeconds, 1735689600);
  assert.equal(s.unixMillis, REF);
  assert.equal(s.iso, '2025-01-01T00:00:00.000Z');
});
