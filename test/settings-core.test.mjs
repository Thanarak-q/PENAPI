import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULTS,
  normalizeSettings,
  loadSettings,
  serializeSettings,
} from '../public/js/settings-core.js';

test('loadSettings returns defaults for empty input', () => {
  assert.deepEqual(loadSettings(null), DEFAULTS);
  assert.deepEqual(loadSettings(''), DEFAULTS);
  assert.deepEqual(loadSettings('{}'), DEFAULTS);
});

test('loadSettings returns defaults for garbage JSON', () => {
  assert.deepEqual(loadSettings('not-json!!!'), DEFAULTS);
  assert.deepEqual(loadSettings('{broken'), DEFAULTS);
});

test('normalizeSettings clamps fuzzConcurrency at lower bound', () => {
  assert.equal(normalizeSettings({ fuzzConcurrency: 0 }).fuzzConcurrency, 1);
  assert.equal(normalizeSettings({ fuzzConcurrency: -5 }).fuzzConcurrency, 1);
});

test('normalizeSettings clamps fuzzConcurrency at upper bound', () => {
  assert.equal(normalizeSettings({ fuzzConcurrency: 999 }).fuzzConcurrency, 50);
  assert.equal(normalizeSettings({ fuzzConcurrency: 51 }).fuzzConcurrency, 50);
});

test('normalizeSettings clamps fuzzDelayMs at upper bound', () => {
  assert.equal(normalizeSettings({ fuzzDelayMs: 99999 }).fuzzDelayMs, 10000);
  assert.equal(normalizeSettings({ fuzzDelayMs: 0 }).fuzzDelayMs, 0);
});

test('normalizeSettings clamps historyLimit at both bounds', () => {
  assert.equal(normalizeSettings({ historyLimit: 2 }).historyLimit, 10);
  assert.equal(normalizeSettings({ historyLimit: 9 }).historyLimit, 10);
  assert.equal(normalizeSettings({ historyLimit: 5000 }).historyLimit, 2000);
});

test('normalizeSettings coerces confirmRisky truthy/falsy', () => {
  assert.equal(normalizeSettings({ confirmRisky: 1 }).confirmRisky, true);
  assert.equal(normalizeSettings({ confirmRisky: 0 }).confirmRisky, false);
  assert.equal(normalizeSettings({ confirmRisky: 'yes' }).confirmRisky, true);
  assert.equal(normalizeSettings({ confirmRisky: '' }).confirmRisky, false);
  assert.equal(normalizeSettings({ confirmRisky: false }).confirmRisky, false);
});

test('normalizeSettings drops unknown keys', () => {
  const s = normalizeSettings({ fuzzConcurrency: 5, unknownKey: 'foo', extra: 123 });
  assert.ok(!('unknownKey' in s));
  assert.ok(!('extra' in s));
  assert.equal(s.fuzzConcurrency, 5);
});

test('loadSettings round-trips with serializeSettings', () => {
  const original = { fuzzConcurrency: 12, fuzzDelayMs: 500, confirmRisky: false, historyLimit: 500 };
  const loaded = loadSettings(serializeSettings(original));
  assert.deepEqual(loaded, { fuzzConcurrency: 12, fuzzDelayMs: 500, confirmRisky: false, historyLimit: 500 });
});

test('out-of-range values are clamped not rejected', () => {
  const s = normalizeSettings({ fuzzConcurrency: 0, fuzzDelayMs: -1, historyLimit: 1 });
  assert.equal(s.fuzzConcurrency, 1);
  assert.equal(s.fuzzDelayMs, 0);
  assert.equal(s.historyLimit, 10);
});
