import test from 'node:test';
import assert from 'node:assert/strict';

import { filterCommands } from '../public/js/palette-core.js';

const COMMANDS = [
  { kind: 'action', label: 'Send current request', hint: 'Ctrl+Enter' },
  { kind: 'action', label: 'Run Quick Attacks' },
  { kind: 'tab', label: 'Go to: Request' },
  { kind: 'tab', label: 'Go to: Fuzzer / Brute' },
  { kind: 'action', label: 'Open JWT Inspector…', hint: 'Decode, edit, sign, and test JWTs locally' },
  { kind: 'action', label: 'Secret Scanner…', hint: 'Scan pasted text for leaked credentials and secrets' },
  { kind: 'action', label: 'WAF Fingerprint…', hint: 'Identify common WAF and CDN signals' },
  { kind: 'action', label: 'Token Sequencer…', hint: 'Estimate randomness across a sample of tokens' },
  { kind: 'action', label: 'Injection Payloads…', hint: 'Browse copy-only injection payloads' },
];

test('returns first 50 items for an empty query', () => {
  const big = Array.from({ length: 100 }, (_, i) => ({ kind: 'action', label: `Item ${i}` }));
  assert.equal(filterCommands(big, '').length, 50);
});

test('returns first 50 items for a whitespace-only query', () => {
  const big = Array.from({ length: 100 }, (_, i) => ({ kind: 'action', label: `Item ${i}` }));
  assert.equal(filterCommands(big, '   ').length, 50);
});

test('handles undefined/null query as empty', () => {
  const big = Array.from({ length: 60 }, (_, i) => ({ kind: 'action', label: `Item ${i}` }));
  assert.equal(filterCommands(big, undefined).length, 50);
  assert.equal(filterCommands(big, null).length, 50);
});

test('filters by label substring (case-insensitive)', () => {
  assert.equal(filterCommands(COMMANDS, 'jwt').length, 1);
  assert.equal(filterCommands(COMMANDS, 'JWT').length, 1);
  assert.equal(filterCommands(COMMANDS, 'Jwt').length, 1);
});

test('filters by hint substring (case-insensitive)', () => {
  const r = filterCommands(COMMANDS, 'waf');
  const labels = r.map((c) => c.label);
  assert.ok(labels.includes('WAF Fingerprint…'), 'WAF hit by label');
  // Hint "Identify common WAF and CDN signals" also contains "waf"
  assert.equal(r.length, 1);
});

test('matches items whose hint contains the query', () => {
  const r = filterCommands(COMMANDS, 'cdn');
  assert.equal(r.length, 1);
  assert.equal(r[0].label, 'WAF Fingerprint…');
});

test('returns empty array when nothing matches', () => {
  assert.deepEqual(filterCommands(COMMANDS, 'xyzzy_no_match'), []);
});

test('caps results at 80 for a non-empty query', () => {
  const big = Array.from({ length: 200 }, (_, i) => ({ kind: 'action', label: `Tool item ${i}` }));
  assert.equal(filterCommands(big, 'tool item').length, 80);
});

test('does not mutate the original array', () => {
  const list = [{ kind: 'action', label: 'Alpha' }, { kind: 'action', label: 'Beta' }];
  filterCommands(list, 'alpha');
  assert.equal(list.length, 2);
});

test('items without hint are matched only on label', () => {
  const list = [
    { kind: 'action', label: 'Only Label Here' },
    { kind: 'action', label: 'Something Else' },
  ];
  // "missing" does not appear in any label or hint → no results
  assert.equal(filterCommands(list, 'missing').length, 0);
  // "only label" appears in the first label → one result
  assert.equal(filterCommands(list, 'only label').length, 1);
});
