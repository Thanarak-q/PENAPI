import test from 'node:test';
import assert from 'node:assert/strict';

import { parseWordlist, buildCandidates, classify, COMMON_PATHS } from '../public/js/discovery-core.js';

test('parseWordlist trims, drops blanks and comments', () => {
  assert.deepEqual(parseWordlist('admin\n\n# comment\n  api  \n'), ['admin', 'api']);
});

test('buildCandidates joins base and path, normalizing slashes', () => {
  const c = buildCandidates('https://t.test/', ['/admin', 'api/v1']);
  assert.deepEqual(c, [
    { word: 'admin', url: 'https://t.test/admin' },
    { word: 'api/v1', url: 'https://t.test/api/v1' },
  ]);
});

test('buildCandidates dedupes repeated paths', () => {
  const c = buildCandidates('https://t.test', ['admin', '/admin', 'admin']);
  assert.equal(c.length, 1);
});

test('buildCandidates skips empty words', () => {
  const c = buildCandidates('https://t.test', ['', '/', 'ok']);
  assert.deepEqual(c.map((x) => x.word), ['ok']);
});

test('classify distinguishes found, protected, redirect, missing, error', () => {
  assert.deepEqual(classify(200), { kind: 'found', interesting: true });
  assert.deepEqual(classify(302), { kind: 'redirect', interesting: true });
  assert.deepEqual(classify(403), { kind: 'protected', interesting: true });
  assert.deepEqual(classify(404), { kind: 'missing', interesting: false });
  assert.deepEqual(classify(500), { kind: 'server-error', interesting: true });
  assert.deepEqual(classify(null), { kind: 'error', interesting: true });
});

test('the built-in wordlist is non-empty and unique', () => {
  assert.ok(COMMON_PATHS.length > 20);
  assert.equal(new Set(COMMON_PATHS).size, COMMON_PATHS.length);
});
