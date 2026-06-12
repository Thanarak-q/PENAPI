import test from 'node:test';
import assert from 'node:assert/strict';

import { identifyHash } from '../public/js/hashid-core.js';

test('identifies a 32-char hex as MD5/NTLM family', () => {
  const r = identifyHash('5f4dcc3b5aa765d61d8327deb882cf99');
  assert.ok(r.candidates.includes('MD5'));
  assert.ok(r.candidates.includes('NTLM'));
});

test('identifies a 40-char hex as SHA-1', () => {
  const r = identifyHash('da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.ok(r.candidates.includes('SHA-1'));
});

test('identifies a 64-char hex as SHA-256', () => {
  const r = identifyHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.ok(r.candidates.includes('SHA-256'));
});

test('identifies a 128-char hex as SHA-512', () => {
  const r = identifyHash('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
  assert.ok(r.candidates.includes('SHA-512'));
});

test('recognizes a bcrypt hash by prefix', () => {
  const r = identifyHash('$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW');
  assert.deepEqual(r.candidates, ['bcrypt']);
});

test('recognizes sha512crypt by $6$ prefix', () => {
  const r = identifyHash('$6$rounds=5000$salt$hashbody');
  assert.ok(r.candidates.includes('sha512crypt (Unix)'));
});

test('flags a short hex as a likely checksum', () => {
  const r = identifyHash('deadbeef');
  assert.ok(r.notes.some((n) => /CRC32|checksum/.test(n)));
});

test('handles empty input without throwing', () => {
  const r = identifyHash('');
  assert.equal(r.candidates.length, 0);
  assert.equal(r.length, 0);
});

test('reports unrecognized formats', () => {
  const r = identifyHash('not a hash!!');
  assert.equal(r.candidates.length, 0);
  assert.ok(r.notes.some((n) => /Unrecognized/.test(n)));
});

test('trims surrounding whitespace before identifying', () => {
  const r = identifyHash('  5f4dcc3b5aa765d61d8327deb882cf99  ');
  assert.equal(r.length, 32);
  assert.ok(r.candidates.includes('MD5'));
});
