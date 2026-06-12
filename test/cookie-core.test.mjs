import test from 'node:test';
import assert from 'node:assert/strict';

import { parseSetCookie, parseCookies, auditCookie } from '../public/js/cookie-core.js';

test('parseSetCookie extracts name, value, and attributes', () => {
  const c = parseSetCookie('sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600');
  assert.equal(c.name, 'sid');
  assert.equal(c.value, 'abc123');
  assert.equal(c.httpOnly, true);
  assert.equal(c.secure, true);
  assert.equal(c.sameSite, 'Lax');
  assert.equal(c.path, '/');
  assert.equal(c.maxAge, '3600');
});

test('parseCookies splits a request Cookie header', () => {
  assert.deepEqual(parseCookies('a=1; b=two; c'), [
    { name: 'a', value: '1' },
    { name: 'b', value: 'two' },
    { name: 'c', value: '' },
  ]);
});

test('auditCookie flags all missing protections', () => {
  const issues = auditCookie(parseSetCookie('sid=abc'));
  assert.equal(issues.length, 3);
  assert.ok(issues.some((i) => /HttpOnly/.test(i)));
  assert.ok(issues.some((i) => /Secure/.test(i)));
  assert.ok(issues.some((i) => /SameSite/.test(i)));
});

test('auditCookie passes a fully hardened cookie', () => {
  const issues = auditCookie(parseSetCookie('sid=abc; HttpOnly; Secure; SameSite=Strict'));
  assert.deepEqual(issues, []);
});

test('auditCookie warns on SameSite=None', () => {
  const issues = auditCookie(parseSetCookie('sid=abc; HttpOnly; Secure; SameSite=None'));
  assert.ok(issues.some((i) => /SameSite=None/.test(i)));
});
