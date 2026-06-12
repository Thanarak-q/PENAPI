import test from 'node:test';
import assert from 'node:assert/strict';

import {
  openRedirectPayloads,
  ssrfPayloads,
  allPayloads,
} from '../public/js/redirect-core.js';

test('openRedirectPayloads strips scheme/path from the attacker host', () => {
  const ps = openRedirectPayloads('https://evil.com/path?x=1', 'victim.com');
  assert.ok(ps.includes('//evil.com'));
  assert.ok(ps.every((p) => !p.includes('/path')));
});

test('openRedirectPayloads weaves the target host into userinfo/subdomain tricks', () => {
  const ps = openRedirectPayloads('evil.com', 'bank.com');
  assert.ok(ps.includes('https://bank.com@evil.com'));
  assert.ok(ps.includes('https://bank.com.evil.com'));
});

test('openRedirectPayloads falls back to defaults on empty input', () => {
  const ps = openRedirectPayloads('', '');
  assert.ok(ps.some((p) => p.includes('evil.com')));
});

test('ssrfPayloads includes loopback obfuscations and cloud metadata', () => {
  const ps = ssrfPayloads('attacker.example');
  assert.ok(ps.includes('http://2130706433/'));        // decimal loopback
  assert.ok(ps.includes('http://0177.0.0.1/'));         // octal loopback
  assert.ok(ps.some((p) => p.includes('169.254.169.254'))); // AWS IMDS
  assert.ok(ps.some((p) => p.includes('metadata.google.internal')));
});

test('ssrfPayloads embeds the attacker host for OOB confirmation', () => {
  const ps = ssrfPayloads('oob.attacker.test');
  assert.ok(ps.some((p) => p.includes('oob.attacker.test/ssrf-callback')));
});

test('allPayloads groups both sets', () => {
  const all = allPayloads('evil.com', 'victim.com');
  assert.ok(Array.isArray(all['Open redirect']));
  assert.ok(Array.isArray(all.SSRF));
  assert.ok(all['Open redirect'].length > 5);
  assert.ok(all.SSRF.length > 5);
});
