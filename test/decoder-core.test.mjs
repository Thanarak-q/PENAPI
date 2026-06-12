import test from 'node:test';
import assert from 'node:assert/strict';

import {
  base64Encode, base64Decode, base64UrlEncode, base64UrlDecode,
  hexEncode, hexDecode, urlEncode, urlDecode,
  htmlEncode, htmlDecode, jwtDecode, smartDecode,
} from '../public/js/decoder-core.js';

test('base64 round-trips ASCII and UTF-8', () => {
  assert.equal(base64Encode('hello'), 'aGVsbG8=');
  assert.equal(base64Decode('aGVsbG8='), 'hello');
  assert.equal(base64Decode(base64Encode('héllo · 世界')), 'héllo · 世界');
});

test('base64url drops padding and uses URL-safe alphabet', () => {
  const enc = base64UrlEncode('subjects?<<>>');
  assert.ok(!enc.includes('='));
  assert.ok(!/[+/]/.test(enc));
  assert.equal(base64UrlDecode(enc), 'subjects?<<>>');
});

test('hex round-trips', () => {
  assert.equal(hexEncode('AB'), '4142');
  assert.equal(hexDecode('4142'), 'AB');
  assert.equal(hexDecode('48 65 6c 6c 6f'), 'Hello');
});

test('url encode/decode handles reserved chars and plus-as-space', () => {
  assert.equal(urlEncode('a b&c=d'), 'a%20b%26c%3Dd');
  assert.equal(urlDecode('a%20b%26c'), 'a b&c');
  assert.equal(urlDecode('a+b'), 'a b');
});

test('html encode/decode handles named and numeric entities', () => {
  assert.equal(htmlEncode('<a href="x">'), '&lt;a href=&quot;x&quot;&gt;');
  assert.equal(htmlDecode('&lt;b&gt;&amp;&#39;&#x41;'), "<b>&'A");
});

test('jwtDecode splits header and payload without verifying', () => {
  // {"alg":"HS256","typ":"JWT"} . {"sub":"1","admin":true} . sig
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.sig';
  const { header, payload, signature } = jwtDecode(token);
  assert.equal(header.alg, 'HS256');
  assert.equal(payload.admin, true);
  assert.equal(signature, 'sig');
});

test('smartDecode detects jwt, url, hex, html, and base64', () => {
  assert.equal(
    smartDecode('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x').format, 'jwt');
  assert.equal(smartDecode('a%20b').format, 'url');
  assert.equal(smartDecode('&lt;x&gt;').format, 'html');
  assert.equal(smartDecode('48656c6c6f').format, 'hex');
  assert.deepEqual(smartDecode('aGVsbG8='), { format: 'base64', output: 'hello' });
  assert.equal(smartDecode('').format, 'none');
});
