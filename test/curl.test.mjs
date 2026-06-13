import test from 'node:test';
import assert from 'node:assert/strict';

import curl from '../lib/curl.js';

const { parseCurl, toCurl, tokenize } = curl;

test('tokenize handles single/double quotes and escapes', () => {
  assert.deepEqual(tokenize(`curl 'a b' "c d"`), ['curl', 'a b', 'c d']);
  assert.deepEqual(tokenize('curl "a\\"b"'), ['curl', 'a"b']);
});

test('parseCurl reads method, headers, and a JSON body', () => {
  const req = parseCurl(`curl -X POST 'https://api.test/u' -H 'Content-Type: application/json' --data-raw '{"a":1}'`);
  assert.equal(req.method, 'POST');
  assert.equal(req.url, 'https://api.test/u');
  assert.equal(req.headers['Content-Type'], 'application/json');
  assert.equal(req.body, '{"a":1}');
});

test('parseCurl defaults to POST + urlencoded when -d is present without method', () => {
  const req = parseCurl(`curl https://api.test/u -d 'x=1'`);
  assert.equal(req.method, 'POST');
  assert.equal(req.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.equal(req.body, 'x=1');
});

test('parseCurl -u builds a Basic auth header', () => {
  const req = parseCurl(`curl https://api.test -u admin:secret`);
  assert.equal(req.headers['Authorization'], 'Basic ' + Buffer.from('admin:secret').toString('base64'));
});

test('parseCurl -G moves data into the query string', () => {
  const req = parseCurl(`curl -G https://api.test/s -d 'q=hi'`);
  assert.equal(req.method, 'GET');
  assert.equal(req.url, 'https://api.test/s?q=hi');
  assert.equal(req.body, null);
});

test('parseCurl picks up a bare URL and -k insecure flag', () => {
  const req = parseCurl(`curl https://api.test/x -k`);
  assert.equal(req.url, 'https://api.test/x');
  assert.equal(req.insecure, true);
  assert.equal(req.method, 'GET');
});

test('parseCurl does not throw on a trailing -H (malformed input)', () => {
  assert.doesNotThrow(() => parseCurl('curl https://api.test -H'));
  const req = parseCurl('curl https://api.test -H');
  assert.equal(req.url, 'https://api.test');
});

test('parseCurl does not throw on a trailing -u (malformed input)', () => {
  assert.doesNotThrow(() => parseCurl('curl https://api.test -u'));
});

test('parseCurl url-encodes --data-urlencode values', () => {
  const req = parseCurl(`curl https://api.test -X POST --data-urlencode 'q=hello world & more'`);
  assert.equal(req.body, 'q=hello%20world%20%26%20more');
  const bare = parseCurl(`curl https://api.test --data-urlencode 'a b'`);
  assert.equal(bare.body, 'a%20b');
});

test('toCurl serializes method, headers, and body with shell quoting', () => {
  const out = toCurl({ method: 'POST', url: 'https://api.test/u', headers: { 'X-A': 'b c' }, body: '{"a":1}' });
  assert.ok(out.startsWith('curl -i'));
  assert.ok(out.includes('-X POST'));
  assert.ok(out.includes("'X-A: b c'"));
  assert.ok(out.includes("--data-raw '{\"a\":1}'"));
});

test('toCurl omits -X for GET and round-trips through parseCurl', () => {
  const out = toCurl({ method: 'GET', url: 'https://api.test/x', headers: { Accept: 'application/json' } });
  assert.ok(!out.includes('-X'));
  const back = parseCurl(out);
  assert.equal(back.url, 'https://api.test/x');
  assert.equal(back.headers.Accept, 'application/json');
});
