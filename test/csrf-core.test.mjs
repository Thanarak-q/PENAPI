import test from 'node:test';
import assert from 'node:assert/strict';

import { parseQuery, parseFormBody, buildCsrfPoc } from '../public/js/csrf-core.js';

test('parseQuery splits action and decodes params', () => {
  const { action, params } = parseQuery('https://t.test/p?a=1&b=hello%20world');
  assert.equal(action, 'https://t.test/p');
  assert.deepEqual(params, [
    { name: 'a', value: '1' },
    { name: 'b', value: 'hello world' },
  ]);
});

test('parseFormBody decodes url-encoded fields', () => {
  assert.deepEqual(parseFormBody('user=ada&role=admin%20x'), [
    { name: 'user', value: 'ada' },
    { name: 'role', value: 'admin x' },
  ]);
  assert.deepEqual(parseFormBody(''), []);
});

test('GET request becomes a GET form with hidden query fields', () => {
  const { html } = buildCsrfPoc({ method: 'GET', url: 'https://t.test/transfer?to=2&amt=100', headers: {} });
  assert.match(html, /method="GET"/);
  assert.match(html, /action="https:\/\/t\.test\/transfer"/);
  assert.match(html, /name="to" value="2"/);
  assert.match(html, /name="amt" value="100"/);
  assert.match(html, /onload="document\.forms\[0\]\.submit\(\)"/);
});

test('form-urlencoded POST emits a normal auto-submit form', () => {
  const { html } = buildCsrfPoc({
    method: 'POST',
    url: 'https://t.test/settings',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'email=evil@x.test&admin=true',
  });
  assert.match(html, /enctype="application\/x-www-form-urlencoded"/);
  assert.match(html, /name="email" value="evil@x\.test"/);
  assert.match(html, /name="admin" value="true"/);
});

test('JSON POST uses the text/plain trick and notes the caveat', () => {
  const { html, notes } = buildCsrfPoc({
    method: 'POST',
    url: 'https://t.test/api',
    headers: { 'Content-Type': 'application/json' },
    body: '{"role":"admin"}',
  });
  assert.match(html, /enctype="text\/plain"/);
  assert.match(html, /name="\{&quot;role&quot;:&quot;admin&quot;\}"/);
  assert.ok(notes.some((n) => /text\/plain/.test(n)));
});

test('Authorization header produces a cookie-auth caveat note', () => {
  const { notes } = buildCsrfPoc({
    method: 'POST',
    url: 'https://t.test/x',
    headers: { Authorization: 'Bearer abc', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'a=1',
  });
  assert.ok(notes.some((n) => /Authorization header/.test(n)));
});

test('attribute values are HTML-escaped to prevent breakout', () => {
  const { html } = buildCsrfPoc({
    method: 'POST',
    url: 'https://t.test/x',
    headers: {},
    body: 'q="><script>alert(1)</script>',
  });
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.match(html, /&quot;&gt;&lt;script&gt;/);
});
