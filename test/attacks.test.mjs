import test from 'node:test';
import assert from 'node:assert/strict';

import attacks from '../lib/attacks.js';

const { buildVariants, stripAuth, rewritePath } = attacks;

const base = () => ({
  method: 'POST',
  url: 'https://api.example.com/v1/users/1',
  headers: { Authorization: 'Bearer abc', 'Content-Type': 'application/json' },
  body: '{"a":1}',
});

const names = (vs) => vs.map((v) => v.name);

test('stripAuth removes only auth headers', () => {
  const out = stripAuth({ Authorization: 'x', Cookie: 'y', Accept: 'json' });
  assert.deepEqual(out, { Accept: 'json' });
});

test('rewritePath transforms the path and keeps origin + query', () => {
  const u = rewritePath('https://h/a/b?x=1', (p) => p.toUpperCase());
  assert.equal(u, 'https://h/A/B?x=1');
});

test('rewritePath returns the original on an unparseable url', () => {
  assert.equal(rewritePath('not a url', (p) => p), 'not a url');
});

test('buildVariants always includes a baseline first', () => {
  const vs = buildVariants(base());
  assert.equal(vs[0].name, 'baseline');
});

test('buildVariants strips auth in the no-auth variant', () => {
  const vs = buildVariants(base());
  const noAuth = vs.find((v) => v.name === 'no auth');
  assert.ok(!('Authorization' in noAuth.request.headers));
});

test('auth-token variants only appear when an Authorization header exists', () => {
  const withAuth = names(buildVariants(base()));
  assert.ok(withAuth.includes('empty bearer'));
  assert.ok(withAuth.includes('malformed token'));

  const noAuthBase = { ...base(), headers: { 'Content-Type': 'application/json' } };
  const without = names(buildVariants(noAuthBase));
  assert.ok(!without.includes('empty bearer'));
});

test('method → GET variant is omitted for GET requests', () => {
  const get = names(buildVariants({ ...base(), method: 'GET', body: '' }));
  assert.ok(!get.includes('method → GET'));
});

test('path-normalization variants rewrite the path', () => {
  const vs = buildVariants(base());
  const map = Object.fromEntries(vs.map((v) => [v.name, v.request.url]));
  assert.ok(map['trailing dot'].endsWith('/users/1/.'));
  assert.ok(map['encoded slash'].includes('/%2f1'));
  assert.ok(/\/V1\/USERS\/1$/.test(map['case-swapped path']));
  assert.ok(map['double slash'].includes('//v1/users/1'));
});

test('content-type variants only appear with a body', () => {
  const withBody = names(buildVariants(base()));
  assert.ok(withBody.includes('content-type → xml'));

  const noBody = names(buildVariants({ ...base(), body: '' }));
  assert.ok(!noBody.includes('content-type → xml'));
});

test('framework ACL-bypass path variants are present and rewrite the path', () => {
  const vs = buildVariants(base());
  const map = Object.fromEntries(vs.map((v) => [v.name, v.request.url]));
  assert.ok(map['matrix param'].includes(';x=1'));
  assert.ok(map['semicolon traversal'].includes('/..;/1'));
  assert.ok(map['extension append'].endsWith('/users/1.json'));
});

test('mass-assignment body variant injects privileged fields into a JSON object body', () => {
  const vs = buildVariants(base());
  const ma = vs.find((v) => v.name === 'mass-assignment body');
  assert.ok(ma, 'mass-assignment body variant missing');
  const body = JSON.parse(ma.request.body);
  assert.equal(body.a, 1);
  assert.equal(body.isAdmin, true);
  assert.equal(body.role, 'admin');
});

test('mass-assignment body variant is omitted for non-JSON-object bodies', () => {
  const arr = names(buildVariants({ ...base(), body: '[1,2,3]' }));
  assert.ok(!arr.includes('mass-assignment body'));
  const plain = names(buildVariants({ ...base(), body: 'not json' }));
  assert.ok(!plain.includes('mass-assignment body'));
});

test('every variant carries a name, note, and request', () => {
  for (const v of buildVariants(base())) {
    assert.ok(v.name && v.note && v.request);
    assert.ok(v.request.url && v.request.method);
  }
});
