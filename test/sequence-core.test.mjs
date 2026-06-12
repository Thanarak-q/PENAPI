import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getByPath,
  parseBody,
  findVars,
  interpolate,
  readValue,
  extractValues,
  evalAssertion,
  evalAssertions,
  resolveStep,
} from '../public/js/sequence-core.js';

function result(overrides = {}) {
  return {
    status: 200,
    statusText: 'OK',
    headers: { 'content-type': 'application/json', location: '/users/42' },
    body: JSON.stringify({ id: 7, user: { name: 'ada', roles: ['admin', 'user'] } }),
    ...overrides,
  };
}

test('getByPath resolves dotted and bracket paths', () => {
  const obj = { a: { b: [{ c: 9 }] } };
  assert.equal(getByPath(obj, 'a.b[0].c'), 9);
  assert.equal(getByPath(obj, 'a.b.0.c'), 9);
});

test('getByPath returns undefined for missing segments without throwing', () => {
  assert.equal(getByPath({ a: 1 }, 'a.b.c'), undefined);
  assert.equal(getByPath(null, 'a'), undefined);
});

test('parseBody returns null for non-JSON and passes objects through', () => {
  assert.equal(parseBody('not json'), null);
  assert.deepEqual(parseBody('{"x":1}'), { x: 1 });
  assert.deepEqual(parseBody({ x: 1 }), { x: 1 });
});

test('findVars lists unique tokens in order', () => {
  assert.deepEqual(findVars('{{a}}/{{b}}/{{a}}'), ['a', 'b']);
  assert.deepEqual(findVars('no tokens'), []);
});

test('interpolate substitutes known vars and leaves unknown tokens intact', () => {
  assert.equal(interpolate('/users/{{id}}', { id: 42 }), '/users/42');
  assert.equal(interpolate('/users/{{missing}}', { id: 42 }), '/users/{{missing}}');
});

test('readValue reads status, header, and body paths', () => {
  const r = result();
  assert.equal(readValue(r, { source: 'status' }), 200);
  assert.equal(readValue(r, { source: 'header', path: 'Location' }), '/users/42');
  assert.equal(readValue(r, { source: 'body', path: 'user.name' }), 'ada');
});

test('extractValues captures named values and skips undefined', () => {
  const bag = extractValues(result(), [
    { name: 'uid', source: 'body', path: 'id' },
    { name: 'missing', source: 'body', path: 'nope.gone' },
    { name: '', source: 'status' },
  ]);
  assert.deepEqual(bag, { uid: 7 });
});

test('evalAssertion handles eq, ne, contains, exists, notExists', () => {
  const r = result();
  assert.equal(evalAssertion(r, { source: 'status', op: 'eq', value: 200 }).ok, true);
  assert.equal(evalAssertion(r, { source: 'status', op: 'ne', value: 403 }).ok, true);
  assert.equal(evalAssertion(r, { source: 'body', path: 'user.name', op: 'contains', value: 'ad' }).ok, true);
  assert.equal(evalAssertion(r, { source: 'body', path: 'id', op: 'exists' }).ok, true);
  assert.equal(evalAssertion(r, { source: 'body', path: 'nope', op: 'notExists' }).ok, true);
});

test('evalAssertions passes only when every check passes', () => {
  const r = result();
  const pass = evalAssertions(r, [
    { source: 'status', op: 'eq', value: 200 },
    { source: 'body', path: 'id', op: 'exists' },
  ]);
  assert.equal(pass.ok, true);
  const fail = evalAssertions(r, [
    { source: 'status', op: 'eq', value: 200 },
    { source: 'status', op: 'eq', value: 500 },
  ]);
  assert.equal(fail.ok, false);
  assert.equal(evalAssertions(r, []).ok, true);
});

test('resolveStep interpolates url, headers, and body from the var bag', () => {
  const step = {
    method: 'post',
    url: '/users/{{uid}}/posts',
    headers: { 'X-Token': 'Bearer {{token}}' },
    body: '{"owner":{{uid}}}',
  };
  const out = resolveStep(step, { uid: 7, token: 'abc' });
  assert.equal(out.method, 'POST');
  assert.equal(out.url, '/users/7/posts');
  assert.equal(out.headers['X-Token'], 'Bearer abc');
  assert.equal(out.body, '{"owner":7}');
});
