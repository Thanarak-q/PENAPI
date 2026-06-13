import test from 'node:test';
import assert from 'node:assert/strict';

import {
  commonProbes,
  parseIntrospection,
  extractOperations,
} from '../public/js/graphql-core.js';

// Minimal introspection fixture with enveloped and bare variants.
const SCHEMA = {
  queryType: { name: 'Query' },
  mutationType: { name: 'Mutation' },
  subscriptionType: null,
  types: [
    { name: 'Query',    kind: 'OBJECT', fields: [{ name: 'users' }, { name: 'user' }] },
    { name: 'Mutation', kind: 'OBJECT', fields: [{ name: 'createUser' }, { name: 'deleteUser' }] },
    { name: 'User',     kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'name' }] },
    { name: '__Schema', kind: 'OBJECT', fields: [] },
    { name: '__Type',   kind: 'OBJECT', fields: [] },
  ],
};

const ENVELOPED = JSON.stringify({ data: { __schema: SCHEMA } });
const BARE      = JSON.stringify({ __schema: SCHEMA });

test('commonProbes returns at least 6 labeled non-empty queries', () => {
  const probes = commonProbes();
  assert.ok(probes.length >= 6);
  assert.ok(probes.every((p) => p.label && typeof p.label === 'string'));
  assert.ok(probes.every((p) => p.query && typeof p.query === 'string'));
});

test('commonProbes includes a probe containing __schema', () => {
  const probes = commonProbes();
  assert.ok(probes.some((p) => p.query.includes('__schema')));
});

test('parseIntrospection handles the full { data: { __schema } } envelope', () => {
  const r = parseIntrospection(ENVELOPED);
  assert.equal(r.ok, true);
  assert.equal(r.queryType, 'Query');
  assert.equal(r.mutationType, 'Mutation');
  assert.equal(r.subscriptionType, null);
});

test('parseIntrospection handles bare { __schema } format', () => {
  const r = parseIntrospection(BARE);
  assert.equal(r.ok, true);
  assert.equal(r.queryType, 'Query');
  assert.equal(r.mutationType, 'Mutation');
});

test('parseIntrospection filters out __-prefixed internal types', () => {
  const r = parseIntrospection(ENVELOPED);
  assert.ok(r.types.every((t) => !t.name.startsWith('__')));
  assert.ok(r.types.some((t) => t.name === 'Query'));
  assert.ok(r.types.some((t) => t.name === 'User'));
});

test('parseIntrospection returns ok:false on garbage input', () => {
  const r = parseIntrospection('not json at all }{');
  assert.equal(r.ok, false);
  assert.ok(r.error && r.error.length > 0);
  assert.deepEqual(r.types, []);
});

test('parseIntrospection returns ok:false when __schema is absent', () => {
  const r = parseIntrospection(JSON.stringify({ data: { foo: 'bar' } }));
  assert.equal(r.ok, false);
  assert.ok(r.error.includes('__schema'));
});

test('extractOperations lists query and mutation field names', () => {
  const parsed = parseIntrospection(ENVELOPED);
  const ops = extractOperations(parsed);
  assert.deepEqual(ops.queries, ['users', 'user']);
  assert.deepEqual(ops.mutations, ['createUser', 'deleteUser']);
});
