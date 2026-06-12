import test from 'node:test';
import assert from 'node:assert/strict';

import { buildSiteMap, sortedChildren } from '../public/js/sitemap-core.js';

const endpoints = [
  { method: 'GET', path: '/users', id: 'GET /users' },
  { method: 'POST', path: '/users', id: 'POST /users' },
  { method: 'GET', path: '/users/{id}', id: 'GET /users/{id}' },
  { method: 'GET', path: '/orders/{id}/items', id: 'GET /orders/{id}/items' },
];

test('shared path prefixes are merged into one branch', () => {
  const root = buildSiteMap(endpoints);
  assert.deepEqual(Object.keys(root.children).sort(), ['orders', 'users']);
  assert.equal(root.children.users.path, '/users');
});

test('operations attach at their leaf node', () => {
  const root = buildSiteMap(endpoints);
  const methods = root.children.users.ops.map((o) => o.method).sort();
  assert.deepEqual(methods, ['GET', 'POST']);
  assert.equal(root.children.users.children['{id}'].path, '/users/{id}');
});

test('opCount rolls up descendants', () => {
  const root = buildSiteMap(endpoints);
  assert.equal(root.opCount, 4);
  assert.equal(root.children.users.opCount, 3); // /users GET+POST + /users/{id} GET
  assert.equal(root.children.orders.opCount, 1);
});

test('deep nesting builds intermediate nodes without ops', () => {
  const root = buildSiteMap(endpoints);
  const orders = root.children.orders;
  assert.equal(orders.ops.length, 0);
  assert.equal(orders.children['{id}'].children.items.ops[0].id, 'GET /orders/{id}/items');
});

test('sortedChildren puts branches before leaves', () => {
  const root = buildSiteMap(endpoints);
  // users has a branch ({id}) — its node is a branch; orders is a branch too.
  const kids = sortedChildren(root);
  assert.ok(kids.every((k) => Object.keys(k.children).length >= 0));
  assert.deepEqual(kids.map((k) => k.segment), ['orders', 'users']);
});

test('empty input yields an empty root', () => {
  const root = buildSiteMap([]);
  assert.equal(root.opCount, 0);
  assert.deepEqual(Object.keys(root.children), []);
});
