import test from 'node:test';
import assert from 'node:assert/strict';

import payloads from '../lib/payloads.js';

const { SETS, listSets, getSet, numericRange } = payloads;

test('listSets returns one entry per set with a correct count', () => {
  const list = listSets();
  assert.equal(list.length, Object.keys(SETS).length);
  for (const entry of list) {
    assert.ok(entry.key && entry.label);
    assert.equal(entry.count, SETS[entry.key].payloads.length);
  }
});

test('every set is non-empty and contains only non-empty strings', () => {
  for (const [key, set] of Object.entries(SETS)) {
    assert.ok(set.payloads.length > 0, `${key} is empty`);
    assert.ok(set.payloads.every((p) => typeof p === 'string' && p.length > 0), `${key} has a blank payload`);
  }
});

test('no set contains duplicate payloads', () => {
  for (const [key, set] of Object.entries(SETS)) {
    assert.equal(new Set(set.payloads).size, set.payloads.length, `${key} has duplicates`);
  }
});

test('getSet returns a copy, not the live array', () => {
  const a = getSet('sqli');
  a.push('MUTATED');
  assert.ok(!getSet('sqli').includes('MUTATED'));
});

test('getSet returns [] for an unknown key', () => {
  assert.deepEqual(getSet('does-not-exist'), []);
});

test('the new SSTI / XXE / CRLF sets are registered', () => {
  for (const key of ['ssti', 'xxe', 'crlf']) {
    assert.ok(SETS[key], `${key} not registered`);
    assert.ok(getSet(key).length > 0);
  }
});

test('the LDAP / XPath / GraphQL / redirect / email / format sets are registered', () => {
  for (const key of ['ldap', 'xpath', 'graphql', 'open-redirect', 'email-injection', 'format-fuzz']) {
    assert.ok(SETS[key], `${key} not registered`);
    assert.ok(getSet(key).length > 0);
  }
});

test('the prototype-pollution / mass-assignment / cors / unicode sets are registered', () => {
  for (const key of ['prototype-pollution', 'mass-assignment', 'cors-origins', 'unicode-bypass']) {
    assert.ok(SETS[key], `${key} not registered`);
    assert.ok(getSet(key).length > 0);
  }
});

test('the jwt-attacks / oauth-redirect / cache-deception sets are registered', () => {
  for (const key of ['jwt-attacks', 'oauth-redirect', 'cache-deception']) {
    assert.ok(SETS[key], `${key} not registered`);
    assert.ok(getSet(key).length > 0);
  }
});

test('the deserialization / file-upload / web-llm sets are registered', () => {
  for (const key of ['deserialization', 'file-upload', 'web-llm']) {
    assert.ok(SETS[key], `${key} not registered`);
    assert.ok(getSet(key).length > 0);
  }
});

test('GraphQL set includes an introspection query', () => {
  assert.ok(getSet('graphql').some((p) => /__schema/.test(p)));
});

test('SQLi set includes a cross-engine time-based payload', () => {
  assert.ok(getSet('sqli').some((p) => /pg_sleep/i.test(p)));
});

test('numericRange counts up inclusively', () => {
  assert.deepEqual(numericRange(1, 5), ['1', '2', '3', '4', '5']);
});

test('numericRange honors a step', () => {
  assert.deepEqual(numericRange(0, 10, 5), ['0', '5', '10']);
});

test('numericRange counts down when start > end', () => {
  assert.deepEqual(numericRange(3, 1), ['3', '2', '1']);
});

test('numericRange returns [] for non-numeric bounds', () => {
  assert.deepEqual(numericRange('x', 5), []);
});

test('numericRange caps output at 100000 entries', () => {
  assert.equal(numericRange(1, 10_000_000).length, 100000);
});
