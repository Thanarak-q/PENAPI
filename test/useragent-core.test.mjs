import test from 'node:test';
import assert from 'node:assert/strict';

import {
  allAgents,
  categories,
  searchAgents,
} from '../public/js/useragent-core.js';

test('allAgents returns entries with category/label/ua', () => {
  const all = allAgents();
  assert.ok(all.length > 8);
  assert.ok(all.every((e) => 'category' in e && 'label' in e && 'ua' in e));
});

test('categories are distinct and include the main groups', () => {
  const cats = categories();
  assert.ok(cats.includes('Desktop'));
  assert.ok(cats.includes('Bot'));
  assert.ok(cats.includes('Tool'));
  assert.equal(new Set(cats).size, cats.length);
});

test('searchAgents matches by label', () => {
  const r = searchAgents('googlebot');
  assert.ok(r.some((e) => e.label === 'Googlebot'));
});

test('searchAgents matches by UA substring', () => {
  const r = searchAgents('python-requests');
  assert.ok(r.some((e) => e.category === 'Tool'));
});

test('searchAgents matches by category', () => {
  const r = searchAgents('mobile');
  assert.ok(r.length >= 2);
  assert.ok(r.every((e) => e.category === 'Mobile'));
});

test('empty query returns the whole table', () => {
  assert.equal(searchAgents('').length, allAgents().length);
});
