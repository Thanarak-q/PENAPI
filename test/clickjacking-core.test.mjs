import test from 'node:test';
import assert from 'node:assert/strict';

import { buildClickjackPoc, defaultOptions } from '../public/js/clickjacking-core.js';

test('defaultOptions returns the documented shape', () => {
  const opts = defaultOptions();
  assert.equal(opts.decoyText, 'Click here to win!');
  assert.ok(opts.opacity > 0 && opts.opacity < 0.01, 'opacity should be near-zero');
  assert.equal(opts.top, 0);
  assert.equal(opts.left, 0);
});

test('output contains the target url in the iframe src', () => {
  const html = buildClickjackPoc({ url: 'https://example.com/login', decoyText: 'Go', opacity: 0.01, top: 0, left: 0 });
  assert.match(html, /src="https:\/\/example\.com\/login"/);
});

test('output contains the decoy text', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/', decoyText: 'Subscribe now', opacity: 0, top: 0, left: 0 });
  assert.match(html, /Subscribe now/);
});

test('opacity is clamped — value above 1 is reduced to 1', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/', decoyText: 'x', opacity: 99, top: 0, left: 0 });
  assert.match(html, /opacity: 1;/);
});

test('opacity is clamped — negative value is raised to 0', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/', decoyText: 'x', opacity: -5, top: 0, left: 0 });
  assert.match(html, /opacity: 0;/);
});

test('top and left are coerced to integers', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/', decoyText: 'x', opacity: 0.5, top: 12.9, left: 7.1 });
  assert.match(html, /top: 12px/);
  assert.match(html, /left: 7px/);
});

test('HTML-escaping — url containing quotes does not break out of src attribute', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/?a="<script>alert(1)</script>', decoyText: 'x', opacity: 0, top: 0, left: 0 });
  assert.ok(!html.includes('<script>alert(1)</script>'), 'raw <script> tag must not appear in output');
  assert.match(html, /&lt;script&gt;/);
});

test('HTML-escaping — decoyText containing angle brackets is escaped', () => {
  const html = buildClickjackPoc({ url: 'https://t.test/', decoyText: '<b>Win</b>', opacity: 0, top: 0, left: 0 });
  assert.ok(!html.includes('<b>Win</b>'), 'raw HTML in decoyText must not appear unescaped');
  assert.match(html, /&lt;b&gt;Win&lt;\/b&gt;/);
});

test('empty url yields a valid template with empty src', () => {
  const html = buildClickjackPoc({ url: '', decoyText: 'click', opacity: 0.0001, top: 0, left: 0 });
  assert.match(html, /<!DOCTYPE html>/i);
  assert.match(html, /src=""/);
  assert.match(html, /<iframe/);
});
