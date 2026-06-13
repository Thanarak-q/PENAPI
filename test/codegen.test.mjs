import test from 'node:test';
import assert from 'node:assert/strict';

import { toFetch, toPython, toHttpie } from '../public/js/codegen.js';

const req = (o = {}) => ({
  method: 'POST',
  url: 'https://api.example.test/users',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer x' },
  body: '{"name":"ada"}',
  ...o,
});

test('toFetch emits method, url, headers, and body', () => {
  const out = toFetch(req());
  assert.ok(out.includes('"method": "POST"'));
  assert.ok(out.includes('https://api.example.test/users'));
  assert.ok(out.includes('"Authorization": "Bearer x"'));
  assert.ok(out.includes('"body"'));
});

test('toFetch defaults the method to GET', () => {
  assert.ok(toFetch(req({ method: undefined, body: '' })).includes('"method": "GET"'));
});

test('toPython produces valid single-line strings for a multi-line body', () => {
  const out = toPython(req({ body: '{\n  "a": 1\n}' }));
  // The body must be a single-quoted Python string with escaped newlines,
  // never a literal newline inside the quotes (which would be a syntax error).
  const dataLine = out.split('\n').find((l) => l.startsWith('data = '));
  assert.ok(dataLine, 'has a data line');
  assert.ok(dataLine.includes('\\n'), 'newlines are escaped');
  assert.ok(!/data = '[^']*\n/.test(out), 'no raw newline inside the data string');
});

test('toPython escapes single quotes and backslashes in values', () => {
  const out = toPython(req({ headers: { X: "a'b\\c" }, body: '' }));
  assert.ok(out.includes("\\'"), 'single quote escaped');
  assert.ok(out.includes('\\\\'), 'backslash escaped');
  assert.ok(out.includes('verify=False'));
});

test('toHttpie quotes values with spaces and pipes a body via stdin', () => {
  const out = toHttpie(req());
  assert.ok(out.startsWith('echo '));
  assert.ok(out.includes('| http --verify=no POST'));
  assert.ok(out.includes("'Authorization:Bearer x'"));
});

test('toHttpie leaves simple tokens unquoted and defaults method', () => {
  const out = toHttpie(req({ method: undefined, headers: {}, body: '' }));
  assert.ok(out.includes('http --verify=no GET https://api.example.test/users'));
});
