import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';

import httpClient from '../lib/httpClient.js';

const { sendRequest, flattenHeaders, maybeDecompress } = httpClient;

function serve(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

test('flattenHeaders newline-joins Set-Cookie but comma-joins others', () => {
  assert.equal(flattenHeaders({ 'set-cookie': ['a=1', 'b=2'] })['set-cookie'], 'a=1\nb=2');
  assert.equal(flattenHeaders({ vary: ['Accept', 'Origin'] }).vary, 'Accept, Origin');
  assert.equal(flattenHeaders({ x: 'y' }).x, 'y');
});

test('maybeDecompress round-trips gzip and passes through unknown/corrupt', () => {
  assert.equal(maybeDecompress(zlib.gzipSync('hi'), 'gzip').toString(), 'hi');
  assert.equal(maybeDecompress(Buffer.from('plain'), undefined).toString(), 'plain');
  assert.equal(maybeDecompress(Buffer.from('notgzip'), 'gzip').toString(), 'notgzip');
});

test('sendRequest returns status/headers/body and keeps Set-Cookies separable', async () => {
  const { server, port } = await serve((req, res) => {
    res.setHeader('Set-Cookie', ['a=1; Expires=Wed, 21 Oct 2025 07:28:00 GMT', 'b=2; HttpOnly']);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('hello');
  });
  try {
    const out = await sendRequest({ url: `http://127.0.0.1:${port}/x` });
    assert.equal(out.status, 200);
    assert.equal(out.body, 'hello');
    const cookies = out.headers['set-cookie'].split('\n');
    assert.equal(cookies.length, 2);
    assert.ok(cookies[0].includes('a=1'));
    assert.ok(cookies[1].includes('b=2'));
  } finally {
    server.close();
  }
});

test('sendRequest transparently decompresses gzip responses', async () => {
  const { server, port } = await serve((req, res) => {
    res.writeHead(200, { 'Content-Encoding': 'gzip' });
    res.end(zlib.gzipSync('compressed-body'));
  });
  try {
    const out = await sendRequest({ url: `http://127.0.0.1:${port}/` });
    assert.equal(out.body, 'compressed-body');
  } finally {
    server.close();
  }
});

test('sendRequest sends a body with a computed Content-Length on POST', async () => {
  const { server, port } = await serve((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`${req.headers['content-length']}:${body}`);
    });
  });
  try {
    const out = await sendRequest({ url: `http://127.0.0.1:${port}/`, method: 'POST', body: 'abc' });
    assert.equal(out.body, '3:abc');
  } finally {
    server.close();
  }
});

test('sendRequest resolves an error object for an invalid URL', async () => {
  const out = await sendRequest({ url: 'not a url' });
  assert.ok(out.error);
});
