import test from 'node:test';
import assert from 'node:assert/strict';

import { buildMultipart, bytesToBase64 } from '../public/js/multipart-core.js';

test('buildMultipart emits a text field part with the boundary', () => {
  const { contentType, bytes } = buildMultipart([{ name: 'a', value: 'hello' }]);
  assert.match(contentType, /^multipart\/form-data; boundary=----Swaggernaut/);
  const text = Buffer.from(bytes).toString('latin1');
  assert.match(text, /Content-Disposition: form-data; name="a"\r\n\r\nhello\r\n/);
  assert.match(text, /----SwaggernautBoundary7MA4YWxkTrZu0gW--\r\n$/);
});

test('buildMultipart writes a file part with filename + content-type', () => {
  const { bytes } = buildMultipart([
    { name: 'upload', value: new Uint8Array([1, 2, 3]), filename: 'x.bin', contentType: 'application/octet-stream' },
  ]);
  const text = Buffer.from(bytes).toString('latin1');
  assert.match(text, /name="upload"; filename="x.bin"/);
  assert.match(text, /Content-Type: application\/octet-stream/);
});

test('binary bytes survive the base64 round-trip intact', () => {
  const payload = new Uint8Array([0, 1, 2, 254, 255, 128, 10, 13]);
  const { bytes } = buildMultipart([{ name: 'f', value: payload, filename: 'b', contentType: 'x/y' }]);
  const roundTripped = new Uint8Array(Buffer.from(bytesToBase64(bytes), 'base64'));
  assert.deepEqual(roundTripped, bytes);
  // and the raw binary bytes appear verbatim inside the assembled body
  const idx = Buffer.from(bytes).indexOf(Buffer.from(payload));
  assert.ok(idx > 0, 'file bytes embedded unchanged');
});

test('bytesToBase64 matches Node Buffer base64', () => {
  const bytes = new Uint8Array([72, 101, 108, 108, 111]);
  assert.equal(bytesToBase64(bytes), Buffer.from(bytes).toString('base64'));
});
