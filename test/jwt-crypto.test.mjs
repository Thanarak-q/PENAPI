import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import {
  algFamily, b64urlEncode, b64urlDecode,
  hmacSig, asymSign, asymVerify,
} from '../public/js/jwt-crypto.js';

function signingInput(header, payload) {
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
}

test('algFamily classifies the supported algorithms', () => {
  assert.equal(algFamily('HS256'), 'HMAC');
  assert.equal(algFamily('RS512'), 'RSA');
  assert.equal(algFamily('ES256'), 'EC');
  assert.equal(algFamily('PS256'), null);
});

test('base64url round-trips unicode', () => {
  assert.equal(b64urlDecode(b64urlEncode('héllo · 世界')), 'héllo · 世界');
});

test('HMAC signature is deterministic and verifiable', async () => {
  const si = signingInput({ alg: 'HS256' }, { sub: 1 });
  const a = await hmacSig('secret', 'HS256', si);
  const b = await hmacSig('secret', 'HS256', si);
  assert.equal(a, b);
  assert.notEqual(await hmacSig('wrong', 'HS256', si), a);
});

test('RS256 sign with private key verifies with public key', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const si = signingInput({ alg: 'RS256' }, { sub: 1, role: 'admin' });
  const sig = await asymSign('RS256', si, privateKey);
  assert.equal(await asymVerify('RS256', si, sig, publicKey), true);
  assert.equal(await asymVerify('RS256', si + 'x', sig, publicKey), false);
});

test('ES256 sign with private key verifies with public key', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const si = signingInput({ alg: 'ES256' }, { sub: 1 });
  const sig = await asymSign('ES256', si, privateKey);
  assert.equal(await asymVerify('ES256', si, sig, publicKey), true);
});

test('RS→HS confusion: HS256 signed with the public key as secret is reproducible', async () => {
  const { publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const si = signingInput({ alg: 'HS256' }, { sub: 1, role: 'admin' });
  const forged = await hmacSig(publicKey, 'HS256', si);
  // A server feeding the public key in as the HMAC secret recomputes the same.
  assert.equal(await hmacSig(publicKey, 'HS256', si), forged);
});
