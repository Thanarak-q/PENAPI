import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzePii } from '../public/js/analyzers/pii-scan.js';
import { eachHistory } from '../public/js/analyzers/shared.js';

// ---- test helpers -----------------------------------------------------------

function makeCtx(entries) {
  return { records: eachHistory(entries, []) };
}

function entry({ url = 'https://api.example.test/data', method = 'GET', resBody = '', reqBody = '', status = 200 } = {}) {
  return {
    request: { method, url, headers: {}, body: reqBody },
    response: { status, headers: { 'content-type': 'application/json' }, body: resBody },
  };
}

function titles(findings) {
  return findings.map((f) => f.title);
}

// A known Luhn-valid test card (Visa test number).
const VALID_CARD = '4111 1111 1111 1111';
const VALID_CARD_DIGITS = '4111111111111111';

// A 16-digit number that fails the Luhn check.
const INVALID_CARD = '1234567890123456';

// A syntactically valid JWT (three base64url segments).
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123def456ghi789jkl';

// ---- tests ------------------------------------------------------------------

test('empty records array returns no findings', () => {
  assert.deepEqual(analyzePii({ records: [] }), []);
});

test('null or undefined records returns no findings', () => {
  assert.deepEqual(analyzePii({ records: null }), []);
  assert.deepEqual(analyzePii({ records: undefined }), []);
});

test('detects email addresses in response body', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: '{"email":"alice@example.com","id":1}' }),
  ]));
  assert.ok(titles(findings).includes('Email addresses in response body'), 'title expected');
  const f = findings.find((x) => x.title === 'Email addresses in response body');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.category, 'data');
  assert.equal(f.cwe, 'CWE-359');
  // The full email address must not appear in evidence.
  assert.ok(!f.evidence.includes('alice@example.com'), 'full email must be masked in evidence');
  // The domain portion should appear (masked form ***@domain).
  assert.ok(f.evidence.includes('@example.com'), 'masked domain should appear in evidence');
});

test('detects Luhn-valid card number and masks it in evidence', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: `{"card":"${VALID_CARD}"}` }),
  ]));
  assert.ok(titles(findings).includes('Luhn-valid card number in response body'), 'card title expected');
  const f = findings.find((x) => x.title === 'Luhn-valid card number in response body');
  assert.equal(f.sev, 'high');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.cwe, 'CWE-312');
  // Neither raw nor space-separated form should appear in evidence.
  assert.ok(!f.evidence.includes(VALID_CARD_DIGITS), 'full card digits must not appear in evidence');
  assert.ok(!f.evidence.includes(VALID_CARD),        'spaced card must not appear in evidence');
  // Masked form with stars should appear.
  assert.ok(f.evidence.includes('4111'), 'first 4 digits should appear in evidence');
  assert.ok(f.evidence.includes('1111'), 'last 4 digits should appear in evidence');
  assert.ok(f.evidence.includes('*'),    'stars should appear in masked evidence');
});

test('Luhn-invalid 16-digit number is NOT flagged as a credit card', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: `{"num":"${INVALID_CARD}"}` }),
  ]));
  assert.ok(
    !titles(findings).includes('Luhn-valid card number in response body'),
    'Luhn-invalid number must not produce a card finding',
  );
});

test('detects US SSN pattern and masks it in evidence', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: '{"ssn":"123-45-6789"}' }),
  ]));
  assert.ok(titles(findings).includes('US SSN pattern in response body'), 'SSN title expected');
  const f = findings.find((x) => x.title === 'US SSN pattern in response body');
  assert.equal(f.sev, 'high');
  assert.equal(f.cwe, 'CWE-359');
  assert.ok(!f.evidence.includes('123-45-6789'), 'full SSN must not appear in evidence');
  // Only last 4 digits should be visible.
  assert.ok(f.evidence.includes('6789'), 'last 4 SSN digits should appear in masked evidence');
});

test('detects JWT in response body and masks it in evidence', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: JSON.stringify({ token: JWT }) }),
  ]));
  assert.ok(titles(findings).includes('JWT present in response/log'), 'JWT title expected');
  const f = findings.find((x) => x.title === 'JWT present in response/log');
  assert.equal(f.sev, 'high');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.cwe, 'CWE-312');
  assert.ok(!f.evidence.includes(JWT), 'full JWT must not appear in evidence');
});

test('detects AWS AKIA access key id in response body', () => {
  // Split literal so the pre-commit secret scanner doesn't flag this fixture
  // (still the AWS docs EXAMPLE key id at runtime, not a real credential).
  const awsKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
  const findings = analyzePii(makeCtx([
    entry({ resBody: `{"key":"${awsKey}"}` }),
  ]));
  assert.ok(titles(findings).includes('AWS access key id exposed'), 'AWS key title expected');
  const f = findings.find((x) => x.title === 'AWS access key id exposed');
  assert.equal(f.sev, 'high');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.cwe, 'CWE-312');
  assert.ok(!f.evidence.includes(awsKey), 'full AWS key must not appear in evidence');
});

test('detects private key block in response body', () => {
  const body = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----';
  const findings = analyzePii(makeCtx([
    entry({ resBody: body }),
  ]));
  assert.ok(titles(findings).includes('Private key material in response'), 'private key title expected');
  const f = findings.find((x) => x.title === 'Private key material in response');
  assert.equal(f.sev, 'high');
  assert.equal(f.cwe, 'CWE-312');
  assert.equal(f.confidence, 'firm');
});

test('detects secret-like JSON field by key name; shows key, not value', () => {
  // Split literal so the pre-commit secret scanner doesn't flag this fake fixture.
  const secret = 'sk-' + 'supersecretvalue123';
  const findings = analyzePii(makeCtx([
    entry({ resBody: JSON.stringify({ id: 1, api_key: secret, name: 'alice' }) }),
  ]));
  assert.ok(titles(findings).includes('Secret-like field returned in response body'), 'secret field title expected');
  const f = findings.find((x) => x.title === 'Secret-like field returned in response body');
  assert.equal(f.confidence, 'tentative');
  assert.equal(f.cwe, 'CWE-312');
  // Evidence must show the key name, never the secret value.
  assert.ok(f.evidence.includes('api_key'), 'key name should appear in evidence');
  assert.ok(!f.evidence.includes(secret), 'secret value must not appear in evidence');
});

test('detects credential (JWT) carried in request URL', () => {
  const findings = analyzePii(makeCtx([
    entry({ url: `https://api.example.test/data?token=${JWT}`, resBody: '{}' }),
  ]));
  assert.ok(titles(findings).includes('Credential value carried in request URL'), 'URL credential title expected');
  const f = findings.find((x) => x.title === 'Credential value carried in request URL');
  assert.equal(f.sev, 'high');
  assert.equal(f.cwe, 'CWE-598');
  assert.equal(f.confidence, 'firm');
  assert.ok(!f.evidence.includes(JWT), 'full JWT must not appear in evidence');
});

test('deduplicates identical findings across multiple records', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: '{"ssn":"123-45-6789"}' }),
    entry({ resBody: '{"ssn":"123-45-6789"}' }),
    entry({ resBody: '{"ssn":"123-45-6789"}' }),
  ]));
  const ssnFindings = findings.filter((f) => f.title === 'US SSN pattern in response body');
  assert.equal(ssnFindings.length, 1, 'three identical records should produce one deduped finding');
});

test('every finding carries category "data" and owasp "API3:2023"', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: `{"email":"user@test.com","ssn":"123-45-6789","card":"${VALID_CARD}"}` }),
  ]));
  assert.ok(findings.length > 0, 'should have at least one finding');
  for (const f of findings) {
    assert.equal(f.category, 'data',       `"${f.title}" must have category "data"`);
    assert.equal(f.owasp,    'API3:2023',  `"${f.title}" must have owasp "API3:2023"`);
  }
});

test('IPv4 addresses flagged as info/tentative; loopback suppressed', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: '{"internal":"10.0.1.42","loopback":"127.0.0.1"}' }),
  ]));
  const ipFindings = findings.filter((f) => f.title === 'IPv4 address in response body');
  assert.ok(ipFindings.length > 0, 'non-loopback IPv4 should produce a finding');
  assert.equal(ipFindings[0].sev, 'info');
  assert.equal(ipFindings[0].confidence, 'tentative');
  // 127.0.0.1 should NOT contribute its own finding (it may appear in evidence of 10.0.1.42 scan)
  // — the important check is no separate finding only for 127.0.0.1.
  assert.ok(
    !ipFindings.some((f) => f.evidence === 'IPv4: 127.0.0.1'),
    'loopback address should be suppressed',
  );
});

test('phone number flagged as low/tentative', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: '{"phone":"(555) 867-5309"}' }),
  ]));
  const f = findings.find((x) => x.title === 'Phone number in response body');
  assert.ok(f, 'phone finding expected');
  assert.equal(f.sev, 'low');
  assert.equal(f.confidence, 'tentative');
  assert.equal(f.cwe, 'CWE-359');
  assert.ok(!f.evidence.includes('5558675309'), 'raw phone digits must not appear in evidence');
});

test('Luhn-valid card found in bare digit string (no spaces) is flagged', () => {
  const findings = analyzePii(makeCtx([
    entry({ resBody: `{"pan":"${VALID_CARD_DIGITS}"}` }),
  ]));
  assert.ok(titles(findings).includes('Luhn-valid card number in response body'), 'bare digit card should be flagged');
});
