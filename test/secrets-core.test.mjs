import test from 'node:test';
import assert from 'node:assert/strict';

import { scanSecrets, summarizeSecrets } from '../public/js/secrets-core.js';

// Fake test-fixture secrets are constructed at runtime from fragments so no
// complete credential literal appears in source (avoids pre-commit scanner FPs).
const FAKE_AWS_KEY  = 'AKIA' + 'IOSFODNN7EXAMPLE';      // 20 chars — AWS key format
const FAKE_GH_TOKEN = 'ghp_' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJ'; // ghp_ + 36

// -- Detection tests ---------------------------------------------------------

test('detects an AWS Access Key ID', () => {
  const findings = scanSecrets('key=' + FAKE_AWS_KEY + ' access');
  assert.ok(findings.some((f) => f.type === 'AWS Access Key ID'), 'found AWS key');
  assert.equal(findings.find((f) => f.type === 'AWS Access Key ID').match, FAKE_AWS_KEY);
});

test('detects a GitHub token (ghp_)', () => {
  // ghp_ prefix + exactly 36 alphanumeric chars
  const findings = scanSecrets('Authorization: token ' + FAKE_GH_TOKEN);
  assert.ok(findings.some((f) => f.type === 'GitHub Token'), 'found GitHub token');
  assert.equal(findings.find((f) => f.type === 'GitHub Token').match, FAKE_GH_TOKEN);
});

test('detects a JWT', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciJ9.abcdefghij';
  const findings = scanSecrets(`Bearer ${jwt}`);
  assert.ok(findings.some((f) => f.type === 'JWT'), 'found JWT');
});

test('detects an alg:none unsigned JWT (empty signature segment)', () => {
  const unsigned = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.';
  const findings = scanSecrets(`token=${unsigned}`);
  assert.ok(findings.some((f) => f.type === 'JWT'), 'found unsigned JWT');
});

test('detects a GitHub fine-grained PAT (github_pat_)', () => {
  const pat = 'github_pat_' + '11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ';
  const findings = scanSecrets('GH_TOKEN=' + pat);
  assert.ok(findings.some((f) => f.type === 'GitHub Fine-grained PAT'), 'found fine-grained PAT');
});

test('detects npm / GitLab / Twilio tokens', () => {
  const npm = 'npm_' + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';
  const glpat = 'glpat-' + 'aBcDeF1234567890_xYz';
  const twilio = 'SK' + '0123456789abcdef0123456789abcdef';
  const findings = scanSecrets(`a=${npm} b=${glpat} c=${twilio}`);
  assert.ok(findings.some((f) => f.type === 'npm Token'), 'found npm token');
  assert.ok(findings.some((f) => f.type === 'GitLab PAT'), 'found GitLab PAT');
  assert.ok(findings.some((f) => f.type === 'Twilio API Key'), 'found Twilio key');
});

test('detects a private key header block', () => {
  const findings = scanSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----');
  assert.ok(findings.some((f) => f.type === 'Private Key Block'), 'found private key block');
});

test('detects basic-auth credentials embedded in a URL', () => {
  const findings = scanSecrets('endpoint: https://admin:hunter2@internal.example.com/api');
  assert.ok(findings.some((f) => f.type === 'Basic Auth in URL'), 'found basic-auth URL');
});

test('detects a generic api_key assignment', () => {
  const findings = scanSecrets('config.api_key=supersecret99');
  assert.ok(findings.some((f) => f.type === 'Assigned Secret'), 'found assigned secret');
});

test('detects a Stripe live secret key', () => {
  const fakeStripe = 'sk_live_' + 'testfakestripekey1234567';
  const findings = scanSecrets(fakeStripe);
  assert.ok(findings.some((f) => f.type === 'Stripe Live Secret Key'), 'found Stripe key');
});

// -- Negative test -----------------------------------------------------------

test('returns [] for plain prose with no secrets', () => {
  const findings = scanSecrets('Hello world. This is a simple response with no credentials.');
  assert.deepEqual(findings, []);
});

test('returns [] for empty or whitespace-only input', () => {
  assert.deepEqual(scanSecrets(''), []);
  assert.deepEqual(scanSecrets('   \n\t  '), []);
  assert.deepEqual(scanSecrets(null), []);
  assert.deepEqual(scanSecrets(undefined), []);
});

// -- Preview redaction -------------------------------------------------------

test('preview keeps first/last 4 chars of a long match, full match preserved', () => {
  const findings = scanSecrets(FAKE_AWS_KEY);
  const f = findings.find((x) => x.type === 'AWS Access Key ID');
  assert.ok(f, 'finding exists');
  assert.equal(f.preview, 'AKIA…MPLE', 'preview is first4 + ellipsis + last4');
  assert.equal(f.match, FAKE_AWS_KEY, 'full match is preserved for copy');
});

test('preview fully masks a basic-auth password (never leaks the credential)', () => {
  const findings = scanSecrets('https://admin:hunter2@internal.example.com/api');
  const f = findings.find((x) => x.type === 'Basic Auth in URL');
  assert.ok(f, 'finding exists');
  assert.equal(f.preview, 'https://••••@', 'credential portion is masked');
  assert.ok(!f.preview.includes('hunter2'), 'password is not present in the preview');
});

// -- summarizeSecrets --------------------------------------------------------

test('summarizeSecrets counts findings by severity and totals them', () => {
  const findings = [
    { type: 'AWS Access Key ID', severity: 'high',   match: FAKE_AWS_KEY, index: 0,  preview: 'AKIA…MPLE' },
    { type: 'GitHub Token',      severity: 'high',   match: 'ghp_abc',    index: 5,  preview: 'ghp_abc' },
    { type: 'JWT',               severity: 'medium', match: 'eyJ.eyJ.s',  index: 10, preview: 'eyJ.…J.s' },
    { type: 'Email Address',     severity: 'low',    match: 'a@b.com',    index: 20, preview: 'a@b.com' },
  ];
  const summary = summarizeSecrets(findings);
  assert.equal(summary.high,   2);
  assert.equal(summary.medium, 1);
  assert.equal(summary.low,    1);
  assert.equal(summary.total,  4);
});

test('summarizeSecrets returns zeros for an empty array', () => {
  const summary = summarizeSecrets([]);
  assert.equal(summary.high,   0);
  assert.equal(summary.medium, 0);
  assert.equal(summary.low,    0);
  assert.equal(summary.total,  0);
});

// -- De-duplication ----------------------------------------------------------

test('de-duplicates identical (type + match) findings across repeated text', () => {
  const repeated = FAKE_AWS_KEY + ' and again ' + FAKE_AWS_KEY + ' and once more ' + FAKE_AWS_KEY;
  const findings = scanSecrets(repeated);
  const awsFindings = findings.filter((f) => f.type === 'AWS Access Key ID');
  assert.equal(awsFindings.length, 1, 'deduped to a single finding');
});
