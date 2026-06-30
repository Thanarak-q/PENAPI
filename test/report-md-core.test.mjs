import test from 'node:test';
import assert from 'node:assert/strict';

import { toMarkdownReport } from '../public/js/report-md.js';

function report(overrides = {}) {
  return {
    findings: [],
    summary: {
      total: 0,
      severities: { high: 0, medium: 0, low: 0, info: 0 },
      owasp: {},
      riskScore: 0,
      grade: 'clean',
      endpointFindings: 0,
      logFindings: 0,
      operations: 0,
      historyCount: 0,
    },
    ...overrides,
  };
}

test('renders a title, generated timestamp, and summary section', () => {
  const md = toMarkdownReport(report());
  assert.match(md, /^# Swaggernaut/);
  assert.match(md, /_Generated \d{4}-\d{2}-\d{2}T/);
  assert.match(md, /## Summary/);
  assert.match(md, /Risk score:\*\* 0 \(posture: clean\)/);
});

test('empty findings produce a "No findings" body', () => {
  const md = toMarkdownReport(report());
  assert.match(md, /## Findings/);
  assert.match(md, /_No findings\._/);
});

test('groups findings by severity with headings and numbering', () => {
  const r = report({
    findings: [
      { sev: 'high', title: 'alg=none', method: 'GET', path: '/me', owasp: 'API2:2023', cwe: 'CWE-347', confidence: 'firm', evidence: 'alg=none', action: 'reject it' },
      { sev: 'low', title: 'fingerprint', method: 'GET', path: '/x', owasp: 'API8:2023', cwe: 'CWE-200', confidence: 'firm', evidence: 'server: nginx', action: 'hide banner' },
    ],
    summary: { ...report().summary, total: 2, severities: { high: 1, medium: 0, low: 1, info: 0 }, owasp: { 'API2:2023': 1, 'API8:2023': 1 } },
  });
  const md = toMarkdownReport(r);
  assert.match(md, /### High \(1\)/);
  assert.match(md, /### Low \(1\)/);
  assert.match(md, /#### 1\. alg=none/);
  assert.match(md, /\*\*Endpoint:\*\* `GET \/me`/);
  assert.match(md, /\*\*OWASP:\*\* API2:2023/);
  assert.match(md, /\*\*Action:\*\* reject it/);
});

test('renders an OWASP coverage table when counts exist', () => {
  const r = report({ summary: { ...report().summary, owasp: { 'API2:2023': 3 } } });
  const md = toMarkdownReport(r);
  assert.match(md, /## OWASP API Security Top 10 \(2023\) coverage/);
  assert.match(md, /\| API2:2023 \| Broken Authentication \| 3 \|/);
});

test('escapes pipe characters in evidence to keep tables/lists intact', () => {
  const r = report({
    findings: [{ sev: 'info', title: 'pipe', method: '', path: '', evidence: 'a|b|c', action: '' }],
    summary: { ...report().summary, total: 1, severities: { high: 0, medium: 0, low: 0, info: 1 } },
  });
  const md = toMarkdownReport(r);
  assert.match(md, /a\\\|b\\\|c/);
});

test('tolerates a bare/empty report object', () => {
  const md = toMarkdownReport({});
  assert.match(md, /## Summary/);
  assert.match(md, /_No findings\._/);
});

test('includes target line when provided in meta', () => {
  const md = toMarkdownReport(report(), { target: 'https://api.example.test' });
  assert.match(md, /\*\*Target:\*\* https:\/\/api\.example\.test/);
});

test('ranks endpoints by aggregate risk in a Top risk endpoints table', () => {
  const r = report({
    findings: [
      { sev: 'high', title: 'a', method: 'GET', path: '/x', endpointId: 'GET /x' },
      { sev: 'medium', title: 'b', method: 'GET', path: '/x', endpointId: 'GET /x' },
      { sev: 'low', title: 'c', method: 'GET', path: '/y', endpointId: 'GET /y' },
    ],
    summary: { ...report().summary, total: 3, severities: { high: 1, medium: 1, low: 1, info: 0 } },
  });
  const md = toMarkdownReport(r);
  assert.match(md, /## Top risk endpoints/);
  // The higher-scoring endpoint (/x) must appear before the lower one (/y).
  assert.ok(md.indexOf('`GET /x`') < md.indexOf('`GET /y`'));
});

test('omits the Top risk endpoints table when no endpoint-scoped findings exist', () => {
  const md = toMarkdownReport(report());
  assert.doesNotMatch(md, /## Top risk endpoints/);
});

test('includes a remediation appendix for each triggered OWASP category', () => {
  const r = report({ summary: { ...report().summary, owasp: { 'API2:2023': 1, 'API8:2023': 2 } } });
  const md = toMarkdownReport(r);
  assert.match(md, /## Remediation by OWASP category/);
  assert.match(md, /\*\*API2:2023 Broken Authentication\*\* —/);
  assert.match(md, /\*\*API8:2023 Security Misconfiguration\*\* —/);
});

test('omits the remediation appendix when no OWASP categories triggered', () => {
  assert.doesNotMatch(toMarkdownReport(report()), /## Remediation by OWASP category/);
});
