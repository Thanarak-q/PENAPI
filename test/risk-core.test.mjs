import test from 'node:test';
import assert from 'node:assert/strict';

import { endpointRiskMap, SEV_RANK } from '../public/js/analyzers/risk.js';

function report(findings) {
  return { findings };
}

test('empty / missing report yields an empty map', () => {
  assert.equal(endpointRiskMap(report([])).size, 0);
  assert.equal(endpointRiskMap(undefined).size, 0);
  assert.equal(endpointRiskMap(null).size, 0);
});

test('findings without an endpointId are ignored', () => {
  const map = endpointRiskMap(report([{ sev: 'high', title: 'x', endpointId: '' }]));
  assert.equal(map.size, 0);
});

test('aggregates count, worst severity, and high/medium tallies per endpoint', () => {
  const map = endpointRiskMap(
    report([
      { sev: 'low', title: 'a', endpointId: 'GET /x' },
      { sev: 'high', title: 'b', endpointId: 'GET /x' },
      { sev: 'medium', title: 'c', endpointId: 'GET /x' },
      { sev: 'info', title: 'd', endpointId: 'POST /y' },
    ])
  );
  const x = map.get('GET /x');
  assert.equal(x.count, 3);
  assert.equal(x.worst, 'high');
  assert.equal(x.high, 1);
  assert.equal(x.medium, 1);
  assert.ok(x.score > map.get('POST /y').score);
  assert.equal(map.get('POST /y').worst, 'info');
});

test('worst severity respects the severity ranking', () => {
  assert.ok(SEV_RANK.high > SEV_RANK.medium);
  assert.ok(SEV_RANK.medium > SEV_RANK.low);
  assert.ok(SEV_RANK.low > SEV_RANK.info);
  const map = endpointRiskMap(
    report([
      { sev: 'medium', title: 'a', endpointId: 'GET /z' },
      { sev: 'low', title: 'b', endpointId: 'GET /z' },
    ])
  );
  assert.equal(map.get('GET /z').worst, 'medium');
});

test('titles are captured but capped at 6 per endpoint', () => {
  const findings = Array.from({ length: 10 }, (_, i) => ({ sev: 'low', title: `t${i}`, endpointId: 'GET /many' }));
  const map = endpointRiskMap(report(findings));
  assert.equal(map.get('GET /many').count, 10);
  assert.equal(map.get('GET /many').titles.length, 6);
  assert.match(map.get('GET /many').titles[0], /^low: t0$/);
});
