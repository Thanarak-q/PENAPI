// Orchestrates the pluggable passive-analyzer layer. Each analyzer is a pure
// function (ctx) -> findingSpec[]. This module runs them, concatenates their
// output, and hands the raw specs back to static-analysis.js, which normalizes
// every spec through makeFinding and enriches it with OWASP/CWE metadata.

import { eachHistory } from './shared.js';
import { analyzeResponseHygiene } from './response-hygiene.js';
import { analyzePii } from './pii-scan.js';
import { analyzeInventory } from './inventory.js';
import { analyzeResourceConsumption } from './resource-consumption.js';
import { analyzeAuthIntelligence } from './auth-intelligence.js';
import { analyzeBusinessFlows } from './business-flows.js';
import { analyzeRuntimeIntel } from './runtime-intel.js';
import { analyzeCsrfRisk } from './csrf-risk.js';

// Ordered so log-driven (observed) findings come before spec-derived heuristics.
// `source` is the default applied to findings that do not declare their own —
// log-driven analyzers are 'history', spec/endpoint analyzers are 'spec'.
// auth-intelligence emits both, so it sets its own source per finding.
const ANALYZERS = [
  { fn: analyzeResponseHygiene, source: 'history' },
  { fn: analyzePii, source: 'history' },
  { fn: analyzeAuthIntelligence, source: 'history' },
  { fn: analyzeRuntimeIntel, source: 'history' },
  { fn: analyzeCsrfRisk, source: 'history' },
  { fn: analyzeInventory, source: 'spec' },
  { fn: analyzeResourceConsumption, source: 'spec' },
  { fn: analyzeBusinessFlows, source: 'spec' },
];

export function runExtraAnalyzers({ spec, endpoints = [], securitySchemes = {}, history = [] }) {
  const records = eachHistory(history, endpoints);
  const ctx = { spec, endpoints, securitySchemes, history, records };
  const out = [];
  for (const { fn, source } of ANALYZERS) {
    try {
      const findings = fn(ctx);
      if (!Array.isArray(findings)) continue;
      for (const finding of findings) {
        out.push(finding.source ? finding : { ...finding, source });
      }
    } catch {
      // A single misbehaving analyzer must never break the whole report.
    }
  }
  return out;
}

export { ANALYZERS };
