// Passive analyzer for API4:2023 — Unrestricted Resource Consumption.
//
// Pure module: receives a ctx object and returns an array of finding-spec objects.
// The orchestrator calls makeFinding on each spec; do NOT call it here.
//
// ctx = { spec, endpoints, securitySchemes, history, records }
// This analyzer is endpoint-driven: it uses ctx.endpoints only.

import { MUTATING } from './shared.js';

// ---- named regex constants --------------------------------------------------

const BULK_RE     = /(bulk|batch|mass|\/all\b|import|\bsync\b|broadcast)/i;
const EXPENSIVE_RE = /(export|report|download|render|pdf|csv|xlsx|aggregat|statistic|\bstats\b|analytic|generate|recalculat|reindex|migrat|backup)/i;
const SEARCH_PARAM_RE = /(^q$|query|search|filter|regex|pattern|term|keyword|expr)/i;
const SIZE_PARAM_RE   = /(limit|per[_-]?page|page[_-]?size|count|max|rows|top|size)/i;
const GRAPHQL_RE  = /graphql|graphiql/i;
const WEBHOOK_RE  = /(webhook|callback|subscription|subscribe|notif)/i;

// ---- helpers ----------------------------------------------------------------

// True when `value` is or recursively contains an array.
function hasArray(value) {
  if (Array.isArray(value)) return true;
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some(hasArray);
}

// True when re matches the endpoint's path OR operationId.
function matchAny(re, endpoint) {
  return re.test(endpoint.path || '') || re.test(endpoint.operationId || '');
}

// ---- main export ------------------------------------------------------------

export function analyzeResourceConsumption(ctx) {
  const endpoints = Array.isArray(ctx?.endpoints) ? ctx.endpoints : [];
  const findings = [];

  for (const ep of endpoints) {
    const method = ep.method || 'GET';
    const isMutating = MUTATING.has(method);
    const queryParams = ep.params?.query || [];

    // 1. Bulk / batch operation
    if (matchAny(BULK_RE, ep) && isMutating) {
      findings.push({
        sev: 'medium',
        category: 'resource',
        title: 'Bulk/batch operation may amplify resource use',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Verify per-item limits, total size caps, and async processing are enforced.',
        owasp: 'API4:2023',
        cwe: 'CWE-770',
        confidence: 'tentative',
      });
    }

    // 2. Expensive read / generation
    if (matchAny(EXPENSIVE_RE, ep)) {
      findings.push({
        sev: 'medium',
        category: 'resource',
        title: 'Potentially expensive operation without visible limits',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Confirm async/queueing, timeouts, and result-size caps are enforced.',
        owasp: 'API4:2023',
        cwe: 'CWE-400',
        confidence: 'tentative',
      });
    }

    // 3. Free-text / regex search parameter (ReDoS + expensive query)
    for (const param of queryParams) {
      if (SEARCH_PARAM_RE.test(param.name || '')) {
        findings.push({
          sev: 'low',
          category: 'resource',
          title: 'Free-text search/filter parameter — verify query cost & ReDoS limits',
          endpoint: ep,
          evidence: param.name,
          action: 'Validate and sanitize query expressions; apply cost/timeout limits to prevent ReDoS and expensive DB scans.',
          owasp: 'API4:2023',
          cwe: 'CWE-1333',
          confidence: 'tentative',
        });
        break; // one finding per endpoint for this check
      }
    }

    // 4. Array request body without an explicit cap
    if (isMutating && ep.body?.example != null) {
      const example = ep.body.example;
      let arrayField = null;

      if (Array.isArray(example)) {
        arrayField = 'request body root';
      } else if (example && typeof example === 'object') {
        for (const [key, val] of Object.entries(example)) {
          if (hasArray(val)) {
            arrayField = key;
            break;
          }
        }
      }

      if (arrayField !== null) {
        findings.push({
          sev: 'low',
          category: 'resource',
          title: 'Array input accepted — verify maxItems / element-count cap',
          endpoint: ep,
          evidence: arrayField,
          action: 'Add a maxItems or element-count limit and reject requests that exceed it.',
          owasp: 'API4:2023',
          cwe: 'CWE-770',
          confidence: 'firm',
        });
      }
    }

    // 5. Unbounded size / limit parameter
    for (const param of queryParams) {
      if (SIZE_PARAM_RE.test(param.name || '')) {
        findings.push({
          sev: 'info',
          category: 'resource',
          title: 'Client-controlled result-size parameter — confirm a server maximum',
          endpoint: ep,
          evidence: param.name,
          action: 'Ensure the server enforces a hard maximum on this parameter to prevent data/CPU amplification.',
          owasp: 'API4:2023',
          cwe: 'CWE-770',
          confidence: 'tentative',
        });
        break; // one finding per endpoint for this check
      }
    }

    // 6. GraphQL DoS angle (distinct from the injection finding in static-analysis.js)
    if (GRAPHQL_RE.test(ep.path || '')) {
      findings.push({
        sev: 'low',
        category: 'resource',
        title: 'GraphQL endpoint — enforce query depth/complexity & disable batching if unused',
        endpoint: ep,
        evidence: ep.path,
        action: 'Apply depth limiting, query cost analysis, and disable alias/batching abuse if not needed.',
        owasp: 'API4:2023',
        cwe: 'CWE-770',
        confidence: 'tentative',
      });
    }

    // 7. Webhook / registration creating outbound work
    if (matchAny(WEBHOOK_RE, ep) && isMutating) {
      findings.push({
        sev: 'low',
        category: 'resource',
        title: 'Endpoint registers outbound work (webhook/callback) — rate-limit & validate targets',
        endpoint: ep,
        evidence: `${method} ${ep.path}`,
        action: 'Rate-limit registrations and validate target URLs to prevent amplification abuse.',
        owasp: 'API4:2023',
        cwe: 'CWE-770',
        confidence: 'tentative',
      });
    }
  }

  return findings;
}
