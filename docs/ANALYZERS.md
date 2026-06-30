# Passive analyzer layer

Swaggernaut's **Attack Surface / Recon** view is a pluggable, OWASP-mapped passive
analysis engine. It is **pure**: analyzers never fetch, send, mutate global state,
or touch the DOM. They read the loaded spec and the saved request log and return
findings. Everything is unit-tested with `node --test`.

## Pipeline

```
analyzeSpec(spec, history)                     // public/js/static-analysis.js
  ├─ built-in spec/endpoint/log checks         // (legacy, in static-analysis.js)
  ├─ runExtraAnalyzers(ctx)                     // public/js/analyzers/index.js
  │    └─ each analyzer(ctx) -> findingSpec[]
  ├─ makeFinding(spec) for each                 // normalize
  ├─ enrich(finding)                            // attach OWASP id + CWE
  ├─ sort by severity, then category
  └─ summarize(...)                             // risk score, grade, owasp counts,
                                                //   auth coverage, category totals
```

The report is consumed by:

- `recon.js` — the Attack Surface table, cards, filters, CSV export, and the
  "Report" (Markdown) button (`report-md.js`).
- `explorer.js` — per-endpoint risk pills and the Attack Surface tab badge.
- Both go through `report.js`, which **memoizes** the report by spec reference +
  history signature so analysis runs once per change, not per render/keystroke.

## The finding contract

An analyzer is `(ctx) => findingSpec[]`. `ctx`:

```js
{ spec, endpoints, securitySchemes, history, records }
// records = eachHistory(history, endpoints) — normalized log entries:
// { method, url, path, query, status, reqHeaders, reqBody, resHeaders, resBody, isHttps, endpoint, raw }
```

A **finding spec** (plain object; the orchestrator normalizes it via `makeFinding`):

```js
{
  sev: 'high' | 'medium' | 'low' | 'info',
  category: 'security'|'idor'|'injection'|'data'|'config'|'resource'|'inventory'|'quality'|'logs',
  title: 'short label',
  endpoint,                 // real endpoint object, or { method, path, id } for a log finding
  evidence: 'supporting detail (mask secrets!)',
  action: 'remediation / next step',
  owasp: 'API8:2023',       // optional — classifier fills it if omitted
  cwe: 'CWE-352',           // optional
  confidence: 'firm' | 'tentative',
}
```

Helpers live in `analyzers/shared.js` (`getHeader`, `parseSetCookies`,
`queryFromUrl`, `objectPaths`, `tryParseJson`, `dedupeFindings`, …). OWASP/CWE
reference + classifier is `analyzers/owasp.js`.

## Current analyzers

| Module | Source | OWASP | What it finds |
| --- | --- | --- | --- |
| `response-hygiene.js` | log | API8 | CORS, security headers, cookie flags, fingerprinting, stack traces, content-type mismatch, auth rate-limit gaps |
| `pii-scan.js` | log | API3 | Cards (Luhn), SSNs, emails, JWTs, AWS/Google/Slack keys, private keys — masked |
| `auth-intelligence.js` | spec+log | API2 | Basic auth, JWT alg=none/HS*/no-exp/long-TTL, creds over HTTP, cookies without HttpOnly on auth |
| `runtime-intel.js` | log | mixed | Reflected input (XSS), open redirect, GraphQL introspection, enumerable ids, leaked error fields |
| `csrf-risk.js` | log | CWE-352 | Cookie-authed state-changing requests without anti-CSRF tokens |
| `inventory.js` | spec | API9 | Multiple/old/pre-release versions, internal routes, non-prod/plaintext base URLs |
| `resource-consumption.js` | spec | API4 | Bulk/batch, expensive exports, ReDoS params, unbounded arrays, GraphQL DoS, webhooks |
| `business-flows.js` | spec | API6 | Payment, coupon, reservation, account-security, voting, scalping flows |

`analyze.js` is the separate **live single-response** analyzer (Response panel);
it shares the OWASP taxonomy via `owasp.js` `enrich`.

## Adding an analyzer

1. Create `public/js/analyzers/<name>.js` exporting `(ctx) => findingSpec[]`.
   Import helpers from `./shared.js`; never throw on missing data.
2. Register it in `analyzers/index.js` `ANALYZERS` with a default `source`
   (`'history'` for log-driven, `'spec'` for spec-driven). If it emits both,
   set `source` per finding inside the module.
3. If you introduce a new `category`, add it to `CATEGORIES`/`CATEGORY_LABELS`
   in `static-analysis.js`, the Recon `<select>` in `public/index.html`, and the
   `categorySummary` array in `recon.js`.
4. Add `test/<name>.test.mjs`. The shared `test/analyzer-robustness.test.mjs`
   already exercises every registered analyzer against adversarial input.

Run `node --test` — pure modules are unit-tested; DOM glue is syntax-checked.
