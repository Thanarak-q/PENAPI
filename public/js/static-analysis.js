// Passive static analysis for the loaded Swaggernaut spec and local request log.
// This module is intentionally pure: it never fetches, sends, or mutates.

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const SEVERITIES = ['high', 'medium', 'low', 'info'];
const CATEGORIES = ['security', 'idor', 'injection', 'data', 'quality', 'logs'];

const SENSITIVE_PATH_RE = /\b(admin|account|accounts|billing|credential|credentials|file|files|key|keys|payment|payments|secret|secrets|session|sessions|token|tokens|user|users|webhook|webhooks)\b/i;
const IDENTIFIER_RE = /(^id$|id$|uuid|guid|slug|user|account|tenant|org|organization|project|order|invoice|file|owner|customer|member)/i;
const RISKY_PARAM_RE = /(redirect|return|next|callback|continue|url|uri|host|domain|path|file|filename|template|debug|trace|role|admin|permission|scope|filter|query|search|include|expand|sort|sql|where)/i;
const SENSITIVE_FIELD_RE = /(password|passwd|pwd|token|secret|api[_-]?key|key|credential|auth|authorization|session|cookie|role|roles|admin|permission|permissions|scope|scopes|owner|ownerId|userId|accountId|tenantId|orgId|organizationId|isAdmin|is_admin|enabled|disabled|verified|balance|credit|price|plan|ssn|socialSecurity)/i;
// Credential-like names that leak when carried in a URL (logs, history, Referer, caches).
const CREDENTIAL_PARAM_RE = /(password|passwd|pwd|^token$|_token|access[_-]?token|api[_-]?key|apikey|secret|access[_-]?key|session[_-]?id|sessionid)/i;
// Management / debug / internal surfaces that should not be publicly reachable.
const MGMT_PATH_RE = /(actuator|internal|debug|metrics|heapdump|swagger|openapi|console|trace|\benv\b|\.git|backup)/i;
// File-upload-ish endpoints worth checking for type/size/extension controls.
const UPLOAD_PATH_RE = /(upload|attachment|avatar|\bfile\b|image|media|import)/i;
const GRAPHQL_PATH_RE = /graphql|graphiql/i;
// Authentication / account endpoints worth brute-force & enumeration testing.
const AUTH_ENDPOINT_RE = /(login|signin|sign-in|authenticate|\btoken\b|\botp\b|verify|2fa|mfa|reset|forgot|password|register|signup|sign-up)/i;
// Pagination-ish query parameter names.
const PAGINATION_RE = /(limit|page|offset|per[_-]?page|page[_-]?size|cursor|\bsize\b|skip|top)/i;

const CATEGORY_LABELS = {
  security: 'Security',
  idor: 'IDOR/BOLA',
  injection: 'Injection/SSRF',
  data: 'Sensitive Data',
  quality: 'Spec Quality',
  logs: 'Request Logs',
};

export function analyzeSpec(spec, history = []) {
  const findings = [];
  const endpoints = Array.isArray(spec?.endpoints) ? spec.endpoints : [];
  const securitySchemes = spec?.securitySchemes || {};

  addSpecFindings(findings, spec, endpoints, securitySchemes);
  addEndpointFindings(findings, endpoints, securitySchemes);
  addHistoryFindings(findings, endpoints, history);

  const sorted = findings
    .map((finding, idx) => ({ id: finding.id || `finding-${idx + 1}`, ...finding }))
    .sort(compareFindings);

  return {
    findings: sorted,
    summary: summarize(sorted, endpoints, history),
    categoryLabels: CATEGORY_LABELS,
  };
}

function addSpecFindings(findings, spec, endpoints, securitySchemes) {
  if (!Array.isArray(spec?.baseUrls) || !spec.baseUrls.length || spec.baseUrls.every((url) => !url)) {
    findings.push(makeFinding({
      sev: 'info',
      category: 'quality',
      title: 'No server/base URL is defined',
      evidence: 'The loaded spec does not declare a usable base URL.',
      action: 'Set a target manually before sending human-driven requests.',
    }));
  }

  if (!endpoints.length) {
    findings.push(makeFinding({
      sev: 'info',
      category: 'quality',
      title: 'No operations found in loaded spec',
      evidence: 'The normalized endpoint list is empty.',
      action: 'Check whether the loaded document contains OpenAPI/Swagger paths.',
    }));
  }

  const referenced = new Set();
  for (const endpoint of endpoints) {
    for (const req of endpoint.security || []) {
      for (const name of Object.keys(req || {})) referenced.add(name);
    }
  }

  for (const name of referenced) {
    if (name && !securitySchemes[name]) {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'security',
        title: 'Security scheme is referenced but not defined',
        endpoint: firstEndpointUsingScheme(endpoints, name),
        evidence: `Referenced scheme: ${name}`,
        action: 'Fix the spec or verify how clients are expected to authenticate.',
      }));
    }
  }

  for (const name of Object.keys(securitySchemes)) {
    if (!referenced.has(name)) {
      findings.push(makeFinding({
        sev: 'info',
        category: 'quality',
        title: 'Security scheme is defined but unused',
        evidence: `Unused scheme: ${name}`,
        action: 'Remove stale auth metadata or apply the scheme to protected operations.',
      }));
    }
  }

  addAuthTransportFindings(findings, spec, securitySchemes);
  addDuplicateOperationIdFindings(findings, endpoints);
  addRouteAmbiguityFindings(findings, endpoints);
}

// Auth-scheme transport risks derived from the spec's security schemes + base URL.
function addAuthTransportFindings(findings, spec, securitySchemes) {
  const baseUrls = Array.isArray(spec?.baseUrls) ? spec.baseUrls : [];
  const plaintext = baseUrls.some((url) => /^http:\/\//i.test(String(url || '')));
  const usesAuth = Object.keys(securitySchemes).length > 0;
  if (plaintext && usesAuth) {
    findings.push(makeFinding({
      sev: 'high',
      category: 'security',
      title: 'Credentials may be sent over plaintext HTTP',
      evidence: baseUrls.filter((url) => /^http:\/\//i.test(String(url || ''))).join(', '),
      action: 'A non-HTTPS base URL with authentication exposes credentials/tokens to network interception — require TLS.',
    }));
  }
  for (const [name, scheme] of Object.entries(securitySchemes)) {
    if (scheme?.type === 'apiKey' && scheme?.in === 'query') {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'security',
        title: 'API key transmitted in the query string',
        evidence: `${name} (in: query, name: ${scheme.name || '?'})`,
        action: 'Query-string keys leak via access logs, browser history, and Referer headers — prefer a header.',
      }));
    }
    if (scheme?.type === 'oauth2' && scheme?.flows && (scheme.flows.implicit || scheme.flows.password)) {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'security',
        title: 'OAuth2 uses a discouraged grant (implicit/password)',
        evidence: `${name}: ${Object.keys(scheme.flows).join(', ')}`,
        action: 'Implicit and resource-owner-password grants are deprecated — prefer authorization code with PKCE.',
      }));
    }
  }
}

// Modern attack-surface hints: credentials in URL, GraphQL, file upload, and
// management/debug endpoints.
function addModernSurfaceFindings(findings, endpoint) {
  const urlParams = [...(endpoint.params?.query || []), ...(endpoint.params?.path || [])];
  const creds = urlParams.filter((param) => CREDENTIAL_PARAM_RE.test(param.name || ''));
  if (creds.length) {
    findings.push(makeFinding({
      sev: 'high',
      category: 'security',
      title: 'Credential-like value carried in the URL',
      endpoint,
      evidence: creds.map((param) => param.name).join(', '),
      action: 'Secrets in URLs leak via server logs, browser history, Referer, and shared caches — move them to a header or body.',
    }));
  }

  if (GRAPHQL_PATH_RE.test(endpoint.path)) {
    findings.push(makeFinding({
      sev: 'medium',
      category: 'injection',
      title: 'GraphQL endpoint detected',
      endpoint,
      evidence: endpoint.path,
      action: 'Test introspection, field suggestions, query batching/DoS, and per-field authorization (see the GraphQL Toolkit).',
    }));
  }

  const multipart = /multipart\/form-data/i.test(endpoint.body?.contentType || '');
  if (MUTATING.has(endpoint.method) && (multipart || UPLOAD_PATH_RE.test(endpoint.path))) {
    findings.push(makeFinding({
      sev: 'medium',
      category: 'data',
      title: 'File-upload surface',
      endpoint,
      evidence: multipart ? 'multipart/form-data body' : endpoint.path,
      action: 'Verify extension/content-type/magic-byte validation, size limits, and storage path — test the File Upload payload set.',
    }));
  }

  if (MGMT_PATH_RE.test(endpoint.path)) {
    findings.push(makeFinding({
      sev: 'medium',
      category: 'security',
      title: 'Management or debug surface exposed',
      endpoint,
      evidence: endpoint.path,
      action: 'Confirm this admin/debug/internal route is not reachable by untrusted users.',
    }));
  }

  if (MUTATING.has(endpoint.method) && AUTH_ENDPOINT_RE.test(endpoint.path)) {
    findings.push(makeFinding({
      sev: 'medium',
      category: 'security',
      title: 'Authentication / account endpoint — brute-force surface',
      endpoint,
      evidence: endpoint.path,
      action: 'Test rate limiting, credential stuffing, OTP/2FA brute force, and username enumeration.',
    }));
  }

  // Collection GET with no object id and no pagination → excessive data exposure.
  const hasPathParam = (endpoint.params?.path || []).length > 0;
  const queryNames = (endpoint.params?.query || []).map((param) => param.name || '').join(' ');
  const lastSegment = String(endpoint.path || '').split('/').filter(Boolean).pop() || '';
  if (endpoint.method === 'GET' && !hasPathParam && !/\{/.test(endpoint.path) && /s$/i.test(lastSegment) && !PAGINATION_RE.test(queryNames)) {
    findings.push(makeFinding({
      sev: 'info',
      category: 'data',
      title: 'Collection endpoint without pagination parameters',
      endpoint,
      evidence: endpoint.path,
      action: 'Confirm pagination and per-object authorization to avoid excessive data exposure.',
    }));
  }
}

function addEndpointFindings(findings, endpoints, securitySchemes) {
  for (const endpoint of endpoints) {
    const auth = authState(endpoint);
    const mutating = MUTATING.has(endpoint.method);
    const sensitivePath = SENSITIVE_PATH_RE.test(splitWords(endpoint.path).join(' '));

    if (auth.none) {
      findings.push(makeFinding({
        sev: mutating ? 'high' : 'medium',
        category: 'security',
        title: mutating
          ? 'Mutating operation has no required authentication'
          : 'Operation has no security requirement',
        endpoint,
        evidence: `${endpoint.method} ${endpoint.path}`,
        action: 'Verify whether this operation is intentionally public before testing it manually.',
      }));
    } else if (auth.optional) {
      findings.push(makeFinding({
        sev: mutating ? 'medium' : 'low',
        category: 'security',
        title: 'Authentication is optional for this operation',
        endpoint,
        evidence: 'security includes an empty requirement object `{}`.',
        action: 'Confirm anonymous access is intended and compare with human-sent logged requests.',
      }));
    }

    if ((auth.none || auth.optional) && sensitivePath) {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'security',
        title: 'Sensitive path has no required authentication',
        endpoint,
        evidence: endpoint.path,
        action: 'Prioritize this endpoint for manual authorization review.',
      }));
    }

    for (const scheme of auth.schemes) {
      if (scheme && !securitySchemes[scheme]) {
        findings.push(makeFinding({
          sev: 'medium',
          category: 'security',
          title: 'Operation references unknown security scheme',
          endpoint,
          evidence: `Unknown scheme: ${scheme}`,
          action: 'Fix the spec or verify the intended auth scheme before relying on generated clients.',
        }));
      }
    }

    addIdorFindings(findings, endpoint, auth);
    addBodyFindings(findings, endpoint);
    addParameterFindings(findings, endpoint);
    addModernSurfaceFindings(findings, endpoint);
    addQualityFindings(findings, endpoint);
  }
}

function addIdorFindings(findings, endpoint, auth) {
  const params = endpoint.params?.path || [];
  const risky = params.filter((param) => IDENTIFIER_RE.test(param.name || ''));
  if (!risky.length) return;
  findings.push(makeFinding({
    sev: auth.none || auth.optional ? 'medium' : 'low',
    category: 'idor',
    title: 'Object identifier in path',
    endpoint,
    evidence: risky.map((param) => param.name).join(', '),
    action: 'Manually compare authorized and low-privilege behavior when you choose to test this endpoint.',
  }));
}

function addBodyFindings(findings, endpoint) {
  if (!endpoint.body) return;
  const keys = objectPaths(endpoint.body.example).filter((path) => SENSITIVE_FIELD_RE.test(path));
  if (keys.length) {
    findings.push(makeFinding({
      sev: 'medium',
      category: 'data',
      title: 'Sensitive request body fields may allow mass assignment',
      endpoint,
      evidence: keys.slice(0, 8).join(', '),
      action: 'Review whether these fields are server-controlled before manually testing changes.',
    }));
  } else {
    findings.push(makeFinding({
      sev: 'info',
      category: 'data',
      title: 'Request body accepts structured input',
      endpoint,
      evidence: endpoint.body.contentType || 'request body present',
      action: 'Review body fields for over-posting and validation issues.',
    }));
  }
}

function addParameterFindings(findings, endpoint) {
  for (const location of ['query', 'header', 'cookie']) {
    for (const param of endpoint.params?.[location] || []) {
      const name = param.name || '';
      if (RISKY_PARAM_RE.test(name)) {
        findings.push(makeFinding({
          sev: location === 'query' ? 'medium' : 'low',
          category: 'injection',
          title: `Risky ${location} parameter`,
          endpoint,
          evidence: name,
          action: 'Inspect how this value is used before sending manual payloads.',
        }));
      }
      if (!param.description) {
        findings.push(makeFinding({
          sev: 'info',
          category: 'quality',
          title: 'Undocumented parameter',
          endpoint,
          evidence: `${location}: ${name}`,
          action: 'Add parameter documentation so testers can distinguish intended input from attack surface.',
        }));
      }
    }
  }
}

function addQualityFindings(findings, endpoint) {
  if (!endpoint.operationId) {
    findings.push(makeFinding({
      sev: 'low',
      category: 'quality',
      title: 'Missing operationId',
      endpoint,
      evidence: `${endpoint.method} ${endpoint.path}`,
      action: 'Add a stable operationId for generated clients and reports.',
    }));
  }

  if (!endpoint.summary && !endpoint.description) {
    findings.push(makeFinding({
      sev: 'low',
      category: 'quality',
      title: 'Missing operation summary or description',
      endpoint,
      evidence: `${endpoint.method} ${endpoint.path}`,
      action: 'Document the operation intent and security expectations.',
    }));
  }

  if (!Array.isArray(endpoint.tags) || !endpoint.tags.length || endpoint.tags.includes('default')) {
    findings.push(makeFinding({
      sev: 'info',
      category: 'quality',
      title: 'Missing specific tag',
      endpoint,
      evidence: endpoint.tags?.join(', ') || 'no tags',
      action: 'Add domain tags so triage and ownership are easier.',
    }));
  }

  if (endpoint.deprecated) {
    findings.push(makeFinding({
      sev: 'low',
      category: 'quality',
      title: 'Deprecated operation remains exposed',
      endpoint,
      evidence: `${endpoint.method} ${endpoint.path}`,
      action: 'Confirm the operation is still required and protected.',
    }));
  }

  const tokens = pathTokens(endpoint.path);
  const pathParams = endpoint.params?.path || [];
  const paramNames = new Set(pathParams.map((param) => param.name));

  for (const token of tokens) {
    if (!paramNames.has(token)) {
      findings.push(makeFinding({
        sev: 'low',
        category: 'quality',
        title: 'Path token missing matching parameter',
        endpoint,
        evidence: `{${token}}`,
        action: 'Declare a required path parameter for every template token.',
      }));
    }
  }

  for (const param of pathParams) {
    if (!tokens.includes(param.name)) {
      findings.push(makeFinding({
        sev: 'low',
        category: 'quality',
        title: 'Path parameter not present in path template',
        endpoint,
        evidence: param.name,
        action: 'Remove stale path parameter metadata or fix the path template.',
      }));
    }
    if (!param.required) {
      findings.push(makeFinding({
        sev: 'low',
        category: 'quality',
        title: 'Path parameter is not marked required',
        endpoint,
        evidence: param.name,
        action: 'OpenAPI path parameters should always be required.',
      }));
    }
    if (!param.description) {
      findings.push(makeFinding({
        sev: 'info',
        category: 'quality',
        title: 'Undocumented parameter',
        endpoint,
        evidence: `path: ${param.name}`,
        action: 'Document object ownership and expected values.',
      }));
    }
  }
}

function addHistoryFindings(findings, endpoints, history) {
  if (!Array.isArray(history) || !history.length) return;

  for (const entry of history.slice(0, 200)) {
    const method = (entry.request?.method || entry.method || 'GET').toUpperCase();
    const url = entry.request?.url || entry.url || '';
    const path = pathFromUrl(url);
    const endpoint = matchEndpoint(endpoints, method, path);
    const status = Number(entry.response?.status ?? entry.status ?? 0);
    const reqHeaders = lowerHeaders(entry.request?.headers || {});
    const response = entry.response || {};

    if (!endpoint) {
      findings.push(makeFinding({
        sev: status >= 500 ? 'medium' : 'low',
        category: 'logs',
        title: 'Request log entry is not described by the loaded spec',
        endpoint: { method, path, id: `${method} ${path}` },
        source: 'history',
        evidence: `${status || 'ERR'} ${method} ${path}`,
        action: 'Decide whether this is a hidden endpoint, stale spec, or request to a different API.',
      }));
    } else if (status >= 200 && status < 300 && hasRequiredAuth(endpoint) && !hasAuthHeader(reqHeaders)) {
      findings.push(makeFinding({
        sev: 'high',
        category: 'security',
        title: 'Authenticated endpoint succeeded without auth header in request log',
        endpoint,
        source: 'history',
        evidence: `${status} ${method} ${path}`,
        action: 'Review the saved human-sent request and confirm whether another auth mechanism was present.',
      }));
    }

    if (status >= 500) {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'logs',
        title: 'Server error observed in request log',
        endpoint: endpoint || { method, path, id: `${method} ${path}` },
        source: 'history',
        evidence: `${status} ${method} ${path}`,
        action: 'Inspect the logged request/response details before reproducing manually.',
      }));
    }

    const leaks = sensitiveLogEvidence(response);
    if (leaks.length) {
      findings.push(makeFinding({
        sev: 'medium',
        category: 'data',
        title: 'Sensitive data observed in response log',
        endpoint: endpoint || { method, path, id: `${method} ${path}` },
        source: 'history',
        evidence: leaks.slice(0, 6).join(', '),
        action: 'Review whether these values are expected in the response and should be redacted in reports.',
      }));
    }
  }
}

function addDuplicateOperationIdFindings(findings, endpoints) {
  const byId = new Map();
  for (const endpoint of endpoints) {
    if (!endpoint.operationId) continue;
    const list = byId.get(endpoint.operationId) || [];
    list.push(endpoint);
    byId.set(endpoint.operationId, list);
  }
  for (const [operationId, list] of byId) {
    if (list.length < 2) continue;
    for (const endpoint of list) {
      findings.push(makeFinding({
        sev: 'low',
        category: 'quality',
        title: 'Duplicate operationId',
        endpoint,
        evidence: `${operationId} is used by ${list.length} operations.`,
        action: 'Make operationId values unique for clean client generation and reporting.',
      }));
    }
  }
}

function addRouteAmbiguityFindings(findings, endpoints) {
  const byTemplate = new Map();
  for (const endpoint of endpoints) {
    const key = `${endpoint.method} ${canonicalPath(endpoint.path)}`;
    const list = byTemplate.get(key) || [];
    list.push(endpoint);
    byTemplate.set(key, list);
  }
  for (const list of byTemplate.values()) {
    if (list.length < 2) continue;
    for (const endpoint of list) {
      findings.push(makeFinding({
        sev: 'info',
        category: 'quality',
        title: 'Similar route template may be ambiguous',
        endpoint,
        evidence: list.map((item) => item.path).join(', '),
        action: 'Confirm route precedence and generated clients handle these templates correctly.',
      }));
    }
  }
}

function makeFinding({ sev, category, title, endpoint, evidence, action, source = 'spec' }) {
  return {
    sev,
    category,
    title,
    source,
    method: endpoint?.method || '',
    path: endpoint?.path || '',
    endpointId: endpoint?.id || '',
    evidence: evidence || '',
    action: action || '',
  };
}

function summarize(findings, endpoints, history) {
  const severities = Object.fromEntries(SEVERITIES.map((sev) => [sev, 0]));
  const categories = Object.fromEntries(CATEGORIES.map((category) => [category, 0]));
  let endpointFindings = 0;
  let logFindings = 0;

  for (const finding of findings) {
    if (severities[finding.sev] != null) severities[finding.sev]++;
    if (categories[finding.category] != null) categories[finding.category]++;
    if (finding.source === 'history') logFindings++;
    else endpointFindings++;
  }

  return {
    total: findings.length,
    severities,
    categories,
    endpointFindings,
    logFindings,
    operations: endpoints.length,
    historyCount: Array.isArray(history) ? history.length : 0,
  };
}

function authState(endpoint) {
  const security = Array.isArray(endpoint.security) ? endpoint.security : [];
  const none = security.length === 0;
  const optional = security.some((req) => req && Object.keys(req).length === 0);
  const schemes = [...new Set(security.flatMap((req) => Object.keys(req || {})))];
  return { none, optional, schemes };
}

function hasRequiredAuth(endpoint) {
  const auth = authState(endpoint);
  return !auth.none && !auth.optional && auth.schemes.length > 0;
}

function firstEndpointUsingScheme(endpoints, scheme) {
  return endpoints.find((endpoint) =>
    (endpoint.security || []).some((req) => Object.prototype.hasOwnProperty.call(req || {}, scheme))
  );
}

function pathTokens(path) {
  return [...String(path || '').matchAll(/\{([^}/]+)\}/g)].map((match) => match[1]);
}

function objectPaths(value, prefix = '') {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap((item) => objectPaths(item, prefix));
  const out = [];
  for (const [key, next] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    out.push(path);
    out.push(...objectPaths(next, path));
  }
  return out;
}

function splitWords(value) {
  return String(value || '')
    .replace(/[{}._-]/g, '/')
    .split(/[/?#&=:/]+/)
    .filter(Boolean);
}

function canonicalPath(path) {
  return String(path || '')
    .replace(/\/+$/, '')
    .replace(/\{[^}]+\}/g, '{}')
    .toLowerCase() || '/';
}

function compareFindings(a, b) {
  const sev = SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev);
  if (sev) return sev;
  const cat = CATEGORIES.indexOf(a.category) - CATEGORIES.indexOf(b.category);
  if (cat) return cat;
  return `${a.method} ${a.path} ${a.title}`.localeCompare(`${b.method} ${b.path} ${b.title}`);
}

function pathFromUrl(url) {
  try {
    return new URL(url).pathname || '/';
  } catch {
    const raw = String(url || '');
    const noQuery = raw.split(/[?#]/)[0];
    return noQuery || '/';
  }
}

function matchEndpoint(endpoints, method, path) {
  return endpoints.find((endpoint) => endpoint.method === method && pathPattern(endpoint.path).test(path));
}

function pathPattern(path) {
  const escaped = String(path || '/')
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\{[^}]+\\\}/g, '[^/]+');
  return new RegExp(`^${escaped}/?$`);
}

function lowerHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) out[key.toLowerCase()] = value;
  return out;
}

function hasAuthHeader(headers) {
  return Boolean(
    headers.authorization ||
      headers.cookie ||
      headers['x-api-key'] ||
      headers['api-key'] ||
      headers['x-auth-token']
  );
}

function sensitiveLogEvidence(response) {
  const hits = [];
  const headers = lowerHeaders(response.headers || {});
  for (const name of Object.keys(headers)) {
    if (SENSITIVE_FIELD_RE.test(name)) hits.push(`header:${name}`);
  }
  const body = String(response.body || '');
  if (!body) return hits;
  try {
    hits.push(...objectPaths(JSON.parse(body)).filter((path) => SENSITIVE_FIELD_RE.test(path)).map((path) => `body:${path}`));
  } catch {
    const textHits = body.match(/\b(password|token|secret|api[_-]?key|authorization|session)\b/gi) || [];
    hits.push(...[...new Set(textHits)].map((hit) => `body:${hit}`));
  }
  return [...new Set(hits)];
}
