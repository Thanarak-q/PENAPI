// API9:2023 — Improper Inventory Management
// Detects versioning gaps, pre-release surfaces, internal routes, and host
// misconfigurations. Pure: receives ctx, returns finding spec objects only.
// The orchestrator in static-analysis.js normalises each spec through makeFinding.

const VERSION_RE = /(^|\/)(v\d+(?:\.\d+)?|version\d+|\d{4}-\d{2}-\d{2}|beta|alpha|preview|legacy|deprecated)(\/|$)/i;
const NUMERIC_VER_RE = /^(?:v\d+(?:\.\d+)?|version\d+|\d{4}-\d{2}-\d{2})$/i;
const PRERELEASE_RE = /(^|\/)(beta|alpha|preview)(\/|$)/i;
const INTERNAL_RE = /(^|\/)(internal|private|_internal|admin-api|sys|system)(\/|$)/i;
const NONPROD_HOST_RE = /(localhost|127\.0\.0\.1|0\.0\.0\.0|\.local\b|\binternal\b|\bstaging\b|\bstage\b|\bdev\b|\bdevelop\b|\bqa\b|\buat\b|\bsandbox\b|\btest\b|\bpreprod\b|\bpre-prod\b)/i;

const INTERNAL_CAP = 10;

// Extract the first version segment token from path, or null.
function versionSegment(path) {
  const m = VERSION_RE.exec(path);
  return m ? m[2].toLowerCase() : null;
}

// Extract the first pre-release segment token from path, or null.
function prereleaseSegment(path) {
  const m = PRERELEASE_RE.exec(path);
  return m ? m[2].toLowerCase() : null;
}

function isNumericVer(token) {
  return NUMERIC_VER_RE.test(token);
}

// Parse the leading numeric component so versions sort chronologically.
function numericMajor(token) {
  if (/^\d{4}-/.test(token)) return parseInt(token, 10);
  return parseInt(token.replace(/^v(?:ersion)?/i, ''), 10) || 0;
}

function checkVersions(endpoints) {
  if (!endpoints.length) return [];

  const findings = [];
  const numericVers = new Map(); // lowercased token → endpoint[]
  const prerelease = new Map();  // lowercased token → endpoint[]

  for (const ep of endpoints) {
    const seg = versionSegment(ep.path);
    if (seg && isNumericVer(seg)) {
      if (!numericVers.has(seg)) numericVers.set(seg, []);
      numericVers.get(seg).push(ep);
    }
    const pre = prereleaseSegment(ep.path);
    if (pre) {
      if (!prerelease.has(pre)) prerelease.set(pre, []);
      prerelease.get(pre).push(ep);
    }
  }

  if (numericVers.size >= 2) {
    const sorted = [...numericVers.keys()].sort((a, b) => numericMajor(a) - numericMajor(b));
    findings.push({
      sev: 'info',
      category: 'inventory',
      title: 'API exposes multiple versions',
      endpoint: null,
      evidence: sorted.join(', '),
      action: 'Confirm each version is intentional, documented, and equally hardened. Decommission stale versions.',
      owasp: 'API9:2023',
      cwe: 'CWE-1059',
      confidence: 'firm',
    });

    const maxMajor = Math.max(...sorted.map(numericMajor));
    for (const [token, eps] of numericVers) {
      if (numericMajor(token) < maxMajor) {
        findings.push({
          sev: 'medium',
          category: 'inventory',
          title: 'Older API version still exposed (potential shadow/unmaintained)',
          endpoint: null,
          evidence: `${token}: ${eps.length} operation${eps.length === 1 ? '' : 's'}`,
          action: `Determine if ${token} is actively maintained and equally protected as the latest version.`,
          owasp: 'API9:2023',
          cwe: 'CWE-1059',
          confidence: 'firm',
        });
      }
    }
  }

  for (const [token, eps] of prerelease) {
    findings.push({
      sev: 'low',
      category: 'inventory',
      title: 'Pre-release API surface exposed',
      endpoint: null,
      evidence: `${token}: ${eps.length} operation${eps.length === 1 ? '' : 's'}`,
      action: `Ensure ${token} endpoints are not reachable in production or are gated by additional access controls.`,
      owasp: 'API9:2023',
      cwe: 'CWE-1059',
      confidence: 'firm',
    });
  }

  return findings;
}

function checkInternalRoutes(endpoints) {
  const findings = [];
  let total = 0;

  for (const ep of endpoints) {
    if (!INTERNAL_RE.test(ep.path)) continue;
    total++;
    if (total <= INTERNAL_CAP) {
      findings.push({
        sev: 'medium',
        category: 'inventory',
        title: 'Internal/private route present in published spec',
        endpoint: ep,
        evidence: `${ep.method} ${ep.path}`,
        action: 'Remove internal routes from the public spec or restrict access via API gateway policies.',
        owasp: 'API9:2023',
        cwe: 'CWE-200',
        confidence: 'firm',
      });
    }
  }

  if (total > INTERNAL_CAP) {
    findings.push({
      sev: 'medium',
      category: 'inventory',
      title: 'Internal/private route present in published spec',
      endpoint: null,
      evidence: `${total} internal/private routes total (first ${INTERNAL_CAP} reported individually)`,
      action: 'Audit all internal routes and remove or restrict them from the published spec.',
      owasp: 'API9:2023',
      cwe: 'CWE-200',
      confidence: 'firm',
    });
  }

  return findings;
}

function checkBaseUrls(spec) {
  const findings = [];
  const baseUrls = spec.baseUrls || [];
  if (!baseUrls.length) return findings;

  const hasHttp = baseUrls.some((u) => u.startsWith('http://'));
  const hasHttps = baseUrls.some((u) => u.startsWith('https://'));

  for (const url of baseUrls) {
    if (NONPROD_HOST_RE.test(url)) {
      findings.push({
        sev: 'medium',
        category: 'inventory',
        title: 'Non-production server URL in spec',
        endpoint: null,
        evidence: url,
        action: 'Remove non-production server entries from the published spec or maintain a separate spec per environment.',
        owasp: 'API9:2023',
        cwe: 'CWE-200',
        confidence: 'tentative',
      });
    }
  }

  for (const url of baseUrls) {
    if (url.startsWith('http://')) {
      findings.push({
        sev: 'medium',
        category: 'inventory',
        title: 'Base URL uses plaintext HTTP',
        endpoint: null,
        evidence: url,
        action: 'Migrate all server URLs to HTTPS to protect credentials and tokens in transit.',
        owasp: 'API9:2023',
        cwe: 'CWE-319',
        confidence: 'firm',
      });
    }
  }

  if (hasHttp && hasHttps) {
    findings.push({
      sev: 'low',
      category: 'inventory',
      title: 'Mixed HTTP and HTTPS base URLs',
      endpoint: null,
      evidence: baseUrls.join(', '),
      action: 'Use HTTPS exclusively across all declared server URLs.',
      owasp: 'API9:2023',
      cwe: 'CWE-319',
      confidence: 'firm',
    });
  }

  if (baseUrls.length >= 3) {
    findings.push({
      sev: 'info',
      category: 'inventory',
      title: 'Multiple server URLs declared',
      endpoint: null,
      evidence: `${baseUrls.length} server URLs`,
      action: 'Verify each server URL is in-scope and intended for the published spec.',
      owasp: 'API9:2023',
      cwe: 'CWE-1059',
      confidence: 'firm',
    });
  }

  return findings;
}

function checkNoVersion(spec, endpoints) {
  if (!endpoints.length) return [];
  const hasVersionInPaths = endpoints.some((ep) => VERSION_RE.test(ep.path));
  if (hasVersionInPaths) return [];
  const specVersion = (spec.version || '').trim();
  if (specVersion) return [];
  return [{
    sev: 'info',
    category: 'inventory',
    title: 'No API version indicator found',
    endpoint: null,
    evidence: 'No version segment in any path; no spec version declared',
    action: 'Add an explicit version identifier (e.g. /v1/) to API paths to aid inventory tracking and change management.',
    owasp: 'API9:2023',
    cwe: 'CWE-1059',
    confidence: 'tentative',
  }];
}

export function analyzeInventory(ctx) {
  const spec = ctx.spec || {};
  const endpoints = ctx.endpoints || [];

  return [
    ...checkVersions(endpoints),
    ...checkInternalRoutes(endpoints),
    ...checkBaseUrls(spec),
    ...checkNoVersion(spec, endpoints),
  ];
}
