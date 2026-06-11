'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const { parseSpec } = require('./lib/specParser');
const { sendRequest } = require('./lib/httpClient');
const { parseCurl, toCurl } = require('./lib/curl');
const { buildVariants } = require('./lib/attacks');
const payloads = require('./lib/payloads');

// ---- CLI / config ------------------------------------------------------

function parseArgs(argv) {
  const cfg = {
    port: process.env.PORT || 7331,
    host: process.env.HOST || '127.0.0.1',
    spec: process.env.SPEC || null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port' || a === '-p') cfg.port = argv[++i];
    else if (a === '--host') cfg.host = argv[++i];
    else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else if (!a.startsWith('-')) cfg.spec = a;
  }
  // Auto-detect a spec in the current directory when none was given.
  if (!cfg.spec) {
    for (const name of ['swagger.json', 'openapi.json', 'swagger.yaml', 'openapi.yaml']) {
      const p = path.join(process.cwd(), name);
      if (fs.existsSync(p)) {
        cfg.spec = p;
        break;
      }
    }
  }
  return cfg;
}

function printHelp() {
  console.log(`PenAPI — pentest API workbench

Usage:
  penapi [spec] [options]

Arguments:
  spec               Path or URL to an OpenAPI/Swagger JSON document.
                     If omitted, looks for swagger.json / openapi.json in the
                     current directory. You can also load one from the UI.

Options:
  -p, --port <n>     Port to listen on        (default 7331, env PORT)
      --host <h>     Host/interface to bind    (default 127.0.0.1, env HOST)
  -h, --help         Show this help

Examples:
  penapi ./swagger.json
  penapi https://target.example/v3/api-docs --port 8080
  SPEC=./openapi.json penapi`);
}

const cfg = parseArgs(process.argv.slice(2));
const PORT = cfg.port;
const HOST = cfg.host;
let specSource = cfg.spec; // path, URL, or null (loaded later via UI)

const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// Cache the parsed spec so a large file/URL is only read & parsed once.
let cachedSpec = null;

async function parseSource(src) {
  let raw;
  if (/^https?:\/\//i.test(src)) {
    const r = await fetch(src);
    if (!r.ok) throw new Error(`Fetch spec failed: HTTP ${r.status}`);
    raw = await r.text();
  } else {
    raw = fs.readFileSync(src, 'utf8');
  }
  return parseSpec(JSON.parse(raw));
}

async function loadSpec() {
  if (cachedSpec) return cachedSpec;
  if (!specSource) {
    throw new Error('No spec loaded. Pass a file/URL on the CLI or load one from the UI.');
  }
  cachedSpec = await parseSource(specSource);
  return cachedSpec;
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 50 * 1024 * 1024) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function parseJsonBody(req) {
  const text = await readBody(req);
  if (!text) return {};
  return JSON.parse(text);
}

// ---- Fuzzer ------------------------------------------------------------

const MARKER = /§([^§]*)§|\bFUZZ\b/;

function hasMarker(req) {
  return (
    MARKER.test(req.url || '') ||
    MARKER.test(req.body || '') ||
    Object.values(req.headers || {}).some((v) => MARKER.test(String(v)))
  );
}

function injectMarker(template, payload) {
  const out = {
    method: template.method,
    url: replaceMarker(template.url || '', payload),
    body: template.body != null ? replaceMarker(template.body, payload) : template.body,
    headers: {},
  };
  for (const [k, v] of Object.entries(template.headers || {})) {
    out.headers[k] = replaceMarker(String(v), payload);
  }
  return out;
}

function replaceMarker(str, payload) {
  // Replace §...§ (keeping nothing) or bare FUZZ token with the payload.
  return str.replace(/§[^§]*§/g, payload).replace(/\bFUZZ\b/g, payload);
}

function resolvePayloads(cfg) {
  let list = [];
  if (cfg.builtin) list = list.concat(payloads.getSet(cfg.builtin));
  if (cfg.range && cfg.range.start != null && cfg.range.end != null) {
    list = list.concat(
      payloads.numericRange(cfg.range.start, cfg.range.end, cfg.range.step)
    );
  }
  if (cfg.custom) {
    list = list.concat(
      String(cfg.custom)
        .split('\n')
        .map((s) => s.replace(/\r$/, ''))
        .filter((s) => s.length > 0)
    );
  }
  return list;
}

// Run requests with bounded concurrency, emitting each result via onResult.
async function runFuzz(template, list, options, onResult, shouldStop) {
  const concurrency = Math.min(Math.max(1, options.concurrency || 10), 50);
  const delay = Math.max(0, options.delayMs || 0);
  let idx = 0;
  let done = 0;

  async function worker() {
    while (idx < list.length) {
      if (shouldStop()) return;
      const myIdx = idx++;
      const payload = list[myIdx];
      const reqObj = injectMarker(template, payload);
      const result = await sendRequest({
        method: reqObj.method,
        url: reqObj.url,
        headers: reqObj.headers,
        body: reqObj.body,
        timeout: options.timeout || 15000,
        followRedirects: !!options.followRedirects,
      });
      done++;
      onResult({
        idx: myIdx,
        payload,
        status: result.status ?? null,
        size: result.size ?? null,
        timeMs: result.timeMs ?? null,
        error: result.error || null,
        location: result.headers ? result.headers.location || '' : '',
        done,
        total: list.length,
      });
      if (delay) await sleep(delay);
    }
  }

  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push(worker());
  await Promise.all(workers);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ---- Routes ------------------------------------------------------------

async function handleApi(req, res, pathname) {
  if (pathname === '/api/spec' && req.method === 'GET') {
    try {
      const spec = await loadSpec();
      return sendJson(res, 200, { ok: true, spec, specSource });
    } catch (e) {
      return sendJson(res, 200, { ok: false, error: e.message, specSource });
    }
  }

  if (pathname === '/api/spec/upload' && req.method === 'POST') {
    try {
      const { content } = await parseJsonBody(req);
      const doc = typeof content === 'string' ? JSON.parse(content) : content;
      cachedSpec = parseSpec(doc);
      specSource = '(uploaded)';
      return sendJson(res, 200, { ok: true, spec: cachedSpec });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  // Load a spec from a remote URL (server-side fetch, avoids browser CORS).
  if (pathname === '/api/spec/url' && req.method === 'POST') {
    try {
      const { url } = await parseJsonBody(req);
      if (!url) return sendJson(res, 400, { ok: false, error: 'Missing url' });
      cachedSpec = await parseSource(url);
      specSource = url;
      return sendJson(res, 200, { ok: true, spec: cachedSpec, specSource });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  if (pathname === '/api/proxy' && req.method === 'POST') {
    try {
      const r = await parseJsonBody(req);
      const result = await sendRequest({
        method: r.method || 'GET',
        url: r.url,
        headers: r.headers || {},
        body: r.body || null,
        timeout: r.timeout || 20000,
        followRedirects: !!r.followRedirects,
        insecureTLS: r.insecureTLS !== false,
      });
      return sendJson(res, 200, { ok: !result.error, result });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  // Access-control matrix: send one request as each identity, return all.
  if (pathname === '/api/matrix' && req.method === 'POST') {
    try {
      const { request: base, identities } = await parseJsonBody(req);
      const results = [];
      for (const ident of identities || []) {
        const headers = { ...(base.headers || {}), ...(ident.headers || {}) };
        // Allow an identity to remove auth by setting a header value to null.
        for (const [k, v] of Object.entries(ident.headers || {})) {
          if (v === null) delete headers[k];
        }
        const result = await sendRequest({
          method: base.method || 'GET',
          url: base.url,
          headers,
          body: base.body || null,
          followRedirects: false,
        });
        results.push({
          identity: ident.name,
          status: result.status ?? null,
          size: result.size ?? null,
          timeMs: result.timeMs ?? null,
          error: result.error || null,
          bodyPreview: (result.body || '').slice(0, 400),
        });
      }
      return sendJson(res, 200, { ok: true, results });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  if (pathname === '/api/curl/parse' && req.method === 'POST') {
    try {
      const { curl } = await parseJsonBody(req);
      return sendJson(res, 200, { ok: true, request: parseCurl(curl || '') });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  if (pathname === '/api/curl/build' && req.method === 'POST') {
    try {
      const r = await parseJsonBody(req);
      return sendJson(res, 200, { ok: true, curl: toCurl(r) });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  if (pathname === '/api/payloads' && req.method === 'GET') {
    return sendJson(res, 200, { ok: true, sets: payloads.listSets() });
  }

  if (pathname === '/api/fuzz' && req.method === 'POST') {
    return handleFuzz(req, res);
  }

  // One-click attack variants against a single request.
  if (pathname === '/api/attacks' && req.method === 'POST') {
    try {
      const { request: base } = await parseJsonBody(req);
      if (!base || !base.url) return sendJson(res, 400, { ok: false, error: 'Missing request.url' });
      const variants = buildVariants(base);
      const results = [];
      for (const v of variants) {
        const result = await sendRequest({
          method: v.request.method || 'GET',
          url: v.request.url,
          headers: v.request.headers || {},
          body: v.request.body || null,
          followRedirects: false,
        });
        results.push({
          name: v.name,
          note: v.note,
          status: result.status ?? null,
          size: result.size ?? null,
          timeMs: result.timeMs ?? null,
          error: result.error || null,
        });
      }
      return sendJson(res, 200, { ok: true, results });
    } catch (e) {
      return sendJson(res, 400, { ok: false, error: e.message });
    }
  }

  // Auth-coverage sweep across every spec endpoint (SSE stream).
  if (pathname === '/api/sweep' && req.method === 'POST') {
    return handleSweep(req, res);
  }

  return sendJson(res, 404, { ok: false, error: 'Unknown API route' });
}

async function handleFuzz(req, res) {
  let cfg;
  try {
    cfg = await parseJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: e.message });
  }

  const template = cfg.request || {};
  if (!template.url) return sendJson(res, 400, { ok: false, error: 'Missing request.url' });
  if (!hasMarker(template)) {
    return sendJson(res, 400, {
      ok: false,
      error: 'No injection point. Mark one with §§ or the FUZZ keyword.',
    });
  }
  const list = resolvePayloads(cfg.payloads || {});
  if (!list.length) {
    return sendJson(res, 400, { ok: false, error: 'No payloads resolved.' });
  }

  // Server-Sent Events stream of live results.
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  let stopped = false;
  req.on('close', () => {
    stopped = true;
  });

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  send('start', { total: list.length });

  try {
    await runFuzz(
      template,
      list,
      cfg.options || {},
      (r) => send('result', r),
      () => stopped
    );
    if (!stopped) send('done', { total: list.length });
  } catch (e) {
    send('error', { error: e.message });
  }
  res.end();
}

// Substitute {pathParams} with their example value (or a placeholder) and
// join onto the chosen base URL.
function resolveEndpointUrl(baseUrl, ep, placeholder) {
  let path = ep.path;
  for (const p of ep.params.path || []) {
    const val = p.example != null && p.example !== '' ? p.example : placeholder;
    path = path.replace(`{${p.name}}`, encodeURIComponent(val));
  }
  // Any remaining {tokens} get the placeholder too.
  path = path.replace(/\{[^}]+\}/g, encodeURIComponent(placeholder));
  if (/^https?:\/\//i.test(path)) return path;
  return baseUrl.replace(/\/$/, '') + (path.startsWith('/') ? '' : '/') + path;
}

async function handleSweep(req, res) {
  let cfg;
  try {
    cfg = await parseJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { ok: false, error: e.message });
  }
  let spec;
  try {
    spec = await loadSpec();
  } catch (e) {
    return sendJson(res, 500, { ok: false, error: e.message });
  }

  const baseUrl = (cfg.baseUrl || spec.baseUrls[0] || '').trim();
  if (!baseUrl) return sendJson(res, 400, { ok: false, error: 'No base URL' });
  // Default to safe, idempotent methods so a sweep never mutates data.
  const methods = (cfg.methods && cfg.methods.length ? cfg.methods : ['GET']).map((m) => m.toUpperCase());
  const identities = cfg.identities && cfg.identities.length ? cfg.identities : [{ name: 'as-sent', headers: {} }];
  const placeholder = cfg.placeholder || '1';
  const concurrency = Math.min(Math.max(1, cfg.concurrency || 8), 30);

  const targets = spec.endpoints.filter((e) => methods.includes(e.method));

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  let stopped = false;
  req.on('close', () => (stopped = true));
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  send('start', { total: targets.length });

  let idx = 0;
  let done = 0;
  async function worker() {
    while (idx < targets.length && !stopped) {
      const ep = targets[idx++];
      const url = resolveEndpointUrl(baseUrl, ep, placeholder);
      const perIdentity = {};
      for (const ident of identities) {
        const headers = { ...(ident.headers || {}) };
        for (const [k, v] of Object.entries(ident.headers || {})) {
          if (v === null) delete headers[k];
        }
        const r = await sendRequest({
          method: ep.method,
          url,
          headers,
          followRedirects: false,
        });
        perIdentity[ident.name] = {
          status: r.status ?? null,
          size: r.size ?? null,
          error: r.error || null,
        };
      }
      done++;
      send('result', {
        method: ep.method,
        path: ep.path,
        url,
        hasSecurity: (ep.security || []).length > 0,
        perIdentity,
        done,
        total: targets.length,
      });
    }
  }
  const workers = [];
  for (let i = 0; i < concurrency; i++) workers.push(worker());
  await Promise.all(workers);
  if (!stopped) send('done', { total: targets.length });
  res.end();
}

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(PUBLIC_DIR, path.normalize(rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    return sendJson(res, 403, { ok: false, error: 'Forbidden' });
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;
  if (pathname.startsWith('/api/')) {
    handleApi(req, res, pathname).catch((e) =>
      sendJson(res, 500, { ok: false, error: e.message })
    );
    return;
  }
  serveStatic(req, res, pathname);
});

server.listen(PORT, HOST, async () => {
  console.log(`\n  PenAPI  —  pentest API workbench`);
  console.log(`  Spec:   ${specSource || '(none — load one from the UI)'}`);
  console.log(`  URL:    http://${HOST}:${PORT}\n`);
  if (specSource) {
    try {
      const s = await loadSpec();
      console.log(`  Loaded ${s.stats.endpoints} endpoints across ${s.tags.length} tags.\n`);
    } catch (e) {
      console.log(`  WARNING: could not parse spec yet: ${e.message}\n`);
    }
  }
});
