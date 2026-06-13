'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const zlib = require('zlib');

// Raw HTTP client giving full control over method, headers and body.
// Uses node http/https directly so forbidden-header restrictions of fetch
// (Host, Content-Length, etc.) do not apply — required for pentest work.

const DEFAULT_TIMEOUT = 20000;
const MAX_BODY = 5 * 1024 * 1024; // cap captured response body at 5 MB

function sendRequest(opts) {
  const {
    method = 'GET',
    url,
    headers = {},
    body = null,
    timeout = DEFAULT_TIMEOUT,
    followRedirects = false,
    insecureTLS = true,
    _redirectCount = 0,
  } = opts;

  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      return resolve({ error: `Invalid URL: ${url}` });
    }
    const isHttps = target.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      if (v === undefined || v === null) continue;
      reqHeaders[k] = v;
    }
    // Default Host from URL unless explicitly overridden.
    if (!Object.keys(reqHeaders).some((h) => h.toLowerCase() === 'host')) {
      reqHeaders.Host = target.host;
    }

    let payload = null;
    if (body != null && method !== 'GET' && method !== 'HEAD') {
      payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
      if (!Object.keys(reqHeaders).some((h) => h.toLowerCase() === 'content-length')) {
        reqHeaders['Content-Length'] = payload.length;
      }
    }

    const requestOptions = {
      method,
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: target.pathname + target.search,
      headers: reqHeaders,
      timeout,
    };
    if (isHttps && insecureTLS) requestOptions.rejectUnauthorized = false;

    const start = process.hrtime.bigint();
    const req = lib.request(requestOptions, (res) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      res.on('data', (c) => {
        size += c.length;
        if (!truncated) {
          if (size > MAX_BODY) {
            truncated = true;
          } else {
            chunks.push(c);
          }
        }
      });
      res.on('end', () => {
        const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
        let raw = Buffer.concat(chunks);
        raw = maybeDecompress(raw, res.headers['content-encoding']);

        // Follow redirects when asked.
        if (
          followRedirects &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location &&
          _redirectCount < 5
        ) {
          const nextUrl = new URL(res.headers.location, target).toString();
          return resolve(
            sendRequest({
              ...opts,
              url: nextUrl,
              method: res.statusCode === 303 ? 'GET' : method,
              _redirectCount: _redirectCount + 1,
            })
          );
        }

        resolve({
          status: res.statusCode,
          statusText: res.statusMessage || '',
          headers: flattenHeaders(res.headers),
          body: raw.toString('utf8'),
          size,
          truncated,
          timeMs: Math.round(elapsedMs),
          finalUrl: target.toString(),
          redirected: _redirectCount > 0,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Request timed out', timeout: true });
    });
    req.on('error', (err) => {
      resolve({ error: err.message, code: err.code });
    });

    if (payload) req.write(payload);
    req.end();
  });
}

function maybeDecompress(buf, encoding) {
  try {
    if (encoding === 'gzip') return zlib.gunzipSync(buf);
    if (encoding === 'deflate') return zlib.inflateSync(buf);
    if (encoding === 'br') return zlib.brotliDecompressSync(buf);
  } catch (e) {
    return buf;
  }
  return buf;
}

function flattenHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h)) {
    if (Array.isArray(v)) {
      // Set-Cookie must stay one-per-line: comma-joining corrupts cookies whose
      // values contain commas (e.g. an Expires date), and breaks the Cookie
      // Inspector which splits on newlines.
      out[k] = v.join(k.toLowerCase() === 'set-cookie' ? '\n' : ', ');
    } else {
      out[k] = v;
    }
  }
  return out;
}

module.exports = { sendRequest, flattenHeaders, maybeDecompress };
