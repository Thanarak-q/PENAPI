'use strict';

// Parse a `curl` command line into a structured request, and serialize a
// request back into a copy-pasteable curl command.

function tokenize(input) {
  const tokens = [];
  let cur = '';
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  let has = false;
  while (i < input.length) {
    const c = input[i];
    if (inSingle) {
      if (c === "'") inSingle = false;
      else cur += c;
    } else if (inDouble) {
      if (c === '"') inDouble = false;
      else if (c === '\\' && i + 1 < input.length && '"\\$`'.includes(input[i + 1])) {
        cur += input[++i];
      } else cur += c;
    } else if (c === "'") {
      inSingle = true;
      has = true;
    } else if (c === '"') {
      inDouble = true;
      has = true;
    } else if (c === '\\' && input[i + 1] === '\n') {
      i++; // line continuation
    } else if (c === '\\' && i + 1 < input.length) {
      cur += input[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has || cur) {
        tokens.push(cur);
        cur = '';
        has = false;
      }
    } else {
      cur += c;
      has = true;
    }
    i++;
  }
  if (has || cur) tokens.push(cur);
  return tokens;
}

function parseCurl(input) {
  const cleaned = input.trim().replace(/\\\r?\n/g, ' ');
  const tokens = tokenize(cleaned);
  const req = {
    method: null,
    url: '',
    headers: {},
    body: null,
    insecure: false,
  };
  let i = 0;
  if (tokens[0] === 'curl') i = 1;

  const dataArgs = [];
  for (; i < tokens.length; i++) {
    const t = tokens[i];
    const next = () => tokens[++i];
    if (t === '-X' || t === '--request') {
      req.method = next();
    } else if (t === '-H' || t === '--header') {
      const h = next();
      if (h) {
        const idx = h.indexOf(':');
        if (idx > -1) req.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
      }
    } else if (t === '-A' || t === '--user-agent') {
      const ua = next();
      if (ua != null) req.headers['User-Agent'] = ua;
    } else if (t === '-e' || t === '--referer') {
      const ref = next();
      if (ref != null) req.headers['Referer'] = ref;
    } else if (t === '-b' || t === '--cookie') {
      const cookie = next();
      if (cookie != null) req.headers['Cookie'] = cookie;
    } else if (t === '-u' || t === '--user') {
      const cred = next();
      if (cred != null) {
        req.headers['Authorization'] = 'Basic ' + Buffer.from(cred).toString('base64');
      }
    } else if (
      t === '-d' ||
      t === '--data' ||
      t === '--data-raw' ||
      t === '--data-binary' ||
      t === '--data-ascii'
    ) {
      dataArgs.push(next());
    } else if (t === '--data-urlencode') {
      dataArgs.push(next());
    } else if (t === '-G' || t === '--get') {
      req.method = req.method || 'GET';
      req._forceGet = true;
    } else if (t === '-k' || t === '--insecure') {
      req.insecure = true;
    } else if (t === '-F' || t === '--form') {
      dataArgs.push(next());
      req.headers['Content-Type'] =
        req.headers['Content-Type'] || 'multipart/form-data';
    } else if (t === '--url') {
      req.url = next();
    } else if (t === '-I' || t === '--head') {
      req.method = 'HEAD';
    } else if (t === '--compressed' || t === '-s' || t === '--silent' || t === '-L' || t === '--location' || t === '-v' || t === '-i' || t === '--include' || t === '-#') {
      // flags with no value we can ignore for request building
    } else if (t.startsWith('http://') || t.startsWith('https://')) {
      req.url = t;
    } else if (!t.startsWith('-') && !req.url) {
      req.url = t;
    }
  }

  const data = dataArgs.filter((d) => d != null);
  if (data.length) {
    req.body = data.join('&');
    if (req._forceGet) {
      // -G puts data in the query string
      const sep = req.url.includes('?') ? '&' : '?';
      req.url += sep + req.body;
      req.body = null;
    } else {
      req.method = req.method || 'POST';
      if (!hasHeader(req.headers, 'content-type')) {
        req.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
    }
  }
  req.method = req.method || 'GET';
  delete req._forceGet;
  return req;
}

function hasHeader(headers, name) {
  return Object.keys(headers).some((k) => k.toLowerCase() === name.toLowerCase());
}

function shellQuote(s) {
  if (s === '') return "''";
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function toCurl(req) {
  const parts = ['curl', '-i'];
  if (req.insecure) parts.push('-k');
  const method = (req.method || 'GET').toUpperCase();
  if (method !== 'GET') parts.push('-X', method);
  parts.push(shellQuote(req.url));
  for (const [k, v] of Object.entries(req.headers || {})) {
    parts.push('-H', shellQuote(`${k}: ${v}`));
  }
  if (req.body != null && req.body !== '') {
    parts.push('--data-raw', shellQuote(req.body));
  }
  return parts.join(' ');
}

module.exports = { parseCurl, toCurl, tokenize };
