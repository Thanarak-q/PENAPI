// Param Analyzer — pure, DOM-free core. Parses a URL or raw query string into
// parameters and classifies each by the attack class its name/value suggests
// (open redirect, SSRF, path traversal, IDOR, auth/secret). Heuristic triage to
// decide what to fuzz first. DOM-free for `node --test`.

// name-pattern -> { category, hint }. First match wins per param.
const NAME_RULES = [
  { re: /^(redirect|redirect_uri|redirect_url|return|returnurl|return_to|next|url|dest|destination|continue|goto|callback|forward)$/i,
    category: 'open-redirect', hint: 'Redirect-like — test open redirect / SSRF.' },
  { re: /^(uri|link|site|domain|host|feed|fetch|proxy|image_url|imageurl|webhook)$/i,
    category: 'ssrf', hint: 'Fetches a remote resource — test SSRF.' },
  { re: /^(file|path|filepath|filename|template|page|doc|document|folder|dir|load|include)$/i,
    category: 'path-traversal', hint: 'File/path-like — test path traversal / LFI.' },
  { re: /^(id|uid|user_id|userid|account|account_id|order|order_id|invoice|doc_id|object|pid|num|no)$/i,
    category: 'idor', hint: 'Identifier — test IDOR / BOLA by changing the value.' },
  { re: /^(token|auth|apikey|api_key|key|secret|password|passwd|pwd|session|sig|signature|access_token|jwt)$/i,
    category: 'auth-secret', hint: 'Auth/secret material — do not leak; test for weak/guessable values.' },
  { re: /^(q|query|search|s|keyword|term|name|comment|message|content|body|html|desc)$/i,
    category: 'injection', hint: 'Free text reflected often — test XSS / SQLi.' },
  { re: /^(sort|order_by|orderby|column|field|group_by|select)$/i,
    category: 'injection', hint: 'Drives a query clause — test SQLi / column injection.' },
  { re: /^(debug|test|admin|is_admin|role|isadmin|preview|internal)$/i,
    category: 'privilege', hint: 'Privilege/mode toggle — test forced-browsing to elevated state.' },
];

// Value heuristics add signal even when the name is generic.
function valueSignals(value) {
  const signals = [];
  if (/^https?:\/\//i.test(value)) signals.push({ category: 'ssrf', hint: 'Value is a URL — SSRF / open redirect candidate.' });
  if (/^\d+$/.test(value)) signals.push({ category: 'idor', hint: 'Numeric value — IDOR candidate.' });
  if (/\.\.(\/|\\)/.test(value)) signals.push({ category: 'path-traversal', hint: 'Already contains traversal sequence.' });
  if (/^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) signals.push({ category: 'auth-secret', hint: 'Looks like a JWT — decode it.' });
  if (/^[0-9a-f]{32,}$/i.test(value)) signals.push({ category: 'auth-secret', hint: 'Long hex — token/hash; check entropy.' });
  return signals;
}

// Parse the query portion of a URL (or a bare query string) into [{ name, value }].
export function parseQuery(input) {
  let s = String(input || '').trim();
  const q = s.indexOf('?');
  // No '?' and the input is a URL/path → it carries no query string.
  if (q === -1 && /:\/\//.test(s)) return [];
  if (q !== -1) s = s.slice(q + 1);
  const hash = s.indexOf('#');
  if (hash !== -1) s = s.slice(0, hash);
  if (!s) return [];
  return s.split('&').filter(Boolean).map((pair) => {
    const i = pair.indexOf('=');
    const rawName = i === -1 ? pair : pair.slice(0, i);
    const rawValue = i === -1 ? '' : pair.slice(i + 1);
    return { name: safeDecode(rawName), value: safeDecode(rawValue) };
  });
}

function safeDecode(s) {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; }
}

// Classify a single param into { name, value, categories: [{category, hint}] }.
export function classifyParam(param) {
  const out = { name: param.name, value: param.value, categories: [] };
  const seen = new Set();
  const add = (category, hint) => {
    if (seen.has(category)) return;
    seen.add(category);
    out.categories.push({ category, hint });
  };
  for (const rule of NAME_RULES) {
    if (rule.re.test(param.name)) { add(rule.category, rule.hint); break; }
  }
  for (const sig of valueSignals(param.value)) add(sig.category, sig.hint);
  return out;
}

// Analyze a URL / query string. Returns classified params with interesting ones first.
export function analyzeParams(input) {
  const classified = parseQuery(input).map(classifyParam);
  return classified.sort((a, b) => b.categories.length - a.categories.length);
}
