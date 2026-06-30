// Pure payload-set suggester: maps a request/endpoint shape (URL, body, method,
// content-type) to the most relevant built-in Fuzzer set keys, so the tool can
// point the tester at the right attack class instead of scrolling the picker.
// DOM-free and dependency-light for `node --test`.

import { queryFromUrl, pathFromUrl, tryParseJson, objectPaths } from './shared.js';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Ordered rules. `re` matches against a token blob (param names + path segments
// + body keys). Earlier rules rank higher. `keys` are SETS keys from lib/payloads.js.
const TOKEN_RULES = [
  { re: /redirect|return|returnurl|\bnext\b|continue|\bdest\b|destination|goto|\btarget\b|callback|\burl\b|\buri\b/i, keys: ['open-redirect', 'ssrf'], why: 'redirect/URL parameter' },
  { re: /webhook|fetch|proxy|\bhost\b|hostname|domain|\bsite\b|\bfeed\b|remote|endpoint|upstream/i, keys: ['ssrf'], why: 'server-side fetch parameter' },
  { re: /\bfile\b|filename|filepath|\bpath\b|template|\bdoc\b|document|\bpage\b|include|\bload\b|download|attachment|image|avatar/i, keys: ['path-traversal', 'lfi'], why: 'file/path parameter' },
  { re: /\bcmd\b|\bexec\b|command|\brun\b|\bping\b|\bshell\b|process|\bjob\b/i, keys: ['cmdi'], why: 'command-like parameter' },
  { re: /\bq\b|query|search|keyword|\bterm\b|filter|\bname\b|title|\bdesc\b|description|comment|message|content|\btext\b|\bbody\b/i, keys: ['sqli', 'xss'], why: 'free-text / searchable parameter' },
  { re: /sort|orderby|order_by|\border\b|\bcolumn\b|\bfield\b|group_?by|\bwhere\b/i, keys: ['sqli'], why: 'sortable / queryable parameter' },
  { re: /render|preview|format|tmpl|template|\blang\b|locale/i, keys: ['ssti'], why: 'templating parameter' },
  { re: /\bemail\b|\bmail\b|\bcc\b|\bbcc\b|subject|recipient/i, keys: ['email-injection'], why: 'email parameter' },
];

const PATH_RULES = [
  { re: /graphql|graphiql/i, keys: ['graphql', 'graphql-injection'], why: 'GraphQL endpoint' },
  { re: /\b(login|signin|sign-in|authenticate|\btoken\b|oauth|register|signup|sign-up|password|otp|verify)\b/i, keys: ['auth-bypass', 'passwords', 'usernames', 'jwt-attacks'], why: 'authentication endpoint' },
  { re: /export|report|\bcsv\b|xlsx|spreadsheet|download|sheet/i, keys: ['csv-injection'], why: 'export / spreadsheet endpoint' },
  { re: /upload|attachment|\bfile\b|import|media/i, keys: ['file-upload'], why: 'upload endpoint' },
];

// Collect the searchable token blob and the JSON body presence from inputs.
function tokensFor({ url = '', body = '', contentType = '' }) {
  const path = pathFromUrl(url);
  const segments = path.split(/[\/{}._-]+/).filter(Boolean);
  const queryKeys = Object.keys(queryFromUrl(url));
  const parsed = tryParseJson(body);
  const bodyKeys = parsed ? objectPaths(parsed) : [];
  const isXml = /xml/i.test(contentType) || /^\s*<\?xml|^\s*<[a-z]/i.test(String(body));
  const isJsonObject = parsed != null && typeof parsed === 'object' && !Array.isArray(parsed);
  return {
    blob: [...segments, ...queryKeys, ...bodyKeys].join(' '),
    path,
    queryCount: queryKeys.length,
    isXml,
    isJsonObject,
    hasBody: Boolean(body),
  };
}

// Return ranked suggestions: [{ key, why }]. `limit` caps the list.
export function suggestSets({ url = '', body = '', method = 'GET', contentType = '' } = {}, limit = 6) {
  const t = tokensFor({ url, body, contentType });
  const out = [];
  const seen = new Set();
  const add = (key, why) => {
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ key, why });
  };

  for (const rule of PATH_RULES) {
    if (rule.re.test(t.path)) rule.keys.forEach((k) => add(k, rule.why));
  }
  for (const rule of TOKEN_RULES) {
    if (rule.re.test(t.blob)) rule.keys.forEach((k) => add(k, rule.why));
  }
  if (t.isXml) add('xxe', 'XML body');
  if (MUTATING.has(String(method).toUpperCase()) && t.isJsonObject) {
    add('mass-assignment', 'JSON object body (over-posting)');
    add('type-juggling', 'JSON object body (type confusion)');
  }
  if (t.queryCount >= 2) add('param-pollution', 'multiple query parameters');
  // General fallback so the picker always has a useful default.
  if (!out.length) {
    add('format-fuzz', 'general edge-case fuzzing');
    add('unicode-bypass', 'encoding/normalization bypass');
  }

  return out.slice(0, limit);
}
