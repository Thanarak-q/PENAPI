// Match & Replace — pure, DOM-free core. Applies a list of rewrite rules to an
// outgoing request before it is sent: rewrite the URL or body by literal/regex
// match, or set/remove a header. DOM-free for `node --test`.
//
// Rule shapes (one array, branched on `target`):
//   { enabled, target: 'url'|'body', match, replace, regex }   → string replace
//   { enabled, target: 'header', match, replace }              → set header
//        match = header name; replace = value ('' removes the header)

function safeReplace(text, match, replace, regex) {
  if (text == null || match === '' || match == null) return text;
  try {
    if (regex) {
      return String(text).replace(new RegExp(match, 'g'), replace ?? '');
    }
    return String(text).split(match).join(replace ?? '');
  } catch {
    return text; // invalid regex → leave the text untouched
  }
}

// Apply rules to a request { method, url, headers, body }. Returns a new
// request; the input is not mutated.
export function applyRules(request, rules) {
  let url = request.url;
  let body = request.body;
  const headers = { ...(request.headers || {}) };

  for (const rule of rules || []) {
    if (!rule || !rule.enabled) continue;
    if (rule.target === 'url') {
      url = safeReplace(url, rule.match, rule.replace, rule.regex);
    } else if (rule.target === 'body') {
      body = safeReplace(body, rule.match, rule.replace, rule.regex);
    } else if (rule.target === 'header') {
      const name = String(rule.match || '').trim();
      if (!name) continue;
      if (rule.replace === '' || rule.replace == null) delete headers[name];
      else headers[name] = rule.replace;
    }
  }
  return { ...request, url, headers, body };
}

// Count enabled rules — used to surface an "active" indicator in the UI.
export function activeRuleCount(rules) {
  return (rules || []).filter((r) => r && r.enabled && (r.match || '').length).length;
}
