// Traffic Search — pure, DOM-free core. Greps captured history entries (method,
// URL, request/response headers and bodies) for a literal or regex query, so
// secrets, tokens, or stack traces seen anywhere in a session are findable.
// DOM-free for `node --test`.

// Build the searchable text for one history entry, tagged by field so callers
// can show where a match landed. Returns [{ field, text }].
export function entryFields(entry) {
  const fields = [
    { field: 'method', text: entry.method || '' },
    { field: 'url', text: entry.url || '' },
  ];
  if (entry.request) {
    fields.push({ field: 'request headers', text: stringifyHeaders(entry.request.headers) });
    fields.push({ field: 'request body', text: entry.request.body || '' });
  }
  if (entry.response) {
    fields.push({ field: 'response headers', text: stringifyHeaders(entry.response.headers) });
    fields.push({ field: 'response body', text: String(entry.response.body || '') });
  }
  return fields;
}

function stringifyHeaders(headers) {
  if (!headers) return '';
  return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

// Build a predicate from the query. Returns null for an empty or invalid query.
export function buildMatcher(query, { regex = false, caseSensitive = false } = {}) {
  if (!query) return null;
  if (regex) {
    try {
      const re = new RegExp(query, caseSensitive ? '' : 'i');
      return (text) => re.test(text);
    } catch {
      return null; // invalid regex
    }
  }
  const needle = caseSensitive ? query : query.toLowerCase();
  return (text) => (caseSensitive ? text : text.toLowerCase()).includes(needle);
}

// Search entries. Returns [{ entry, matchedFields: [field…] }] for entries with
// at least one matching field, preserving input order.
export function searchHistory(entries, query, opts = {}) {
  const match = buildMatcher(query, opts);
  if (!match) return [];
  const results = [];
  for (const entry of entries || []) {
    const matchedFields = entryFields(entry).filter((f) => match(f.text)).map((f) => f.field);
    if (matchedFields.length) results.push({ entry, matchedFields });
  }
  return results;
}
