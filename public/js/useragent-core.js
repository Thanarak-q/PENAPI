// User-Agent Library — pure, DOM-free core. A searchable set of representative
// User-Agent strings (desktop, mobile, bot/crawler, tools) for testing
// UA-based routing, cloaking, and access logic. DOM-free for `node --test`.

const AGENTS = [
  ['Desktop', 'Chrome / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'],
  ['Desktop', 'Firefox / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0'],
  ['Desktop', 'Safari / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'],
  ['Desktop', 'Edge / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0'],
  ['Mobile', 'Safari / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1'],
  ['Mobile', 'Chrome / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'],
  ['Bot', 'Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
  ['Bot', 'Bingbot', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
  ['Bot', 'Slackbot', 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)'],
  ['Bot', 'facebookexternalhit', 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'],
  ['Tool', 'curl', 'curl/8.6.0'],
  ['Tool', 'python-requests', 'python-requests/2.31.0'],
  ['Tool', 'Go-http-client', 'Go-http-client/2.0'],
  ['Tool', 'Empty / suspicious', ''],
];

const TABLE = AGENTS.map(([category, label, ua]) => ({ category, label, ua }));

export function allAgents() {
  return TABLE.slice();
}

export function categories() {
  return [...new Set(TABLE.map((e) => e.category))];
}

// Search by label / UA / category (case-insensitive).
export function searchAgents(query) {
  const q = String(query || '').trim().toLowerCase();
  if (!q) return allAgents();
  return TABLE.filter((e) =>
    e.label.toLowerCase().includes(q) ||
    e.ua.toLowerCase().includes(q) ||
    e.category.toLowerCase().includes(q)
  );
}
