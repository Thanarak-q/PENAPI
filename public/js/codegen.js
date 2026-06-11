// Generate code snippets for the current request in several languages so a
// finding can be reproduced outside PenAPI.

function pyStr(s) {
  return "'" + String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
}

export function toFetch(req) {
  const opts = { method: req.method, headers: req.headers || {} };
  if (req.body) opts.body = req.body;
  return (
    `fetch(${JSON.stringify(req.url)}, ${JSON.stringify(opts, null, 2)})\n` +
    `  .then(r => r.text())\n  .then(console.log);`
  );
}

export function toPython(req) {
  const lines = ['import requests', ''];
  const headers = req.headers || {};
  lines.push('headers = {');
  for (const [k, v] of Object.entries(headers)) lines.push(`    ${pyStr(k)}: ${pyStr(v)},`);
  lines.push('}');
  let dataArg = '';
  if (req.body) {
    lines.push(`data = ${pyStr(req.body)}`);
    dataArg = ', data=data';
  }
  lines.push(
    `resp = requests.request(${pyStr(req.method)}, ${pyStr(req.url)}, headers=headers${dataArg}, verify=False)`
  );
  lines.push('print(resp.status_code)', 'print(resp.text)');
  return lines.join('\n');
}

export function toHttpie(req) {
  const parts = ['http', '--verify=no', req.method, shell(req.url)];
  for (const [k, v] of Object.entries(req.headers || {})) parts.push(shell(`${k}:${v}`));
  let cmd = parts.join(' ');
  if (req.body) cmd = `echo ${shell(req.body)} | ${cmd}`;
  return cmd;
}

function shell(s) {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}
