// Hash Identifier — pure, DOM-free core. Given a string, guesses which hash /
// digest algorithms it could be, from length, character set, and prefix format.
// Heuristic only — multiple algorithms share a length, so several may match.
// DOM-free for `node --test`.

// Prefix-formatted hashes (modular crypt, etc.). Checked before length rules.
const PREFIX_RULES = [
  { re: /^\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$/, names: ['bcrypt'] },
  { re: /^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$/, names: ['md5crypt (Unix)'] },
  { re: /^\$5\$/, names: ['sha256crypt (Unix)'] },
  { re: /^\$6\$/, names: ['sha512crypt (Unix)'] },
  { re: /^\$argon2(id|i|d)\$/, names: ['Argon2'] },
  { re: /^\{SSHA\}[A-Za-z0-9+/=]+$/, names: ['SSHA (LDAP)'] },
  { re: /^\{SHA\}[A-Za-z0-9+/=]+$/, names: ['SHA-1 (LDAP)'] },
  { re: /^[0-9a-f]{32}:[0-9a-f]{1,}$/i, names: ['MD5 (salted, hash:salt)'] },
  { re: /^[0-9a-f]{32}:[0-9A-Za-z]{1,}$/, names: ['NTLM/MD5 with salt'] },
];

// Hex-length rules. Each maps an exact hex length to candidate algorithms.
const HEX_LENGTH_RULES = {
  32: ['MD5', 'MD4', 'NTLM', 'LM (half)', 'RIPEMD-128'],
  40: ['SHA-1', 'RIPEMD-160', 'Tiger-160'],
  56: ['SHA-224', 'SHA3-224'],
  64: ['SHA-256', 'SHA3-256', 'BLAKE2s', 'RIPEMD-256'],
  96: ['SHA-384', 'SHA3-384'],
  128: ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool'],
};

const HEX_RE = /^[0-9a-f]+$/i;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// Identify a hash. Returns { input, length, candidates: string[], notes: string[] }.
export function identifyHash(input) {
  const value = String(input == null ? '' : input).trim();
  const result = { input: value, length: value.length, candidates: [], notes: [] };
  if (!value) return result;

  for (const rule of PREFIX_RULES) {
    if (rule.re.test(value)) {
      result.candidates.push(...rule.names);
    }
  }
  if (result.candidates.length) return dedupe(result);

  if (HEX_RE.test(value)) {
    const byLen = HEX_LENGTH_RULES[value.length];
    if (byLen) {
      result.candidates.push(...byLen);
      if (value.length === 32) result.notes.push('Could be an unsalted MD5/NTLM — check context (Windows → NTLM).');
    } else {
      result.notes.push(`Hex string of ${value.length} chars — no common fixed-length digest matches.`);
    }
    if (/^[0-9a-f]{8}$/i.test(value)) result.notes.push('Short — likely a CRC32 / Adler-32 checksum, not a password hash.');
    return dedupe(result);
  }

  if (BASE64_RE.test(value) && value.length % 4 === 0) {
    const bytes = Math.floor((value.replace(/=+$/, '').length * 3) / 4);
    result.notes.push(`Base64-looking, decodes to ~${bytes} bytes.`);
    if (bytes === 20) result.candidates.push('SHA-1 (base64)');
    if (bytes === 32) result.candidates.push('SHA-256 (base64)');
    if (bytes === 16) result.candidates.push('MD5 (base64)');
    return dedupe(result);
  }

  result.notes.push('Unrecognized format — not hex, not base64, no known crypt prefix.');
  return dedupe(result);
}

function dedupe(result) {
  result.candidates = [...new Set(result.candidates)];
  return result;
}
