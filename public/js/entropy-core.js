// Entropy Analyzer — pure, DOM-free core. Measures the randomness of a single
// string (session token, API key, nonce) via Shannon entropy and an estimated
// brute-force keyspace from its observed character set. DOM-free for `node --test`.

// Shannon entropy in bits PER CHARACTER for the given string.
export function shannonPerChar(s) {
  const str = String(s || '');
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

// Which character classes appear, and the resulting alphabet size for a
// keyspace estimate.
export function charsetOf(s) {
  const str = String(s || '');
  const classes = {
    lower: /[a-z]/.test(str),
    upper: /[A-Z]/.test(str),
    digit: /[0-9]/.test(str),
    hex: /^[0-9a-f]+$/i.test(str) && str.length > 0,
    base64url: /^[A-Za-z0-9_-]+$/.test(str) && str.length > 0,
    symbol: /[^A-Za-z0-9]/.test(str),
  };
  let size = 0;
  if (classes.lower) size += 26;
  if (classes.upper) size += 26;
  if (classes.digit) size += 10;
  if (classes.symbol) size += 32; // rough printable-symbol estimate
  return { classes, alphabet: size || 1 };
}

// Full analysis of one value. `bitsTotal` is the Shannon estimate over the
// string; `keyspaceBits` is the optimistic upper bound from alphabet^length.
export function analyzeEntropy(input) {
  const value = String(input == null ? '' : input);
  const len = value.length;
  const perChar = shannonPerChar(value);
  const { classes, alphabet } = charsetOf(value);
  const bitsTotal = perChar * len;
  const keyspaceBits = len ? len * Math.log2(alphabet) : 0;
  const unique = new Set(value).size;
  return {
    length: len,
    unique,
    bitsPerChar: round(perChar),
    bitsTotal: round(bitsTotal),
    keyspaceBits: round(keyspaceBits),
    alphabet,
    classes,
    verdict: verdictFor(keyspaceBits, len),
  };
}

// A short strength verdict from the optimistic keyspace size.
export function verdictFor(keyspaceBits, len) {
  if (len === 0) return { level: 'empty', label: 'no input' };
  if (keyspaceBits < 32) return { level: 'weak', label: 'weak — brute-forceable, do not use as a secret' };
  if (keyspaceBits < 64) return { level: 'fair', label: 'fair — marginal; fine for non-secret nonces only' };
  if (keyspaceBits < 128) return { level: 'good', label: 'good — adequate for most session tokens' };
  return { level: 'strong', label: 'strong — 128+ bits of keyspace' };
}

function round(n) {
  return Math.round(n * 100) / 100;
}
