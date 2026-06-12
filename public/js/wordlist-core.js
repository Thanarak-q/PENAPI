// Wordlist Generator — pure, DOM-free core. Builds fuzzing wordlists from a
// numeric range, affix wrapping, and case/leet mutations. Feeds the Fuzzer and
// Content Discovery tools. DOM-free for `node --test`.

const MAX_OUTPUT = 10000; // guard against runaway ranges

// Numeric range start..end inclusive, with step and optional zero-padding.
export function numericRange(start, end, step = 1, pad = 0) {
  const s = Number(start);
  const e = Number(end);
  const st = Number(step) || 1;
  if (!Number.isFinite(s) || !Number.isFinite(e)) return [];
  const out = [];
  const dir = e >= s ? 1 : -1;
  const stride = Math.abs(st) * dir;
  for (let n = s; dir > 0 ? n <= e : n >= e; n += stride) {
    out.push(pad > 0 ? String(Math.abs(n)).padStart(pad, '0') : String(n));
    if (out.length >= MAX_OUTPUT) break;
  }
  return out;
}

// Wrap each word with a prefix and/or suffix.
export function affix(words, prefix = '', suffix = '') {
  return (words || []).map((w) => `${prefix}${w}${suffix}`);
}

// Case mutations of a single word: lower, UPPER, Capitalized, and the original.
export function caseMutations(word) {
  const w = String(word || '');
  if (!w) return [];
  const cap = w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
  return [...new Set([w, w.toLowerCase(), w.toUpperCase(), cap])];
}

const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7' };

// Basic full-substitution leet variant of a word (a->4, e->3, ...).
export function leet(word) {
  return String(word || '').split('').map((c) => LEET[c.toLowerCase()] || c).join('');
}

// Expand a list of base words into all case mutations (+ optional leet).
export function mutateWords(words, withLeet = false) {
  const out = [];
  for (const w of words || []) {
    for (const m of caseMutations(w)) out.push(m);
    if (withLeet) out.push(leet(w));
  }
  return [...new Set(out)].slice(0, MAX_OUTPUT);
}

export { MAX_OUTPUT };
