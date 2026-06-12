// Token Sequencer — pure, DOM-free core. Estimates the randomness of a set of
// captured tokens (session IDs, CSRF tokens, password-reset tokens) so weak,
// guessable, or sequential generation stands out.
//
// The per-position Shannon entropy is a lightweight heuristic, not a full
// statistical battery — more samples give a better estimate. DOM-free for
// `node --test`.

function shannon(counts, n) {
  let h = 0;
  for (const k of Object.keys(counts)) {
    const p = counts[k] / n;
    if (p > 0) h -= p * Math.log2(p);
  }
  return h;
}

// Detect tokens that are purely numeric and increment by a constant step.
export function detectSequential(tokens) {
  if (tokens.length < 3) return false;
  const nums = tokens.map((t) => (/^\d+$/.test(t) ? Number(t) : null));
  if (nums.some((n) => n === null || !Number.isSafeInteger(n))) return false;
  const sorted = [...nums].sort((a, b) => a - b);
  const step = sorted[1] - sorted[0];
  if (step === 0) return false;
  return sorted.every((n, i) => i === 0 || n - sorted[i - 1] === step);
}

function grade(bits, duplicates, sequential, total) {
  if (sequential) {
    return { level: 'predictable', label: 'Sequential / incrementing — fully predictable' };
  }
  if (total >= 5 && duplicates > 0) {
    return { level: 'weak', label: `${duplicates} duplicate token(s) — collisions indicate weak generation` };
  }
  if (bits < 64) {
    return { level: 'weak', label: `~${bits.toFixed(1)} bits of entropy — below 64-bit, brute-forceable` };
  }
  if (bits < 128) {
    return { level: 'moderate', label: `~${bits.toFixed(1)} bits — moderate; 128+ recommended for session tokens` };
  }
  return { level: 'strong', label: `~${bits.toFixed(1)} bits — strong` };
}

// Analyze an array of token strings. Returns a report object.
export function analyzeTokens(tokens) {
  const clean = (tokens || []).map((t) => String(t).trim()).filter(Boolean);
  const total = clean.length;
  if (!total) {
    return {
      total: 0, unique: 0, duplicates: 0, minLen: 0, maxLen: 0, sameLength: true,
      charsetSize: 0, perPosition: [], totalEntropyBits: 0, bitsPerChar: 0,
      sequential: false, verdict: { level: 'none', label: 'No tokens to analyze' },
    };
  }

  const unique = new Set(clean).size;
  const duplicates = total - unique;
  const lengths = clean.map((t) => t.length);
  const minLen = Math.min(...lengths);
  const maxLen = Math.max(...lengths);
  const sameLength = minLen === maxLen;

  const charset = new Set();
  for (const t of clean) for (const ch of t) charset.add(ch);

  // Per-position entropy over the common prefix length.
  const perPosition = [];
  for (let i = 0; i < minLen; i++) {
    const counts = {};
    for (const t of clean) counts[t[i]] = (counts[t[i]] || 0) + 1;
    perPosition.push(shannon(counts, total));
  }
  const totalEntropyBits = perPosition.reduce((a, b) => a + b, 0);
  const bitsPerChar = minLen ? totalEntropyBits / minLen : 0;
  const sequential = detectSequential(clean);

  return {
    total, unique, duplicates, minLen, maxLen, sameLength,
    charsetSize: charset.size, perPosition, totalEntropyBits, bitsPerChar,
    sequential, verdict: grade(totalEntropyBits, duplicates, sequential, total),
  };
}
