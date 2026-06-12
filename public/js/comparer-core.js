// Comparer — pure, DOM-free diff core. Compares two blobs (requests or
// responses) at line or word granularity via a classic LCS diff, so subtle
// changes between two responses (an extra field, a flipped flag) stand out.
//
// DOM-free for `node --test`. The DP is O(n·m); callers should diff reasonably
// sized text (responses are capped elsewhere), not multi-megabyte blobs.

export function tokenizeLines(text) {
  return String(text ?? '').split('\n');
}

// Split into words while keeping whitespace as its own tokens, so re-joining
// reproduces the original text exactly.
export function tokenizeWords(text) {
  return String(text ?? '').split(/(\s+)/).filter((t) => t !== '');
}

// LCS diff of two token arrays → ordered ops [{ type: 'equal'|'add'|'del', value }].
export function diffTokens(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const ops = [];
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      ops.push({ type: 'equal', value: a[i - 1] });
      i--; j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      ops.push({ type: 'del', value: a[i - 1] });
      i--;
    } else {
      ops.push({ type: 'add', value: b[j - 1] });
      j--;
    }
  }
  while (i > 0) ops.push({ type: 'del', value: a[--i] });
  while (j > 0) ops.push({ type: 'add', value: b[--j] });
  return ops.reverse();
}

// Diff two strings. mode = 'line' | 'word'. Returns { ops, added, removed, equal, identical }.
export function diff(textA, textB, mode = 'line') {
  const tokenize = mode === 'word' ? tokenizeWords : tokenizeLines;
  const ops = diffTokens(tokenize(textA), tokenize(textB));
  let added = 0;
  let removed = 0;
  let equal = 0;
  for (const op of ops) {
    if (op.type === 'add') added++;
    else if (op.type === 'del') removed++;
    else equal++;
  }
  return { ops, added, removed, equal, identical: added === 0 && removed === 0 };
}
