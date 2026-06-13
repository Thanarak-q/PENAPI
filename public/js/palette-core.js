// Pure, DOM-free helpers used by the command palette — importable in Node tests.

/**
 * Filter a command list by a search query.
 * Returns at most 50 items for an empty/whitespace query, or at most 80 items
 * whose label or hint contains the query string (case-insensitive).
 *
 * @param {Array<{label: string, hint?: string}>} items
 * @param {string} query
 * @returns {Array<{label: string, hint?: string}>}
 */
export function filterCommands(items, query) {
  const q = (query || '').trim().toLowerCase();
  return !q
    ? items.slice(0, 50)
    : items
        .filter((it) => (it.label + ' ' + (it.hint || '')).toLowerCase().includes(q))
        .slice(0, 80);
}
