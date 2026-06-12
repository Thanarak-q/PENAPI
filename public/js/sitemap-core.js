// Site Map — pure, DOM-free core. Folds a flat list of endpoints into a tree
// keyed by URL path segments (a hierarchical lens, complementary to the
// tag-grouped explorer). DOM-free for `node --test`.

// Build a path tree from endpoints [{ method, path, id }].
// Node shape: { segment, path, children: { [seg]: Node }, ops: [{method,id}], opCount }
// opCount is the number of operations at or below the node.
export function buildSiteMap(endpoints) {
  const root = { segment: '', path: '', children: {}, ops: [], opCount: 0 };
  for (const ep of endpoints || []) {
    const segments = String(ep.path || '').split('/').filter(Boolean);
    let node = root;
    let acc = '';
    for (const seg of segments) {
      acc += '/' + seg;
      if (!node.children[seg]) {
        node.children[seg] = { segment: seg, path: acc, children: {}, ops: [], opCount: 0 };
      }
      node = node.children[seg];
    }
    if (segments.length === 0) {
      // root-level operation ("/")
      root.ops.push({ method: ep.method, id: ep.id });
    } else {
      node.ops.push({ method: ep.method, id: ep.id });
    }
  }
  computeCounts(root);
  return root;
}

function computeCounts(node) {
  let count = node.ops.length;
  for (const child of Object.values(node.children)) {
    count += computeCounts(child);
  }
  node.opCount = count;
  return count;
}

// Return child nodes sorted: branches first, then alphabetical.
export function sortedChildren(node) {
  return Object.values(node.children).sort((a, b) => {
    const aBranch = Object.keys(a.children).length > 0;
    const bBranch = Object.keys(b.children).length > 0;
    if (aBranch !== bBranch) return aBranch ? -1 : 1;
    return a.segment.localeCompare(b.segment);
  });
}
