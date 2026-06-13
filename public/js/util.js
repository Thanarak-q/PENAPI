// Small DOM + formatting helpers shared across modules.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function methodClass(m) {
  return 'm-' + (m || 'get').toLowerCase();
}

export function statusClass(code) {
  if (!code) return '';
  if (code < 300) return 's-2xx';
  if (code < 400) return 's-3xx';
  if (code < 500) return 's-4xx';
  return 's-5xx';
}

export function fmtBytes(n) {
  if (n == null || !Number.isFinite(Number(n))) return '–';
  const bytes = Number(n);
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

export function prettyJson(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

export function headersToText(headers) {
  return Object.entries(headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

export function textToHeaders(text) {
  const out = {};
  for (const line of (text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const idx = t.indexOf(':');
    if (idx === -1) continue;
    out[t.slice(0, idx).trim()] = t.slice(idx + 1).trim();
  }
  return out;
}

let toastTimer = null;
export function toast(msg, isErr = false) {
  const t = $('#toast');
  if (!t) return; // tolerate being called before the toast element exists
  t.textContent = msg;
  t.classList.toggle('err', isErr);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3200);
}

export async function copy(text) {
  const value = String(text ?? '');
  // Preferred path: the async Clipboard API (requires a secure context —
  // https or localhost). Falls back to execCommand for plain-HTTP LAN use,
  // which is common for a tool served with `--host`.
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      toast('Copied to clipboard');
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  if (legacyCopy(value)) {
    toast('Copied to clipboard');
    return true;
  }
  toast('Copy failed — select and copy manually', true);
  return false;
}

// Hidden-textarea + execCommand fallback. Returns whether the copy succeeded.
function legacyCopy(value) {
  try {
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// Switch to a top-level tab by name, firing its click handler so per-tab
// render hooks run. Single source of truth for in-app navigation.
export function goTab(name) {
  const tab = document.querySelector(`.tab[data-tab="${name}"]`);
  if (tab) tab.click();
}
