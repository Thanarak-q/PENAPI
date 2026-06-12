// Cookie Inspector modal. Parses + audits Set-Cookie values. Parsing/audit live
// in the unit-tested cookie-core.js; this is render + wiring.

import { $, el } from './util.js';
import { parseSetCookie, auditCookie } from './cookie-core.js';

function flag(label, ok) {
  return el('span', { class: 'flag-tag ' + (ok ? 'flag-ok' : 'flag-vuln'), text: label });
}

function analyze() {
  const lines = $('#ckIn').value.split('\n').map((s) => s.trim()).filter(Boolean);
  const host = $('#ckOut');
  host.innerHTML = '';
  if (!lines.length) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste one or more Set-Cookie header values.' }));
    return;
  }
  for (const line of lines) {
    const c = parseSetCookie(line);
    const issues = auditCookie(c);
    const flags = [
      flag('HttpOnly', c.httpOnly),
      flag('Secure', c.secure),
      flag('SameSite' + (c.sameSite ? '=' + c.sameSite : ''), !!c.sameSite && !/^none$/i.test(c.sameSite)),
    ];
    host.appendChild(el('div', { class: 'ck-card' }, [
      el('div', { class: 'ck-head' }, [
        el('span', { class: 'ck-name', text: c.name }),
        el('span', { class: 'ck-val', text: c.value, title: c.value }),
      ]),
      el('div', { class: 'ck-flags' }, flags),
      ...issues.map((i) => el('div', { class: 'ck-issue', text: '⚠ ' + i })),
    ]));
  }
}

export function openCookie() {
  $('#ckModal').hidden = false;
  $('#ckIn').focus();
}

export function initCookie() {
  $('#ckRun').addEventListener('click', analyze);
  $('#ckIn').addEventListener('input', analyze);
  $('#closeCk').addEventListener('click', () => ($('#ckModal').hidden = true));
}
