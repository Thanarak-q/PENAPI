// User-Agent Library modal. The list + search live in the unit-tested
// useragent-core.js; this is render + wiring.

import { $, el, copy, toast } from './util.js';
import { searchAgents } from './useragent-core.js';

function render() {
  const host = $('#uaOut');
  host.innerHTML = '';
  const rows = searchAgents($('#uaIn').value);
  if (!rows.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No User-Agent matches.' }));
    return;
  }
  let lastCat = null;
  for (const e of rows) {
    if (e.category !== lastCat) {
      host.appendChild(el('div', { class: 'rd-group-title', text: e.category }));
      lastCat = e.category;
    }
    const btn = el('button', { class: 'btn tiny ghost', text: 'copy', title: 'Copy this User-Agent string' });
    btn.addEventListener('click', () => { copy(e.ua); toast('UA copied'); });
    host.appendChild(el('div', { class: 'ah-row' }, [
      el('div', { class: 'ah-head' }, [
        el('span', { class: 'ah-name', text: e.label }),
        btn,
      ]),
      el('div', { class: 'ua-string', text: e.ua || '(empty string)' }),
    ]));
  }
}

export function openUserAgent() {
  $('#uaModal').hidden = false;
  $('#uaIn').focus();
  render();
}

export function initUserAgent() {
  $('#uaIn').addEventListener('input', render);
  $('#closeUa').addEventListener('click', () => ($('#uaModal').hidden = true));
}
