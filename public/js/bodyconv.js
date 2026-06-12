// Body Converter modal. Conversion lives in the unit-tested bodyconv-core.js;
// this is render + wiring.

import { $, el, copy, toast } from './util.js';
import { convertBody } from './bodyconv-core.js';

function outBlock(title, contentType, value) {
  const pre = el('pre', { class: 'code output bc-pre', text: value });
  const btn = el('button', { class: 'btn tiny ghost', text: 'copy', title: `Copy ${title} body` });
  btn.addEventListener('click', () => { copy(value); toast('Copied'); });
  return el('div', { class: 'bc-block' }, [
    el('div', { class: 'bc-head' }, [
      el('span', { class: 'bc-title', text: title }),
      el('code', { class: 'bc-ct', text: contentType }),
      btn,
    ]),
    pre,
  ]);
}

function render() {
  const host = $('#bcOut');
  host.innerHTML = '';
  const text = $('#bcIn').value;
  if (!text.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a JSON object to convert.' }));
    return;
  }
  const r = convertBody(text);
  if (!r.ok) {
    host.appendChild(el('span', { class: 'flag-tag flag-vuln', text: 'error' }));
    host.appendChild(el('div', { class: 'hdr-note', text: r.error }));
    return;
  }
  host.appendChild(outBlock('Form URL-encoded', 'application/x-www-form-urlencoded', r.formUrlencoded));
  host.appendChild(outBlock('Query string', 'append to URL', r.queryString));
  host.appendChild(outBlock('Multipart', 'multipart/form-data; boundary=' + r.multipartBoundary, r.multipart));
}

export function openBodyConv() {
  $('#bcModal').hidden = false;
  $('#bcIn').focus();
}

export function initBodyConv() {
  $('#bcRun').addEventListener('click', render);
  $('#bcIn').addEventListener('input', render);
  $('#closeBc').addEventListener('click', () => ($('#bcModal').hidden = true));
}
