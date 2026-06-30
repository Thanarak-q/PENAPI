// Default (persistent) headers editor. Headers saved here live on the active
// profile (state.defaultHeaders) and are merged into every outgoing request —
// see defaultHeadersObj() in state.js — so pentest headers survive endpoint
// switches instead of being wiped when a new operation is loaded.

import { $, toast } from './util.js';
import { state, save } from './state.js';
import { allHeaders, toHeaderLine } from './attackhdr-core.js';

const COMMON = ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Original-URL'];

export function openDefaultHdr() {
  $('#defaultHdrText').value = state.defaultHeaders || '';
  $('#defaultHdrModal').hidden = false;
}

export function initDefaultHdr() {
  $('#closeDefaultHdr').addEventListener('click', () => ($('#defaultHdrModal').hidden = true));
  $('#defaultHdrSave').addEventListener('click', () => {
    state.defaultHeaders = $('#defaultHdrText').value;
    save();
    $('#defaultHdrModal').hidden = true;
    toast('Default headers saved — merged into every request');
  });
  $('#defaultHdrSeed').addEventListener('click', () => {
    const lines = allHeaders().filter((h) => COMMON.includes(h.name)).map(toHeaderLine);
    const existing = $('#defaultHdrText').value.trim();
    $('#defaultHdrText').value = [existing, ...lines].filter(Boolean).join('\n');
  });
}
