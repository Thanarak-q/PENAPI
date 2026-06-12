// Auth Builder modal. Constructs Authorization header values. Encoding lives in
// the unit-tested auth-core.js; this is wiring only.

import { $, copy, toast } from './util.js';
import { buildBasic, buildBearer } from './auth-core.js';

export function openAuth() {
  $('#authModal').hidden = false;
  $('#authUser').focus();
}

export function initAuth() {
  $('#authBasic').addEventListener('click', () => {
    $('#authOut').value = buildBasic($('#authUser').value, $('#authPass').value);
  });
  $('#authBearer').addEventListener('click', () => {
    $('#authOut').value = buildBearer($('#authToken').value);
  });
  $('#authCopy').addEventListener('click', () => {
    const value = $('#authOut').value;
    if (!value) return toast('Build a header first', true);
    copy('Authorization: ' + value);
  });
  $('#closeAuth').addEventListener('click', () => ($('#authModal').hidden = true));
}
