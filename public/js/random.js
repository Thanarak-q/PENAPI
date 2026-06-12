// Random Generator modal. Appends CSPRNG values for nonces / test data.
// Generators live in the unit-tested random-core.js; this is wiring only.

import { $, copy, toast } from './util.js';
import { randomHex, randomToken, uuidv4, randomString } from './random-core.js';

function add(value) {
  const out = $('#rndOut');
  out.value = (out.value ? out.value + '\n' : '') + value;
  out.scrollTop = out.scrollHeight;
}

export function openRandom() {
  $('#rndModal').hidden = false;
}

export function initRandom() {
  $('#rndUuid').addEventListener('click', () => add(uuidv4()));
  $('#rndHex').addEventListener('click', () => add(randomHex(16)));
  $('#rndToken').addEventListener('click', () => add(randomToken(24)));
  $('#rndStr').addEventListener('click', () => {
    const n = Math.min(Math.max(parseInt($('#rndLen').value, 10) || 16, 1), 256);
    $('#rndLen').value = String(n);
    add(randomString(n));
  });
  $('#rndClear').addEventListener('click', () => ($('#rndOut').value = ''));
  $('#rndCopy').addEventListener('click', () => {
    if (!$('#rndOut').value) return toast('Nothing to copy', true);
    copy($('#rndOut').value);
  });
  $('#closeRnd').addEventListener('click', () => ($('#rndModal').hidden = true));
}
