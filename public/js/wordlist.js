// Wordlist Generator modal. Generation lives in the unit-tested
// wordlist-core.js; this is render + wiring.

import { $, copy, toast } from './util.js';
import { numericRange, affix, mutateWords } from './wordlist-core.js';

function generate() {
  const mode = $('#wlMode').value;
  let words = [];
  if (mode === 'range') {
    words = numericRange($('#wlStart').value, $('#wlEnd').value, $('#wlStep').value, Number($('#wlPad').value) || 0);
  } else {
    const base = $('#wlBase').value.split('\n').map((s) => s.trim()).filter(Boolean);
    words = mutateWords(base, $('#wlLeet').checked);
  }
  words = affix(words, $('#wlPrefix').value, $('#wlSuffix').value);
  $('#wlOut').value = words.join('\n');
  $('#wlCount').textContent = words.length + ' lines';
}

function syncMode() {
  const range = $('#wlMode').value === 'range';
  $('#wlRangeRow').hidden = !range;
  $('#wlMutateRow').hidden = range;
  $('#wlBase').hidden = range;
  generate();
}

export function openWordlist() {
  $('#wlModal').hidden = false;
  syncMode();
}

export function initWordlist() {
  $('#wlMode').addEventListener('change', syncMode);
  for (const id of ['wlStart', 'wlEnd', 'wlStep', 'wlPad', 'wlBase', 'wlPrefix', 'wlSuffix']) {
    $('#' + id).addEventListener('input', generate);
  }
  $('#wlLeet').addEventListener('change', generate);
  $('#wlGen').addEventListener('click', generate);
  $('#wlCopy').addEventListener('click', () => {
    if (!$('#wlOut').value) return toast('Nothing to copy', true);
    copy($('#wlOut').value);
    toast('Wordlist copied');
  });
  $('#closeWl').addEventListener('click', () => ($('#wlModal').hidden = true));
}
