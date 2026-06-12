// Token Sequencer modal. Analyzes a pasted set of tokens for randomness.
// Logic lives in the unit-tested sequencer-core.js; this is wiring + render.

import { $, el } from './util.js';
import { analyzeTokens } from './sequencer-core.js';

function analyze() {
  const tokens = $('#tokInput').value.split('\n');
  const r = analyzeTokens(tokens);
  const host = $('#tokReport');
  host.hidden = false;
  host.innerHTML = '';

  host.appendChild(el('div', { class: 'tok-verdict tok-' + r.verdict.level }, [
    el('span', { class: 'tok-grade', text: r.verdict.level.toUpperCase() }),
    el('span', { text: r.verdict.label }),
  ]));

  const stats = [
    ['Samples', `${r.total} (${r.unique} unique${r.duplicates ? `, ${r.duplicates} duplicate` : ''})`],
    ['Length', r.sameLength ? `${r.minLen} (fixed)` : `${r.minLen}–${r.maxLen} (varies)`],
    ['Charset', `${r.charsetSize} distinct chars`],
    ['Entropy', `~${r.totalEntropyBits.toFixed(1)} bits total · ${r.bitsPerChar.toFixed(2)} bits/char`],
  ];
  const table = el('div', { class: 'tok-stats' });
  for (const [k, v] of stats) {
    table.appendChild(el('div', { class: 'tok-stat' }, [
      el('span', { class: 'tok-k', text: k }),
      el('span', { class: 'tok-v', text: v }),
    ]));
  }
  host.appendChild(table);

  if (r.perPosition.length) {
    const max = Math.max(...r.perPosition, 0.0001);
    const bars = el('div', { class: 'tok-bars', title: 'Per-character-position entropy (bits)' });
    r.perPosition.forEach((bits, i) => {
      bars.appendChild(el('span', {
        class: 'tok-bar',
        style: `height:${Math.max(2, Math.round((bits / max) * 40))}px`,
        title: `pos ${i + 1}: ${bits.toFixed(2)} bits`,
      }));
    });
    host.appendChild(el('div', { class: 'tok-bars-label', text: 'Entropy by character position' }));
    host.appendChild(bars);
  }
}

export function openSequencer() {
  $('#tokModal').hidden = false;
  $('#tokInput').focus();
}

export function initSequencer() {
  $('#tokAnalyze').addEventListener('click', analyze);
  $('#closeTok').addEventListener('click', () => ($('#tokModal').hidden = true));
}
