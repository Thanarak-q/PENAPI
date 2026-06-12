// Match & Replace modal. Manages session-scoped rewrite rules applied to
// requests sent from the Request tab. Transform logic lives in the unit-tested
// matchreplace-core.js; this is the rule editor + persistence.

import { $, el } from './util.js';
import { state, save } from './state.js';
import { activeRuleCount } from './matchreplace-core.js';

function checkbox(checked, onChange) {
  const node = el('input', { type: 'checkbox', onchange: (e) => onChange(e.target.checked) });
  node.checked = !!checked;
  return node;
}

function select(value, options, onChange) {
  const node = el('select', { class: 'mini-select', onchange: (e) => onChange(e.target.value) });
  for (const opt of options) {
    const o = el('option', { value: opt, text: opt });
    if (opt === value) o.selected = true;
    node.appendChild(o);
  }
  return node;
}

function updateCount() {
  const n = activeRuleCount(state.matchReplace);
  $('#mrCount').textContent = n ? `— ${n} active` : '';
}

function ruleRow(rule, i) {
  const isHeader = rule.target === 'header';
  const matchInput = el('input', {
    type: 'text', class: 'k', value: rule.match,
    placeholder: isHeader ? 'Header-Name' : 'find',
    oninput: (e) => { rule.match = e.target.value; }, onchange: () => { save(); updateCount(); },
  });
  const replaceInput = el('input', {
    type: 'text', class: 'v', value: rule.replace,
    placeholder: isHeader ? 'value (empty = remove)' : 'replace with',
    oninput: (e) => { rule.replace = e.target.value; }, onchange: save,
  });
  const regexLabel = el('label', { class: 'check mr-regex' }, [
    checkbox(rule.regex, (v) => { rule.regex = v; save(); }),
    document.createTextNode(' regex'),
  ]);
  regexLabel.style.visibility = isHeader ? 'hidden' : 'visible';

  return el('div', { class: 'mr-rule' }, [
    checkbox(rule.enabled, (v) => { rule.enabled = v; save(); updateCount(); }),
    select(rule.target, ['url', 'body', 'header'], (v) => { rule.target = v; save(); render(); }),
    matchInput,
    replaceInput,
    regexLabel,
    el('span', { class: 'del', text: '✕', onclick: () => { state.matchReplace.splice(i, 1); save(); render(); } }),
  ]);
}

function render() {
  const host = $('#mrRules');
  host.innerHTML = '';
  if (!state.matchReplace.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No rules. Add one to rewrite outgoing requests.' }));
  }
  state.matchReplace.forEach((rule, i) => host.appendChild(ruleRow(rule, i)));
  updateCount();
}

export function openMatchReplace() {
  render();
  $('#mrModal').hidden = false;
}

export function initMatchReplace() {
  $('#mrAdd').addEventListener('click', () => {
    state.matchReplace.push({ enabled: true, target: 'header', match: '', replace: '', regex: false });
    save();
    render();
  });
  $('#closeMr').addEventListener('click', () => ($('#mrModal').hidden = true));
}
