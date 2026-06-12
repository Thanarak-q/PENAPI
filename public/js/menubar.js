// Classic application menu bar (File · Edit · View · Tools · Help).
// One menu open at a time; hovering a sibling while open switches to it;
// click-outside / Esc / choosing an item closes.
//
// Menu items act in two ways:
//   data-act="click:<id>"   → forwards a click to an existing button by id
//   data-act="<name>"       → calls a handler supplied via initMenubar(handlers)
// Items with their own id (e.g. #loadSpecBtn) keep their existing listeners and
// just close the menu on click.

import { $, $$ } from './util.js';
import { openPalette } from './palette.js';

let handlers = {};

export function initMenubar(actionHandlers = {}) {
  handlers = actionHandlers;
  const bar = $('#menubar');
  if (!bar) return;
  const roots = $$('.menu-root', bar);

  const closeAll = () => roots.forEach((r) => r.classList.remove('open'));
  const open = (root) => {
    closeAll();
    root.classList.add('open');
  };
  const anyOpen = () => roots.some((r) => r.classList.contains('open'));

  roots.forEach((root) => {
    const top = $('.menu-top', root);
    top.addEventListener('click', (e) => {
      e.stopPropagation();
      root.classList.contains('open') ? closeAll() : open(root);
    });
    top.addEventListener('mouseenter', () => {
      if (anyOpen() && !root.classList.contains('open')) open(root);
    });
  });

  $$('.menu-item', bar).forEach((item) => {
    item.addEventListener('click', () => {
      if (item.dataset.act) runAct(item.dataset.act);
      closeAll();
    });
  });

  document.addEventListener('click', (e) => {
    if (!bar.contains(e.target)) closeAll();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAll();
  });
}

function runAct(act) {
  if (act.startsWith('click:')) {
    const el = document.getElementById(act.slice(6));
    if (el) el.click();
    return;
  }
  if (act === 'find') {
    $('#endpointSearch')?.focus();
    return;
  }
  if (act === 'palette') return openPalette();
  const fn = handlers[act];
  if (fn) fn();
}
