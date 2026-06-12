// Classic application menu bar (File · Edit · View · Attack · Tools · Help).
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

  const closeSubmenus = (root = bar) => {
    $$('.menu-sub.open, .menu-sub.flip-left', root).forEach((sub) => {
      sub.classList.remove('open', 'flip-left');
      $('.submenu-trigger', sub)?.setAttribute('aria-expanded', 'false');
    });
  };
  const closeAll = () => {
    roots.forEach((r) => {
      r.classList.remove('open');
      $('.menu-top', r)?.setAttribute('aria-expanded', 'false');
    });
    closeSubmenus();
  };
  const open = (root) => {
    closeAll();
    root.classList.add('open');
    $('.menu-top', root)?.setAttribute('aria-expanded', 'true');
  };
  const anyOpen = () => roots.some((r) => r.classList.contains('open'));
  const setSubmenuOpen = (sub, isOpen) => {
    sub.classList.toggle('open', isOpen);
    sub.classList.remove('flip-left');
    $('.submenu-trigger', sub)?.setAttribute('aria-expanded', String(isOpen));
  };
  const closeSiblingSubmenus = (root, except) => {
    $$('.menu-sub.open', root).forEach((openSub) => {
      if (openSub !== except) setSubmenuOpen(openSub, false);
    });
  };
  const setFlyoutDirection = (sub) => {
    const drop = $('.submenu-drop', sub);
    if (!drop) return;
    sub.classList.remove('flip-left');
    const width = drop.offsetWidth || 210;
    const gap = 8;
    if (sub.getBoundingClientRect().right + gap + width > window.innerWidth) {
      sub.classList.add('flip-left');
    }
  };

  roots.forEach((root) => {
    const top = $('.menu-top', root);
    top.setAttribute('aria-haspopup', 'menu');
    top.setAttribute('aria-expanded', 'false');
    top.addEventListener('click', (e) => {
      e.stopPropagation();
      root.classList.contains('open') ? closeAll() : open(root);
    });
    top.addEventListener('mouseenter', () => {
      if (anyOpen() && !root.classList.contains('open')) open(root);
    });
  });

  $$('.submenu-trigger', bar).forEach((trigger) => {
    trigger.setAttribute('aria-haspopup', 'menu');
    trigger.setAttribute('aria-expanded', 'false');
    const sub = trigger.closest('.menu-sub');
    const root = trigger.closest('.menu-root');

    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (!root.classList.contains('open')) open(root);

      const shouldOpen = !sub.classList.contains('open');
      closeSiblingSubmenus(root, sub);
      setSubmenuOpen(sub, shouldOpen);
      if (shouldOpen) setFlyoutDirection(sub);
    });

    sub.addEventListener('mouseenter', () => {
      if (root.classList.contains('open')) {
        closeSiblingSubmenus(root, sub);
        setSubmenuOpen(sub, true);
      }
      setFlyoutDirection(sub);
    });
  });

  $$('.menu-item:not(.submenu-trigger)', bar).forEach((item) => {
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
