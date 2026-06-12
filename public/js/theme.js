// Theme controls: global color palette + light/dark mode.

import { $ } from './util.js';

const THEME_KEY = 'swaggernaut.theme.v1';
const DEFAULT_THEME = { mode: 'light', palette: 'signal' };
const MODES = new Set(['light', 'dark']);
const PALETTES = new Set(['signal', 'ocean', 'volt', 'grape']);

function loadTheme() {
  try {
    const parsed = JSON.parse(localStorage.getItem(THEME_KEY) || '{}');
    return normalizeTheme(parsed);
  } catch {
    return DEFAULT_THEME;
  }
}

function normalizeTheme(theme) {
  return {
    mode: MODES.has(theme?.mode) ? theme.mode : DEFAULT_THEME.mode,
    palette: PALETTES.has(theme?.palette) ? theme.palette : DEFAULT_THEME.palette,
  };
}

function saveTheme(theme) {
  localStorage.setItem(THEME_KEY, JSON.stringify(normalizeTheme(theme)));
}

function applyTheme(theme) {
  const next = normalizeTheme(theme);
  document.documentElement.dataset.theme = next.mode;
  document.documentElement.dataset.palette = next.palette;

  const modeButton = $('#themeMode');
  if (modeButton) {
    const dark = next.mode === 'dark';
    modeButton.textContent = dark ? 'Light' : 'Dark';
    modeButton.setAttribute('aria-pressed', String(dark));
    modeButton.title = dark ? 'Switch to light theme' : 'Switch to dark theme';
  }

  $('#themePalette')?.querySelectorAll('[data-palette]').forEach((button) => {
    const selected = button.dataset.palette === next.palette;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });

  return next;
}

export function initTheme() {
  let theme = applyTheme(loadTheme());

  $('#themePalette')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-palette]');
    if (!button) return;
    theme = applyTheme({ ...theme, palette: button.dataset.palette });
    saveTheme(theme);
  });

  $('#themeMode')?.addEventListener('click', () => {
    theme = applyTheme({ ...theme, mode: theme.mode === 'dark' ? 'light' : 'dark' });
    saveTheme(theme);
  });
}
