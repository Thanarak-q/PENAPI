// Settings panel — localStorage-backed preferences UI. Pure logic lives in
// settings-core.js (DOM-free). This module owns the modal, field wiring, and
// fuzzer-default application.

import { $, toast } from './util.js';
import {
  SETTINGS_KEY,
  loadSettings,
  normalizeSettings,
  serializeSettings,
} from './settings-core.js';

export function getSettings() {
  return loadSettings(localStorage.getItem(SETTINGS_KEY));
}

function saveSettings(settings) {
  localStorage.setItem(SETTINGS_KEY, serializeSettings(settings));
}

export function applyFuzzerDefaults() {
  const s = getSettings();
  if ($('#fuzzConc')) $('#fuzzConc').value = s.fuzzConcurrency;
  if ($('#fuzzDelay')) $('#fuzzDelay').value = s.fuzzDelayMs;
}

export function openSettings() {
  const s = getSettings();
  $('#settingsConcurrency').value = s.fuzzConcurrency;
  $('#settingsDelay').value = s.fuzzDelayMs;
  $('#settingsHistoryLimit').value = s.historyLimit;
  $('#settingsConfirmRisky').checked = s.confirmRisky;
  $('#settingsModal').hidden = false;
}

export function initSettings() {
  $('#settingsSave').addEventListener('click', () => {
    const settings = normalizeSettings({
      fuzzConcurrency: Number($('#settingsConcurrency').value),
      fuzzDelayMs: Number($('#settingsDelay').value),
      historyLimit: Number($('#settingsHistoryLimit').value),
      confirmRisky: $('#settingsConfirmRisky').checked,
    });
    saveSettings(settings);
    applyFuzzerDefaults();
    toast('Settings saved');
    $('#settingsModal').hidden = true;
  });

  $('#closeSettings').addEventListener('click', () => {
    $('#settingsModal').hidden = true;
  });

  applyFuzzerDefaults();
}
