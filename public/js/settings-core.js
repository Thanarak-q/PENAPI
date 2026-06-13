// Settings — pure, DOM-free core for normalise / load / serialise. No
// localStorage access here so the logic runs under `node --test` without a DOM.

export const SETTINGS_KEY = 'swaggernaut.settings.v1';

export const DEFAULTS = {
  fuzzConcurrency: 8,
  fuzzDelayMs: 0,
  confirmRisky: true,
  historyLimit: 200,
};

function clamp(val, min, max) {
  return Math.max(min, Math.min(max, val));
}

export function normalizeSettings(obj) {
  const src = obj && typeof obj === 'object' ? obj : {};

  const rawConc = Number(src.fuzzConcurrency);
  const fuzzConcurrency = clamp(
    Math.trunc(isNaN(rawConc) ? DEFAULTS.fuzzConcurrency : rawConc),
    1,
    50,
  );

  const rawDelay = Number(src.fuzzDelayMs);
  const fuzzDelayMs = clamp(
    Math.trunc(isNaN(rawDelay) ? DEFAULTS.fuzzDelayMs : rawDelay),
    0,
    10000,
  );

  const rawHistory = Number(src.historyLimit);
  const historyLimit = clamp(
    Math.trunc(isNaN(rawHistory) ? DEFAULTS.historyLimit : rawHistory),
    10,
    2000,
  );

  const confirmRisky =
    src.confirmRisky === undefined ? DEFAULTS.confirmRisky : Boolean(src.confirmRisky);

  return { fuzzConcurrency, fuzzDelayMs, confirmRisky, historyLimit };
}

export function loadSettings(raw) {
  try {
    const parsed = JSON.parse(raw || '{}');
    return normalizeSettings(parsed);
  } catch {
    return { ...DEFAULTS };
  }
}

export function serializeSettings(settings) {
  return JSON.stringify(normalizeSettings(settings));
}
