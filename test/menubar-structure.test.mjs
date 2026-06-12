import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

const buttons = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)].map((match) => {
  const attrs = match[1];
  return {
    attrs,
    id: attrs.match(/\bid="([^"]+)"/)?.[1] || '',
    className: attrs.match(/\bclass="([^"]+)"/)?.[1] || '',
    title: attrs.match(/\btitle="([^"]+)"/)?.[1] || '',
    dataDesc: attrs.match(/\bdata-desc="([^"]+)"/)?.[1] || '',
    text: match[2].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim(),
  };
});

function menuSection(label) {
  const marker = new RegExp(`<button\\b[^>]*class="menu-top"[^>]*>${label}</button>`);
  const match = marker.exec(html);
  const start = match?.index ?? -1;
  assert.notEqual(start, -1, `${label} menu exists`);

  const next = html.indexOf('<div class="menu-root">', start + match[0].length);
  return next === -1 ? html.slice(start) : html.slice(start, next);
}

test('main menu separates attack tooling from utility tools', () => {
  const labels = buttons
    .filter((button) => button.className.split(/\s+/).includes('menu-top'))
    .map((button) => button.text);
  assert.deepEqual(labels.slice(0, 6), ['File', 'Edit', 'View', 'Attack', 'Tools', 'Help']);

  const attack = menuSection('Attack');
  const tools = menuSection('Tools');

  for (const text of ['Payloads', 'Headers &amp; spoofing']) {
    assert.ok(attack.includes(text), `Attack menu includes ${text}`);
  }
  for (const action of ['payloadlib', 'redirect', 'wordlist', 'attackhdr', 'useragent', 'ipobf', 'matchreplace', 'discovery']) {
    assert.ok(attack.includes(action), `Attack menu includes ${action}`);
    assert.equal(tools.includes(`data-act="${action}"`), false, `Tools menu excludes ${action}`);
  }
  assert.ok(attack.includes('click:quickAttackBtn'), 'Attack menu includes Quick Attacks');
});

test('tools menu keeps utility commands in nested groups', () => {
  const tools = menuSection('Tools');

  for (const text of ['Tokens &amp; crypto', 'Encode &amp; convert', 'Recon &amp; analysis']) {
    assert.ok(tools.includes(text), `Tools menu includes ${text}`);
  }
  assert.equal((tools.match(/class="menu-item submenu-trigger"/g) || []).length, 3);
  assert.equal((tools.match(/class="submenu-drop"/g) || []).length, 3);
});

test('request view does not render the current endpoint placeholder strip', () => {
  assert.equal(html.includes('id="currentEndpoint"'), false);
  assert.equal(html.includes('id="currentMethod"'), false);
  assert.equal(html.includes('id="currentPath"'), false);
  assert.equal(html.includes('class="current-path"'), false);
  assert.equal(html.includes('Pick an endpoint'), false);
});

test('short and high-impact buttons expose useful hover help', () => {
  const requiresHelp = (button) => {
    const classes = button.className.split(/\s+/);
    return classes.includes('menu-top') ||
      classes.includes('submenu-trigger') ||
      classes.some((className) => className.startsWith('mchip')) ||
      classes.includes('danger') ||
      ['clearFilters', 'clearHistory', 'seqClear', 'rndClear', 'fuzzStart', 'matrixRun', 'seqRun', 'sweepStart', 'dscRun', 'historyReplay', 'jwtBrute', 'jwtForgeNone', 'specUrlLoad'].includes(button.id);
  };

  const missing = buttons
    .filter(requiresHelp)
    .filter((button) => !button.title && !button.dataDesc)
    .map((button) => button.id || button.text);

  assert.deepEqual(missing, []);
});

test('dynamic generated short buttons expose hover help', () => {
  const expectedSnippets = {
    'public/js/useragent.js': 'Copy this User-Agent string',
    'public/js/attackhdr.js': 'Copy this header line',
    'public/js/payloads-lib.js': 'Copy this payload',
    'public/js/bodyconv.js': 'Copy ${title} body',
    'public/js/sequence.js': 'Capture a value from this step response',
    'public/js/export.js': 'Export this table as ${label}',
    'public/js/history.js': 'Open request and response details',
    'public/js/explorer.js': 'Delete this focus tag from every endpoint',
  };

  for (const [path, snippet] of Object.entries(expectedSnippets)) {
    assert.ok(source(path).includes(snippet), `${path} includes "${snippet}"`);
  }
});

test('theme controls expose palette and dark mode choices', () => {
  assert.ok(html.includes('id="themePalette"'), 'palette selector exists');
  assert.ok(html.includes('id="themeMode"'), 'dark mode toggle exists');
  assert.ok(html.includes('data-palette="signal"'), 'signal palette option exists');
  assert.ok(html.includes('data-palette="ocean"'), 'ocean palette option exists');
  assert.ok(html.includes('data-palette="volt"'), 'volt palette option exists');
  assert.ok(html.includes('data-palette="grape"'), 'grape palette option exists');
  assert.ok(source('public/js/main.js').includes("import { initTheme } from './theme.js';"));
  assert.ok(source('public/js/theme.js').includes('swaggernaut.theme.v1'));
});

test('help menu links to a documentation-style user guide page', () => {
  const help = menuSection('Help');
  assert.ok(help.includes('data-act="guide"'), 'Help menu includes guide action');
  assert.ok(source('public/js/main.js').includes("window.open('/guide.html'"));

  const guide = source('public/guide.html');
  for (const text of [
    'guide-sidebar',
    'Swaggernaut Guide',
    'Start safely',
    'Suggested workflow',
    'Attack tools',
    'Where tools live',
    'Attack -> Payloads',
    'Tools -> Tokens &amp; crypto',
    'Dark mode',
    'Color palettes',
  ]) {
    assert.ok(guide.includes(text), `guide includes ${text}`);
  }
});
