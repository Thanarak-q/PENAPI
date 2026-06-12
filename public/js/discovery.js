// Content Discovery modal. Brute-forces common/extra paths off a base URL to
// surface unspecced (shadow) endpoints. Client-driven through the existing
// proxy, with a hard cap and a confirmation gate (it sends real requests).
// Candidate building + classification live in the unit-tested discovery-core.js.

import { $, el, statusClass, toast } from './util.js';
import { state, identityHeaders } from './state.js';
import { sendProxy } from './api.js';
import { parseWordlist, buildCandidates, classify, COMMON_PATHS } from './discovery-core.js';

const CAP = 500;
const CONCURRENCY = 5;

let results = [];
let running = false;
let abort = false;

function gatherWords() {
  const words = [];
  if ($('#dscBuiltin').checked) words.push(...COMMON_PATHS);
  words.push(...parseWordlist($('#dscCustom').value));
  return words;
}

async function run() {
  if (running) return;
  const base = $('#dscBase').value.trim();
  if (!base) return toast('Set a base URL', true);

  let candidates = buildCandidates(base, gatherWords());
  if (!candidates.length) return toast('No paths to try', true);
  const capped = candidates.length > CAP;
  if (capped) candidates = candidates.slice(0, CAP);

  const warning = [
    `Content Discovery will send ${candidates.length} real GET requests to ${base}${capped ? ` (capped at ${CAP})` : ''}.`,
    'Only run this against systems you are authorized to test.',
    'Continue?',
  ].join('\n');
  if (!confirm(warning)) return;

  running = true;
  abort = false;
  results = [];
  $('#dscRun').disabled = true;
  $('#dscStop').disabled = false;
  renderResults();

  const headers = {};
  for (const [k, v] of Object.entries(identityHeaders())) if (v !== null) headers[k] = v;

  let idx = 0;
  let done = 0;
  const worker = async () => {
    while (!abort) {
      const i = idx++;
      if (i >= candidates.length) break;
      const c = candidates[i];
      let result;
      try {
        const data = await sendProxy({ method: 'GET', url: c.url, headers, body: null, followRedirects: false });
        result = data.result || { error: data.error || 'failed' };
      } catch (e) {
        result = { error: e.message };
      }
      const cls = classify(result.error ? null : result.status);
      results.push({
        word: c.word, url: c.url,
        status: result.error ? null : result.status,
        size: result.size ?? null, kind: cls.kind, interesting: cls.interesting,
      });
      done++;
      $('#dscProgress').textContent = `${done} / ${candidates.length}`;
      if (done % 5 === 0 || done < 20) renderResults();
    }
  };

  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, candidates.length) }, worker));

  running = false;
  $('#dscRun').disabled = false;
  $('#dscStop').disabled = true;
  renderResults();
  const hits = results.filter((r) => r.interesting).length;
  toast(`Discovery complete — ${hits} interesting / ${results.length}`);
}

function renderResults() {
  const tbody = $('#dscTable tbody');
  tbody.innerHTML = '';
  const interestingOnly = $('#dscInteresting').checked;
  const rows = results.slice().sort((a, b) =>
    (b.interesting - a.interesting) || ((a.status || 999) - (b.status || 999))
  );
  for (const r of rows) {
    if (interestingOnly && !r.interesting) continue;
    tbody.appendChild(el('tr', { class: r.interesting ? 'flagged' : '' }, [
      el('td', { text: '/' + r.word, title: r.url }),
      el('td', {}, [
        r.status == null
          ? el('span', { text: 'ERR', style: 'color:var(--red)' })
          : el('span', { class: 'code-num ' + statusClass(r.status), text: String(r.status) }),
      ]),
      el('td', {}, [el('span', { class: 'flag-tag ' + (r.interesting ? 'flag-vuln' : 'flag-ok'), text: r.kind })]),
      el('td', { text: r.size == null ? '–' : String(r.size) }),
    ]));
  }
}

export function openDiscovery() {
  if (!$('#dscBase').value) $('#dscBase').value = state.baseUrl || '';
  $('#dscModal').hidden = false;
}

export function initDiscovery() {
  $('#dscRun').addEventListener('click', run);
  $('#dscStop').addEventListener('click', () => { abort = true; });
  $('#dscInteresting').addEventListener('change', renderResults);
  $('#closeDsc').addEventListener('click', () => ($('#dscModal').hidden = true));
}
