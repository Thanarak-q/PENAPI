// Export tabular results to CSV / Markdown / JSON and trigger a download.

import { toast } from './util.js';

function csvCell(v) {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

export function toCSV(headers, rows) {
  const lines = [headers.map(csvCell).join(',')];
  for (const r of rows) lines.push(headers.map((h) => csvCell(r[h])).join(','));
  return lines.join('\n');
}

export function toMarkdown(headers, rows) {
  const esc = (v) => String(v == null ? '' : v).replace(/\|/g, '\\|');
  const lines = [
    '| ' + headers.join(' | ') + ' |',
    '| ' + headers.map(() => '---').join(' | ') + ' |',
  ];
  for (const r of rows) lines.push('| ' + headers.map((h) => esc(r[h])).join(' | ') + ' |');
  return lines.join('\n');
}

export function download(filename, content, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  toast('Exported ' + filename);
}

// Wire a CSV/MD/JSON button trio in a toolbar element.
// getData() must return { headers: string[], rows: object[], name: string }.
export function attachExport(container, getData) {
  const mk = (label, fmt) => {
    const b = document.createElement('button');
    b.className = 'btn ghost tiny';
    b.textContent = label;
    b.title = `Export this table as ${label}`;
    b.addEventListener('click', () => doExport(getData(), fmt));
    return b;
  };
  const wrap = document.createElement('span');
  wrap.className = 'export-group';
  wrap.append(
    Object.assign(document.createElement('span'), { className: 'meta', textContent: 'export:' }),
    mk('CSV', 'csv'),
    mk('MD', 'md'),
    mk('JSON', 'json')
  );
  container.appendChild(wrap);
}

function doExport({ headers, rows, name }, fmt) {
  if (!rows || !rows.length) return toast('Nothing to export', true);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const base = `${name}-${stamp}`;
  if (fmt === 'csv') download(`${base}.csv`, toCSV(headers, rows), 'text/csv');
  else if (fmt === 'md') download(`${base}.md`, toMarkdown(headers, rows), 'text/markdown');
  else download(`${base}.json`, JSON.stringify(rows, null, 2), 'application/json');
}
