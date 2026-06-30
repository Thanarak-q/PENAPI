// Form-data body builder for the Request tab. Renders a row per field with a
// text/file type switch; on send it reads any chosen files as raw bytes and
// produces a base64-encoded multipart body (binary-safe over the JSON proxy).

import { $, $$, el } from './util.js';
import { buildMultipart, bytesToBase64 } from './multipart-core.js';

// Build one form-data row. `field` comes from the spec ({name, isFile, example}).
function addFormRow(field = {}) {
  const root = $('#formDataTable');
  const isFile = !!field.isFile;
  const valueInput = el('input', {
    type: 'text',
    class: 'v fd-value',
    value: field.example == null ? '' : String(field.example),
    placeholder: 'value',
  });
  const fileInput = el('input', { type: 'file', class: 'fd-file' });
  const typeSel = el('select', { class: 'fd-type' }, [
    el('option', { value: 'text', text: 'text', ...(isFile ? {} : { selected: 'selected' }) }),
    el('option', { value: 'file', text: 'file', ...(isFile ? { selected: 'selected' } : {}) }),
  ]);
  const applyType = () => {
    const file = typeSel.value === 'file';
    fileInput.hidden = !file;
    valueInput.hidden = file;
  };
  typeSel.addEventListener('change', applyType);
  const node = el('div', { class: 'kv-row fd-row' }, [
    el('input', { type: 'checkbox', checked: 'checked' }),
    el('input', { type: 'text', class: 'k fd-name', value: field.name || '', placeholder: 'field name' }),
    typeSel,
    valueInput,
    fileInput,
    el('span', { class: 'del', text: '✕', onclick: () => node.remove() }),
  ]);
  root.appendChild(node);
  applyType();
}

// (Re)render the builder from a spec field list. Always leaves one blank row.
export function renderFormData(fields = []) {
  const root = $('#formDataTable');
  root.innerHTML = '';
  for (const f of fields) addFormRow(f);
  if (!fields.length) addFormRow({});
}

export function addBlankFormRow() {
  addFormRow({});
}

// Read the builder into a base64 multipart body. Reads file bytes via the File
// API. Returns { contentType, base64Body } or null when there are no fields.
export async function buildFormDataBody() {
  const parts = [];
  for (const row of $$('.fd-row', $('#formDataTable'))) {
    if (!row.querySelector('input[type=checkbox]').checked) continue;
    const name = row.querySelector('.fd-name').value.trim();
    if (!name) continue;
    if (row.querySelector('.fd-type').value === 'file') {
      const file = row.querySelector('.fd-file').files[0];
      if (file) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        parts.push({ name, value: bytes, filename: file.name, contentType: file.type || 'application/octet-stream' });
      } else {
        // File field with no chosen file — send an empty file part so the
        // server still sees the field shape.
        parts.push({ name, value: new Uint8Array(0), filename: '', contentType: 'application/octet-stream' });
      }
    } else {
      parts.push({ name, value: row.querySelector('.fd-value').value });
    }
  }
  if (!parts.length) return null;
  const { contentType, bytes } = buildMultipart(parts);
  return { contentType, base64Body: bytesToBase64(bytes) };
}
