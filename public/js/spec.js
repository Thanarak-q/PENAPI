// Spec loader modal: load an OpenAPI/Swagger spec from URL, file, or paste.

import { $, toast } from './util.js';
import { uploadSpec, loadSpecUrl } from './api.js';

let applySpec = () => {};

export function initSpecLoader(applyHandler) {
  applySpec = applyHandler;
  $('#loadSpecBtn').addEventListener('click', open);
  $('#closeSpec').addEventListener('click', close);
  $('#specUrlLoad').addEventListener('click', fromUrl);
  $('#specFile').addEventListener('change', fromFile);
  $('#specPasteLoad').addEventListener('click', fromPaste);
}

export function setSpecSourceLabel(src) {
  $('#specSourceLabel').textContent = src || '—';
}

function open() {
  $('#specModal').hidden = false;
}
function close() {
  $('#specModal').hidden = true;
}

async function fromUrl() {
  const url = $('#specUrl').value.trim();
  if (!url) return toast('Enter a URL', true);
  toast('Fetching spec…');
  const { ok, spec, specSource, error } = await loadSpecUrl(url);
  if (!ok) return toast('Load failed: ' + error, true);
  applySpec(spec, specSource || url);
  close();
}

function fromFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async () => {
    const { ok, spec, error } = await uploadSpec(reader.result);
    if (!ok) return toast('Parse failed: ' + error, true);
    applySpec(spec, file.name);
    close();
  };
  reader.readAsText(file);
}

async function fromPaste() {
  const content = $('#specPaste').value.trim();
  if (!content) return toast('Paste some JSON', true);
  const { ok, spec, error } = await uploadSpec(content);
  if (!ok) return toast('Parse failed: ' + error, true);
  applySpec(spec, '(pasted)');
  close();
}
