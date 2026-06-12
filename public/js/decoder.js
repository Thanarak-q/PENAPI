// Decoder tab. Encode / decode / smart-decode / hash arbitrary text. All
// client-side — nothing is sent. Transform logic lives in the unit-tested
// decoder-core.js; this module is wiring only.

import { $, toast, copy, goTab } from './util.js';
import { getCurrentRequest } from './request.js';
import * as codec from './decoder-core.js';

const OPS = {
  base64: { encode: codec.base64Encode, decode: codec.base64Decode },
  base64url: { encode: codec.base64UrlEncode, decode: codec.base64UrlDecode },
  url: { encode: codec.urlEncode, decode: codec.urlDecode },
  hex: { encode: codec.hexEncode, decode: codec.hexDecode },
  html: { encode: codec.htmlEncode, decode: codec.htmlDecode },
  jwt: { encode: null, decode: codec.jwtDecodePretty },
};

function setOutput(text) {
  $('#decOut').value = text;
}

function transform(direction) {
  const format = $('#decFormat').value;
  const input = $('#decIn').value;
  const op = OPS[format];
  const fn = op && op[direction];
  if (!fn) {
    toast(`${format} has no ${direction} operation`, true);
    return;
  }
  try {
    setOutput(fn(input));
  } catch (e) {
    setOutput(`[${direction} error] ${e.message}`);
  }
}

function smart() {
  const { format, output } = codec.smartDecode($('#decIn').value);
  setOutput(output);
  $('#decDetected').textContent = format === 'plain' || format === 'none'
    ? 'no encoding detected'
    : `detected: ${format}`;
}

async function hash() {
  const algo = $('#decHash').value;
  const input = $('#decIn').value;
  try {
    const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(input));
    const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
    setOutput(hex);
    $('#decDetected').textContent = `${algo} · ${hex.length * 4} bits`;
  } catch (e) {
    setOutput(`[hash error] ${e.message}`);
  }
}

function swap() {
  const out = $('#decOut').value;
  if (!out) return;
  $('#decIn').value = out;
  setOutput('');
  $('#decDetected').textContent = '';
}

function fromRequest() {
  const req = getCurrentRequest({ withIdentity: false });
  const text = req.body || req.url || '';
  if (!text) return toast('Current request has no body or URL', true);
  $('#decIn').value = text;
  $('#decDetected').textContent = '';
}

export function sendToDecoder(text) {
  $('#decIn').value = text || '';
  setOutput('');
  $('#decDetected').textContent = '';
  goTab('decoder');
}

export function initDecoder() {
  $('#decEncode').addEventListener('click', () => transform('encode'));
  $('#decDecode').addEventListener('click', () => transform('decode'));
  $('#decSmart').addEventListener('click', smart);
  $('#decHashBtn').addEventListener('click', hash);
  $('#decSwap').addEventListener('click', swap);
  $('#decFromReq').addEventListener('click', fromRequest);
  $('#decCopy').addEventListener('click', () => copy($('#decOut').value));
  $('#decClear').addEventListener('click', () => {
    $('#decIn').value = '';
    setOutput('');
    $('#decDetected').textContent = '';
  });
}
