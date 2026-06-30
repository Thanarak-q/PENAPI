// multipart-core.js — DOM-free multipart/form-data serialization for file
// uploads. Assembles text and binary parts into a single byte array so binary
// file contents survive transport (the proxy ships them base64-encoded).
// Pure and environment-agnostic so it runs under `node --test`.

const CRLF = '\r\n';
const DEFAULT_BOUNDARY = '----SwaggernautBoundary7MA4YWxkTrZu0gW';

// Encode a UTF-8 string to bytes in either the browser or Node.
function utf8Bytes(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  return Uint8Array.from(Buffer.from(str, 'utf8'));
}

function concatBytes(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

// parts: [{ name, value, filename?, contentType? }]
//   value is a string (text field) or Uint8Array (raw file bytes).
//   filename/contentType, when present, mark the part as a file upload.
// Returns { boundary, contentType, bytes }.
export function buildMultipart(parts, boundary = DEFAULT_BOUNDARY) {
  const chunks = [];
  for (const part of parts) {
    let header = `--${boundary}${CRLF}Content-Disposition: form-data; name="${part.name}"`;
    if (part.filename != null) header += `; filename="${part.filename}"`;
    header += CRLF;
    if (part.contentType) header += `Content-Type: ${part.contentType}${CRLF}`;
    header += CRLF;
    chunks.push(utf8Bytes(header));
    chunks.push(part.value instanceof Uint8Array ? part.value : utf8Bytes(String(part.value ?? '')));
    chunks.push(utf8Bytes(CRLF));
  }
  chunks.push(utf8Bytes(`--${boundary}--${CRLF}`));
  return {
    boundary,
    contentType: `multipart/form-data; boundary=${boundary}`,
    bytes: concatBytes(chunks),
  };
}

// base64-encode a byte array (browser btoa or Node Buffer).
export function bytesToBase64(bytes) {
  if (typeof btoa !== 'undefined') {
    let s = '';
    const CHUNK = 0x8000; // avoid arg-count limits on String.fromCharCode
    for (let i = 0; i < bytes.length; i += CHUNK) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(s);
  }
  return Buffer.from(bytes).toString('base64');
}
