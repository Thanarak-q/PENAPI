// Thin wrappers over the backend API.

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

export async function fetchSpec() {
  const res = await fetch('/api/spec');
  return res.json();
}

export async function uploadSpec(content) {
  return postJson('/api/spec/upload', { content });
}

export async function loadSpecUrl(url) {
  return postJson('/api/spec/url', { url });
}

export async function sendProxy(request) {
  return postJson('/api/proxy', request);
}

export async function runMatrix(request, identities) {
  return postJson('/api/matrix', { request, identities });
}

export async function parseCurl(curl) {
  return postJson('/api/curl/parse', { curl });
}

export async function buildCurl(request) {
  return postJson('/api/curl/build', request);
}

export async function fetchPayloadSets() {
  const res = await fetch('/api/payloads');
  return res.json();
}

export async function runAttacks(request) {
  return postJson('/api/attacks', { request });
}

// Streaming auth-coverage sweep (SSE). Returns an abort function.
export function startSweep(payload, handlers) {
  return streamSSE('/api/sweep', payload, handlers);
}

// Open an SSE-style fuzz stream. Returns an abort function.
export function startFuzz(payload, handlers) {
  return streamSSE('/api/fuzz', payload, handlers);
}

// POST a JSON body and read back a Server-Sent-Events stream. Dispatches
// start/result/done/error events to the matching handler. Returns an abort fn.
function streamSSE(url, payload, handlers) {
  const controller = new AbortController();
  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        handlers.onError?.(data.error || `HTTP ${res.status}`);
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const events = buf.split('\n\n');
        buf = events.pop();
        for (const chunk of events) {
          const evMatch = chunk.match(/^event: (.+)$/m);
          const dataMatch = chunk.match(/^data: (.+)$/m);
          if (!evMatch || !dataMatch) continue;
          const ev = evMatch[1];
          const data = JSON.parse(dataMatch[1]);
          if (ev === 'start') handlers.onStart?.(data);
          else if (ev === 'result') handlers.onResult?.(data);
          else if (ev === 'done') handlers.onDone?.(data);
          else if (ev === 'error') handlers.onError?.(data.error);
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') handlers.onError?.(err.message);
    });
  return () => controller.abort();
}
