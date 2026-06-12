# Swaggernaut

**Version 1.11.0** · MIT · Node >= 18

A Swagger/Scalar-style API explorer built for **offensive security testing**.
Point it at any OpenAPI/Swagger spec and every operation becomes a ready-to-fire
request — then layer on a repeater, fuzzer/brute-forcer, access-control matrix,
a sequence runner that chains requests by capturing response values into later
steps, identity switching, tagged endpoint triage, guarded bypass checks, a JWT
tamperer, and cURL import/export.

Zero npm dependencies — pure Node plus a static front end. `swaggernaut spec.json` and go.

> **For authorized testing only.** Swaggernaut sends whatever you tell it to from the
> host it runs on. Use it only against systems you have explicit permission to
> test. The maintainers are not responsible for misuse.

## Install

Install from GitHub source:

```bash
cd ~
git clone https://github.com/Thanarak-q/Swaggernaut.git
cd Swaggernaut
# put a launcher on your PATH so `swaggernaut` works anywhere
mkdir -p ~/.local/bin
printf '#!/usr/bin/env bash\nexec node "%s/server.js" "$@"\n' "$PWD" > ~/.local/bin/swaggernaut
chmod +x ~/.local/bin/swaggernaut
export PATH="$HOME/.local/bin:$PATH"
hash -r 2>/dev/null || true
swaggernaut --version
```

If GitHub asks for a username when cloning, the repo is private or your GitHub
session does not have access. Use SSH instead if your key is configured:

```bash
cd ~
git clone git@github.com:Thanarak-q/Swaggernaut.git
```

Requires Node.js >= 18 (uses the built-in global `fetch`). No npm install is
required. If `swaggernaut` is not found in a new terminal, add
`export PATH="$HOME/.local/bin:$PATH"` to your shell profile.

## Update

If you installed from the GitHub source checkout:

```bash
cd ~/Swaggernaut
git pull --ff-only
hash -r 2>/dev/null || true
swaggernaut --version
```

If you kept the launcher from the install step, it keeps pointing at the same
checkout after the pull.

## Delete / Uninstall

Remove the launcher, then remove the source checkout:

```bash
cd ~
rm -f ~/.local/bin/swaggernaut
rm -rf ~/Swaggernaut
hash -r 2>/dev/null || true
```

Run delete commands from outside the checkout so your shell is not left inside a
removed directory.

## Run

Point it at **any** OpenAPI/Swagger spec:

```bash
node server.js ./swagger.json                       # explicit file
node server.js https://target.example/v3/api-docs   # fetch from a URL
node server.js ./openapi.json --port 8080           # options
node server.js                                      # auto-detect swagger.json/openapi.json in cwd
```

Then open **http://127.0.0.1:7331**. You can also load or switch specs at
runtime from the **Load Spec** button (URL / file / paste) — no restart needed.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `Ctrl/Cmd + K` | Open the command palette (jump to endpoint / action) |
| `Ctrl/Cmd + Enter` | Send the current request (from anywhere) |
| `/` | Focus the endpoint filter |
| `Alt + 1…8` | Jump to a tab |
| `Esc` | Close any open dialog |

Use **Fuzz** / **Matrix** in the request header to push the current request
straight into the Fuzzer or Access Matrix.

| Source | How |
|---|---|
| CLI argument | `swaggernaut <file-or-url>` |
| Current directory | run `swaggernaut` with no args; finds `swagger.json` / `openapi.json` |
| Environment | `SPEC=/path/to/spec.json swaggernaut` |
| Runtime (UI) | **Load Spec** → URL, file upload, or paste |

The spec is parsed **server-side**; file contents never leave the box beyond
what the UI renders.

## Features

| Feature | What it's for |
|---|---|
| **Endpoint explorer** | Operations grouped by tag, with method, summary, generated example body, and a flag when an operation has **no security defined**. Add custom focus tags with `#`, pin endpoints with ★, and search by either built-in or custom tags. |
| **Attack Surface / Recon** | Passive static analysis of loaded endpoints and saved human request logs. Flags auth gaps, optional auth, IDOR/BOLA hints, risky params, mass-assignment fields, sensitive data seen in logs, spec-quality drift, and shadow endpoints without sending any request. |
| **Request / Repeater** | Auto-fills path/query/header params and a schema-derived JSON body. Path params stay editable in the Params table and are substituted into `{tokens}` at send time. Raw `http`/`https` client gives full header control (including `Host`, `Content-Length`). |
| **Identities** | Named header sets (Admin / User / Unauth …). Switch the active identity to send every request as that role. Set a header value to `null` to *strip* it. |
| **Fuzzer / Brute** | Mark injection points with `§§` (wrap a value: `§admin§`) or the keyword `FUZZ`. Built-in payload sets (SQLi, XSS, traversal, cmdi, SSRF, NoSQLi, LFI, usernames, passwords, auth-bypass, host-header), a numeric range for IDOR enumeration, and custom wordlists. Concurrency + delay, live streaming, sortable results, anomaly highlighting. Risky runs require confirmation and server-side caps limit accidental floods. |
| **Access Matrix (BOLA/BFLA)** | Replay one request as every identity and diff outcomes. Low-priv/unauth identity getting `2xx` is flagged. Write-method replay requires confirmation. |
| **Sequence Runner** | Chain requests into a multi-step flow. **Capture** a value from any response — a JSON body path (`data.id`), a response header, or the status — into a named variable, then reference it as `{{name}}` in any later step's URL, headers, or body (`{{baseUrl}}` is always available). Each step picks its own identity, and per-step **checks** (`eq`/`ne`/`contains`/`exists` on status/body/header) flag failures with optional stop-on-fail. Powers BOLA/IDOR setups, auth-token refresh, and stateful flows. Runs sequentially through the proxy, records each step to History, and exports results. Add a step from **Request → ⋯ → Send to Sequence**; sequences persist per session profile. |
| **Quick Attacks** | Runs mutation variants — no-auth, empty/malformed bearer, verb swap, `X-HTTP-Method-Override`, `X-Original-URL`, spoofed `X-Forwarded-*`, trailing-slash, content-type confusion — after confirmation, flagging any that still succeed. |
| **Auth Sweep** | Fires every spec endpoint as each identity to map authorization coverage. Every sweep shows an estimated request count and requires confirmation; write verbs are explicitly warned. |
| **JWT Inspector** | Decode/edit a token client-side; shows alg, `exp`, claims; forge an `alg:none` / unsigned token to test signature-verification flaws. |
| **Decoder** | Encode, decode, smart-decode, and hash text entirely client-side — Base64 / Base64URL, URL, hex, HTML entities, JWT decode, and SHA-1/256/384/512 hashing. **Smart decode** auto-detects the encoding; `⇅` chains the output back into the input; **From request** seeds the current body/URL. |
| **CSRF PoC generator** | From **Request → ⋯ → Generate CSRF PoC…**, build a self-submitting HTML page from the current request to test for missing CSRF protection. Handles GET, form-urlencoded, and JSON bodies (via the `text/plain` trick), flags caveats like a non-cookie `Authorization` header, and HTML-escapes all values. Copy or download the `.html`. |
| **Token Sequencer** | From **Tools → Token Sequencer…**, paste a sample of tokens to estimate randomness — uniqueness, length, charset, per-position Shannon entropy (bar chart), total bits, and a graded verdict that flags sequential or colliding tokens. Pure client-side. |
| **Comparer** | From **Tools → Comparer…**, diff two pasted blobs (requests or responses) line- or word-by-word with an added/removed summary and colored output. Pure client-side. |
| **Site Map** | From **View → Site Map…**, browse endpoints as a URL-path tree (shared prefixes merged, per-branch counts); click an operation to open it in the Request tab. |
| **Match & Replace** | From **Tools → Match & Replace…**, define session-scoped rewrite rules applied to requests sent from the Request tab — literal/regex replace on URL or body, or set/remove a header (e.g. inject `X-Forwarded-For`). Saved per profile. |
| **Content Discovery** | From **Tools → Content Discovery…**, brute-force common and custom paths off a base URL to surface unspecced/shadow endpoints. Uses the active identity, classifies outcomes (found / protected / redirect / missing), and is capped at 500 requests with a confirmation gate. |
| **Traffic Search** | From **Edit → Search Traffic…**, grep all captured requests and responses (method, URL, headers, bodies) with a literal or regex query; results show which field matched. Pure client-side. |
| **Timing Analysis** | From **Tools → Timing Analysis…**, per-endpoint response-time stats (count, min, avg, max) from session history, sorted slowest first — gaps between similar endpoints can reveal timing oracles. |
| **Auth Builder** | From **Tools → Auth Builder…**, construct an `Authorization` header — **Basic** from user/password or **Bearer** from a token — and copy it into an identity. Pure client-side. |
| **cURL import / Copy as code** | Paste a `curl` from your browser DevTools or an intercepting proxy to populate the Request tab; copy any request back out as `curl`, `fetch`, Python `requests`, or HTTPie. |
| **Response Analysis** | Each response is passively checked for missing security headers (HSTS/CSP/XFO/etc.), permissive or credentialed CORS, tech-disclosure banners, and weak cookie flags — shown in the **Analysis** subtab with severity. |
| **Findings export** | Export fuzzer, sweep, and matrix results to CSV / Markdown / JSON straight from the results toolbar — drop them into a report. |
| **Find & navigate** | Command palette (Ctrl/Cmd+K) to jump to any endpoint or action; find-in-response with highlighting; filterable result tables; ★ pinned endpoints and custom tags. |
| **History** | Every sent request is persisted in `localStorage` with request/response detail, a safe view dialog, and explicit replay. |

## Session & Safety

Swaggernaut persists local working state in the browser: target base URL, identities,
request history, pinned endpoints, and custom endpoint tags. It does not yet
export/import full session files; clearing browser storage clears this state.

Actions that send multiple real requests now have guardrails:

- **Quick Attacks** confirms before sending mutation variants.
- **Fuzzer** confirms high-volume or write-method runs, defaults to concurrency
  `3`, and the server rejects runs over 500 payloads.
- **Access Matrix** confirms before replaying write methods as multiple
  identities.
- **Sequence Runner** confirms before a run that contains any write-method
  step, and sends steps strictly one at a time.
- **Auth Sweep** confirms every run with estimated request count and caps
  concurrency to `10`.

The **Attack Surface / Recon** analysis is passive. It reads the loaded spec plus
browser-local request history and never sends, replays, fuzzes, or probes
anything on its own.

## Examples

- **IDOR sweep** — `GET /api/v1/items/§1§`, ID range `1`–`500`, Start. Rows whose length differs from the baseline are flagged.
- **Login brute** — `POST /auth/login` body `{"user":"admin","pass":"§x§"}`, pick the *Common Passwords* set, watch for the status/length anomaly.
- **SQLi probe** — mark a query value `§1§`, choose *SQL Injection*; time-based payloads surface as outliers in the Time column.
- **BOLA via chained flow** — in the **Sequence** tab: step 1 `POST /api/orders` as *Admin*, capture `data.id` → `orderId`; step 2 `GET /api/orders/{{orderId}}` as *User* with a check `status eq 403`. A `2xx` on step 2 flags broken object-level auth.

## Scope

Out of scope by design: an intercepting MITM proxy and an out-of-band
interaction service — both need infrastructure beyond a zero-dependency local
tool. Swaggernaut stays spec-driven and self-contained.

## Layout

```
server.js              # zero-dep HTTP server: static + /api/*
lib/specParser.js      # OpenAPI 2/3 -> normalized endpoints + example bodies
lib/httpClient.js      # raw http/https request engine (full header control)
lib/curl.js            # curl parse + serialize
lib/payloads.js        # built-in payload sets + numeric range
lib/attacks.js         # quick-attack variant generator
public/                # front end (ES modules, no build step)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
