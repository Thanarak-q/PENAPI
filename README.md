# PENAPI

**Version 1.5.0** · MIT · Node ≥ 18

A Swagger/Scalar-style API explorer built for **offensive security testing**.
Point it at any OpenAPI/Swagger spec and every operation becomes a ready-to-fire
request — then layer on a repeater, fuzzer/brute-forcer, access-control matrix,
identity switching, one-click bypass checks, a JWT tamperer, and cURL
import/export.

Zero npm dependencies — pure Node plus a static front end. `penapi spec.json` and go.

> **For authorized testing only.** PenAPI sends whatever you tell it to from the
> host it runs on. Use it only against systems you have explicit permission to
> test. The maintainers are not responsible for misuse.

## Install

```bash
git clone https://github.com/Thanarak-q/PENAPI.git
cd PENAPI
# put a launcher on your PATH so `penapi` works anywhere
printf '#!/usr/bin/env bash\nexec node "%s/server.js" "$@"\n' "$PWD" > ~/.local/bin/penapi
chmod +x ~/.local/bin/penapi
penapi --version
```

Requires Node.js >= 18 (uses the built-in global `fetch`). No other dependencies.

## Updating

```bash
penapi update      # runs `git pull` in the install dir, then reports the new version
# or manually:
cd /path/to/PENAPI && git pull
```

Check your version any time with `penapi --version` (also shown in the UI header).

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
| `Ctrl/Cmd + Enter` | Send the current request (from anywhere) |
| `/` | Focus the endpoint filter |
| `Alt + 1…8` | Jump to a tab |
| `Esc` | Close any open dialog |

Use **→ Fuzz** / **→ Matrix** on the request line to push the current request
straight into the Fuzzer or Access Matrix.

| Source | How |
|---|---|
| CLI argument | `penapi <file-or-url>` |
| Current directory | run `penapi` with no args; finds `swagger.json` / `openapi.json` |
| Environment | `SPEC=/path/to/spec.json penapi` |
| Runtime (UI) | **Load Spec** → URL, file upload, or paste |

The spec is parsed **server-side**; file contents never leave the box beyond
what the UI renders.

## Features

| Feature | What it's for |
|---|---|
| **Endpoint explorer** | Operations grouped by tag, with method, summary, generated example body, and a flag when an operation has **no security defined**. |
| **Attack Surface / Recon** | Static analysis of the spec: counts of unauthenticated ops, mutating+unauth ops, IDOR candidates (path ids), mass-assignment candidates (request bodies), deprecated ops, and a sortable, prioritized target list. |
| **Request / Repeater** | Auto-fills path/query/header params and a schema-derived JSON body. Raw `http`/`https` client gives full header control (including `Host`, `Content-Length`). |
| **Identities** | Named header sets (Admin / User / Unauth …). Switch the active identity to send every request as that role. Set a header value to `null` to *strip* it. |
| **Fuzzer / Brute** | Mark injection points with `§§` (wrap a value: `§admin§`) or the keyword `FUZZ`. Built-in payload sets (SQLi, XSS, traversal, cmdi, SSRF, NoSQLi, LFI, usernames, passwords, auth-bypass, host-header), a numeric range for IDOR enumeration, and custom wordlists. Concurrency + delay, live streaming, sortable results, anomaly highlighting. |
| **Access Matrix (BOLA/BFLA)** | Replay one request as every identity and diff outcomes. Low-priv/unauth identity getting `2xx` is flagged. |
| **Quick Attacks** | One click fires mutation variants — no-auth, empty/malformed bearer, verb swap, `X-HTTP-Method-Override`, `X-Original-URL`, spoofed `X-Forwarded-*`, trailing-slash, content-type confusion — flagging any that still succeed. |
| **Auth Sweep** | Fires every spec endpoint as each identity to map authorization coverage. Safe idempotent methods by default; write verbs require a confirm. |
| **JWT Inspector** | Decode/edit a token client-side; shows alg, `exp`, claims; forge an `alg:none` / unsigned token to test signature-verification flaws. |
| **cURL import / Copy as code** | Paste a `curl` from Burp/DevTools to populate the Request tab; copy any request back out as `curl`, `fetch`, Python `requests`, or HTTPie. |
| **Response Analysis** | Each response is passively checked for missing security headers (HSTS/CSP/XFO/etc.), permissive or credentialed CORS, tech-disclosure banners, and weak cookie flags — shown in the **Analysis** subtab with severity. |
| **Findings export** | Export fuzzer, sweep, and matrix results to CSV / Markdown / JSON straight from the results toolbar — drop them into a report. |
| **History** | Every sent request, replayable, persisted in `localStorage`. |

## Examples

- **IDOR sweep** — `GET /api/v1/items/§1§`, ID range `1`–`500`, Start. Rows whose length differs from the baseline are flagged.
- **Login brute** — `POST /auth/login` body `{"user":"admin","pass":"§x§"}`, pick the *Common Passwords* set, watch for the status/length anomaly.
- **SQLi probe** — mark a query value `§1§`, choose *SQL Injection*; time-based payloads surface as outliers in the Time column.

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
