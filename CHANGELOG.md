# Changelog

All notable changes to Swaggernaut are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## 1.10.0

### Added
- **Application menu bar** (File · Edit · View · Tools · Help) replacing the scattered
  top-bar buttons. Classic behavior: click to open, hover to switch, Esc/click-out to close.
- **Named-profile sessions** — save multiple working setups (target URL, identities, history,
  pinned endpoints, focus tags) and switch between them. **Export / Open** a session as a `.json`
  file, **Edit** the active session JSON in place, quick-save with `⌘/Ctrl+S`. Existing saved state
  is migrated automatically into a "default" profile.
- **JWT toolkit** (all in-browser via Web Crypto — nothing leaves the machine):
  - **Sign / verify** with an HMAC secret (HS256/384/512).
  - **Brute-force** a weak secret from a local wordlist (paste or load a file).
  - **Claim & attack presets** (role=admin, admin=true, bump/remove exp, sub=1, alg=none,
    RS→HS alg-confusion, kid traversal).
  - **Apply token** — set as the active identity's bearer, or copy a ready `Authorization` header.
- **Split find & filter** in the sidebar — the text search now sits above a filter row: method
  chips, tag and security selects, and flag toggles (body / IDOR / deprecated / pinned), all
  combinable, with an active-filter count and one-click clear.
- **Tag UX** — inline **chip editor** with autocomplete (replaces the old prompt), **click a tag to
  filter**, color-coded tag dots, and a **Tag Manager** (View menu) to rename or delete a tag
  everywhere it is used. Right-click a tag chip to remove it from an endpoint.
- **Help** menu with a Keyboard Shortcuts reference and an About dialog.

## 1.9.1

### Changed
- **Density & button IA pass** (follow-up to the 1.9.0 redesign):
  - **Send** now sits on the method+URL line as the primary action. Attack, Send
    to Fuzzer, Send to Matrix, and Copy-as-code moved into a `⋯` overflow menu,
    removing the buttons that duplicated the Fuzzer/Matrix tabs.
  - Added **New / clear request** to the `⋯` menu.
  - **Find in response** collapses to a `⌕` icon in the response bar (reclaims a
    full row); click to reveal a slim search field.
  - Relabeled the cryptic topbar identities button (`IDS` → `Identities`) and
    dropped redundant micro-labels (TARGET / IDENTITY / ENDPOINTS).
  - Shortened the per-tab hint text to one line each; the request body editor now
    fills the column (no large empty void); tighter table rows, topbar, and
    panel padding for higher data density.

## 1.9.0

### Changed
- **Complete UI/UX redesign — "Light Technical / Swiss".** The entire interface
  was rebuilt from scratch: a paper-white surface, a single signal-red accent,
  hairline data grids, strong typographic hierarchy, and disciplined 8px spacing.
  New segmented tab nav, restyled sidebar/endpoint list, response viewer, modal
  "sheet" system, command palette, and toast. Markup (`public/index.html`) and
  styles (`public/styles.css`) were fully replaced; the 6-tab structure and all
  features/workflows are preserved. No backend or JS behavior changes.
- Accessibility: visible focus rings on all controls and `prefers-reduced-motion`
  support.

## Unreleased

### Changed
- **Tools menu organized into labeled groups** — the menu (now ~28 entries) is
  split into *Current request*, *Payloads & attack*, *Tokens & crypto*,
  *Encode & convert*, and *Recon & analysis* sections with headings, and the
  dropdown scrolls if it would exceed the viewport. No tools were removed.

### Added
- **More Quick Attack variants** — the one-click attack runner now also tries
  path-normalization ACL bypasses (`/.` trailing dot, `%2f` encoded slash,
  case-swapped path, leading double slash), a scheme downgrade
  (`X-Forwarded-Proto: http`), extra method-override headers, wildcard `Accept`,
  and a JSON→XML content-type swap. `lib/attacks.js` is now covered by a
  `node --test` suite (variant gating, path rewriting, header stripping).
- **Six more Fuzzer payload sets** — **LDAP Injection**, **XPath Injection**,
  **GraphQL Introspection**, **Open Redirect**, **Email Header Injection**, and
  **Format String / Edge Cases** — bringing the built-in sets to 20. All surface
  automatically in the Fuzzer dropdown and are covered by the `lib/payloads.js`
  integrity tests.
- **Injection Payloads cheat sheet expanded** — added **NoSQLi**, **XXE**,
  **CRLF / header**, and **Polyglot** categories (with `{{M}}` marker support for
  OOB exfil / canaries), keeping the client-side cheat sheet aligned with the
  Fuzzer's built-in sets.
- **Fuzzer payload sets expanded** — three new built-in sets: **SSTI** (template
  injection across Jinja2/Twig/SpEL/Razor), **XXE** (file read, SSRF, and
  out-of-band parameter-entity exfiltration), and **CRLF / Header Injection**.
  The **SQLi** set gains cross-engine time-based probes (MySQL/Postgres/Oracle)
  and comment/whitespace WAF-bypass variants. New sets appear automatically in
  the Fuzzer's payload-set dropdown. `lib/payloads.js` is now covered by a
  `node --test` suite (set integrity, de-duplication, `getSet` copy-safety,
  `numericRange` bounds/caps).
- **User-Agent Library** — under **Tools → User-Agent Library…**, a searchable
  set of representative User-Agent strings (desktop, mobile, bot/crawler, tools)
  for testing UA-based routing, cloaking, and access logic, with per-entry copy.
  Library is unit-tested via `node --test` (`public/js/useragent-core.js`).
- **Attack Headers** — under **Tools → Attack Headers…**, a searchable,
  categorized library of request headers useful in testing (IP spoofing,
  URL/path override, host-header & cache poisoning, scheme, auth-context, method
  override), each with a sample value, an explanation, and copy as a
  `Name: value` line for the Request tab or Match & Replace. Library is
  unit-tested via `node --test` (`public/js/attackhdr-core.js`).
- **IP Obfuscator** — under **Tools → IP Obfuscator…**, convert an IPv4 address
  into every equivalent encoding (decimal, octal, hex, dotted-hex/octal,
  IPv6-mapped, loopback shorthand) that bypasses naive SSRF host filters;
  click-to-copy. Pairs with **Redirect & SSRF Payloads**. Conversion is
  unit-tested via `node --test` (`public/js/ipobf-core.js`).
- **Wordlist Generator** — under **Tools → Wordlist Generator…**, build fuzzing
  lists from a numeric range (with step and zero-padding) or case/leet mutations
  of base words, then wrap each entry with a prefix/suffix and copy it into the
  Fuzzer or Content Discovery. Output is capped to keep ranges safe. Logic is
  unit-tested via `node --test` (`public/js/wordlist-core.js`).
- **Status Reference** — under **Tools → Status Reference…**, a searchable HTTP
  status-code table (by number, phrase, or keyword) where each entry carries a
  short pentest note — e.g. 403 → verb/header tampering, 500 → error-based
  injection, 502/504 → SSRF, 429 → rate-limit scoping. Logic is unit-tested via
  `node --test` (`public/js/status-core.js`).
- **WAF Fingerprint** — under **Tools → WAF Fingerprint…**, paste a response's
  headers (and optional body snippet) to detect common WAFs / CDNs / reverse
  proxies — Cloudflare, Akamai, AWS (CloudFront/ALB/WAF), Imperva, F5 BIG-IP,
  Sucuri, Fastly, Azure, ModSecurity, Barracuda, and more — from header and body
  signatures. Logic is unit-tested via `node --test` (`public/js/waf-core.js`).
- **Injection Payloads** — under **Tools → Injection Payloads…**, a categorized
  cheat sheet of test strings (XSS, SQLi, path traversal, SSTI, command
  injection) with per-payload copy. A marker field substitutes `{{M}}` with your
  OOB host or a unique reflection canary. Generation only — nothing is sent.
  Library is unit-tested via `node --test` (`public/js/payloads-lib-core.js`).
- **Body Converter** — under **Tools → Body Converter…**, paste a JSON object to
  re-encode the same data as `application/x-www-form-urlencoded`, a query
  string, and `multipart/form-data` (per-block copy) — for probing content-type
  confusion and parameter pollution. Nested values are JSON-encoded so they
  survive the round trip. Logic is unit-tested via `node --test`
  (`public/js/bodyconv-core.js`).
- **JSON Flattener** — under **Tools → JSON Flattener…**, paste a JSON response
  to flatten it into `dot.path[i]` → value leaf rows with each leaf's type, and
  auto-highlight keys that look sensitive (password, token, api_key, email, …).
  A **sensitive only** toggle and **Copy paths** make it quick to spot leaks and
  locate a value to extract in a Sequence step. Logic is unit-tested via
  `node --test` (`public/js/jsonflat-core.js`).
- **Redirect & SSRF Payloads** — under **Tools → Redirect & SSRF Payloads…**,
  generate classic open-redirect (scheme-relative, backslash, userinfo `@`,
  subdomain, encoded) and SSRF filter-bypass strings (loopback obfuscations in
  octal/decimal/hex, cloud metadata endpoints, `gopher://`/`dict://`/`file://`,
  and an OOB callback to your host) for an authorized test. Generation only —
  nothing is sent. Logic is unit-tested via `node --test`
  (`public/js/redirect-core.js`).
- **Entropy Analyzer** — under **Tools → Entropy Analyzer…**, paste a single
  token / API key / session ID to measure its Shannon entropy, observed
  character set, and an optimistic brute-force keyspace, with a weak / fair /
  good / strong verdict — a fast single-value check (use **Token Sequencer** for
  sampling many). Logic is unit-tested via `node --test`
  (`public/js/entropy-core.js`).
- **Param Analyzer** — under **Tools → Param Analyzer…**, paste a URL or query
  string to classify each parameter by the attack class its name/value suggests
  (open redirect, SSRF, path traversal, IDOR, auth/secret, injection,
  privilege), surfacing the most interesting params first so you know what to
  fuzz. Logic is unit-tested via `node --test` (`public/js/params-core.js`).
- **Timestamp Converter** — under **Tools → Timestamp Converter…**, enter a Unix
  epoch (seconds or milliseconds) or an ISO 8601 date to see every
  representation (Unix s/ms, ISO, UTC) plus a human-relative offset and an
  expired/future flag — handy for reading JWT `exp`/`iat` claims. A **Now**
  button inserts the current time. Logic is unit-tested via `node --test`
  (`public/js/timestamp-core.js`).
- **Hash Identifier** — under **Tools → Hash Identifier…**, paste a hash to
  guess likely algorithms from length, character set, and crypt prefix
  (MD5/NTLM, SHA-1/256/384/512, SHA-3, bcrypt, md5/sha256/sha512crypt, Argon2,
  LDAP {SSHA}, salted forms). Heuristic and fully client-side; logic is
  unit-tested via `node --test` (`public/js/hashid-core.js`).
- **Header Auditor** — under **Tools → Header Auditor…**, paste a raw HTTP
  response header block to audit it for missing or weak security headers
  (**CSP** incl. `unsafe-inline`/`unsafe-eval`, **HSTS** max-age, **X-Content-Type-Options**,
  **X-Frame-Options** / CSP `frame-ancestors`, **Referrer-Policy**), tech-stack
  disclosure (`Server`, `X-Powered-By`, …), and unsafe CORS (`Access-Control-Allow-Origin: *`,
  worse with `Allow-Credentials: true`). Parser/audit are unit-tested via
  `node --test` (`public/js/headers-core.js`).
- **Cookie Inspector** — under **Tools → Cookie Inspector…**, paste one or more
  `Set-Cookie` header values to parse each cookie and audit its security
  attributes, flagging missing **HttpOnly**, **Secure**, and **SameSite** (and
  warning on `SameSite=None`). Parser/audit are unit-tested via `node --test`
  (`public/js/cookie-core.js`).
- **Random Generator** — under **Tools → Random Generator…**, generate
  cryptographically-random values (UUID v4, random hex, URL-safe token, custom
  random string) for nonces, cache-busters, and fuzzing; each click appends a
  line, copy them all out. Uses the platform CSPRNG; unit-tested via
  `node --test` (`public/js/random-core.js`).
- **Auth Builder** — under **Tools → Auth Builder…**, construct an
  `Authorization` header value: **Basic** from a user/password (Base64-encoded
  in the browser) or **Bearer** from a token, then copy it into an identity.
  Unit-tested via `node --test` (`public/js/auth-core.js`).
- **Timing Analysis** — under **Tools → Timing Analysis…**, see per-endpoint
  response-time stats (count, min, average with a bar, max) aggregated from this
  session's history, sorted slowest first. Large gaps between similar endpoints
  can indicate a timing oracle (e.g. login slower for valid usernames).
  Aggregation is unit-tested via `node --test` (`public/js/timing-core.js`).
- **Traffic Search** — under **Edit → Search Traffic…**, grep every request and
  response captured this session (method, URL, headers, bodies) with a literal
  or regex query to surface tokens, emails, or stack traces anywhere in the
  session. Results show where each match landed. Pure client-side; engine is
  unit-tested via `node --test` (`public/js/search-core.js`).
- **Content Discovery** — under **Tools → Content Discovery…**, brute-force a
  built-in list of common paths (plus your own wordlist) off a base URL to find
  unspecced/shadow endpoints. Sends real GET requests as the active identity,
  classifies each outcome (found / protected / redirect / missing / error), and
  is capped at 500 requests behind a confirmation gate. Candidate building and
  classification are unit-tested via `node --test`
  (`public/js/discovery-core.js`).
- **Match & Replace** — under **Tools → Match & Replace…**, define session-scoped
  rewrite rules applied to requests sent from the Request tab before they leave:
  literal/regex replace on the URL or body, or set/remove a header (e.g. inject
  `X-Forwarded-For` on every send). Rules are saved per session profile. The
  transform is unit-tested via `node --test` (`public/js/matchreplace-core.js`).
- **Site Map** — under **View → Site Map…**, browse the loaded spec's endpoints
  as a URL-path tree (shared prefixes merged, per-branch operation counts) — a
  hierarchical lens complementary to the tag-grouped explorer. Click any
  operation to open it in the Request tab. Tree builder is unit-tested via
  `node --test` (`public/js/sitemap-core.js`).
- **Comparer** — under **Tools → Comparer…**, diff two pasted blobs (requests or
  responses) at line or word granularity via an LCS diff, with an
  added/removed/unchanged summary and colored output. Makes subtle differences
  between two responses (an extra field, a flipped flag) obvious. Pure
  client-side; diff engine is unit-tested via `node --test`
  (`public/js/comparer-core.js`).
- **Token Sequencer** — under **Tools → Token Sequencer…**, paste a sample of
  tokens (session IDs, CSRF, reset tokens) to estimate their randomness:
  sample/uniqueness counts, fixed vs. varying length, charset size, a
  per-character-position Shannon-entropy bar chart, total entropy in bits, and a
  graded verdict (predictable / weak / moderate / strong) that flags sequential
  tokens and duplicate collisions. Pure client-side; engine is unit-tested via
  `node --test` (`public/js/sequencer-core.js`).
- **CSRF PoC generator** — from **Request → ⋯ → Generate CSRF PoC…**, turn the
  current request into a self-submitting HTML page to test whether an endpoint
  is missing CSRF protection. Handles GET (query → form fields), form-urlencoded
  POST, and JSON POST (via the `text/plain` form trick), flags caveats (e.g. an
  `Authorization` header that a browser form can't set), and HTML-escapes every
  value. Copy or download the `.html`. Pure client-side; generator is
  unit-tested via `node --test` (`public/js/csrf-core.js`).

## 1.11.0

### Added
- **Decoder** — a new tab to encode, decode, smart-decode, and hash text
  entirely in the browser. Supports Base64 /
  Base64URL, URL, hex, HTML entities, and JWT decode, plus SHA-1/256/384/512
  hashing via Web Crypto. **Smart decode** auto-detects the encoding; `⇅` feeds
  the output back into the input for chained transforms; **From request** seeds
  the current request body/URL. Nothing is sent. The transform engine
  (`public/js/decoder-core.js`) is unit-tested via `node --test`.
- **Sequence Runner** — a new tab that chains requests into a multi-step flow.
  **Capture** a value from any response (a JSON body path like `data.id`, a
  response header, or the status) into a named variable, then reference it as
  `{{name}}` in any later step's URL, headers, or body (`{{baseUrl}}` is always
  available). Each step picks its own identity, and per-step **checks**
  (status/body/header `eq`/`ne`/`contains`/`exists`) flag failures, with an
  optional "stop on fail". This adds the missing primitive behind BOLA/IDOR
  setups, auth-token refresh, and any stateful flow. Runs sequentially through
  the existing proxy (no new backend surface), records each step to History, and
  exports results. Reach it from the tab bar or **Request → ⋯ → Send to
  Sequence**. Sequences are saved per session profile. Engine is unit-tested via
  `node --test` (`public/js/sequence-core.js`).
- **Expanded passive static analysis** — the Attack Surface tab now produces a
  severity-ranked report from loaded endpoints and saved human request logs:
  auth gaps, optional auth, IDOR/BOLA hints, risky params, mass-assignment
  fields, sensitive log data, shadow endpoints, server-error logs, and
  spec-quality drift. This view does not send or replay requests.
- **Built-in test harness** — added `npm test` using Node's native test runner
  for the static-analysis engine.
- **Request workspace polish** — request actions now live in the request header
  with a visible current-endpoint context bar.
- **Editable path params** — path params appear in the Params table and are
  substituted into `{tokens}` at send time, so changing `id` before Send affects
  the actual request URL.
- **Endpoint focus tags** — add multiple custom tags to endpoints, search by
  those tags, and keep pinned/tagged targets visible during triage.
- **History detail view** — inspect saved request and response headers/body from
  history without replaying; replay remains an explicit action.
- **Request/response syntax color** — JSON-style attribute/value highlighting in
  request and response bodies plus colored response headers.

### Changed
- **De-duplicated navigation** — the View menu no longer repeats the tab list
  (which had also drifted out of sync); the tab bar is the single source for
  switching panels. Tag Manager and Command Palette remain under View.

### Changed
- **Safer active testing defaults** — Quick Attacks, Fuzzer, Matrix, and Sweep
  now ask for confirmation before higher-risk runs; Fuzzer/Sweep default to
  lower concurrency and server-side caps limit accidental high-volume traffic.

## [1.8.2] — 2026-06-11

### Changed
- Removed the full-width tab-description row — the active tab's description now
  sits inline at the right of the tab bar (full text on hover), and the request
  summary line collapses when empty. Two fewer wasted rows.

## [1.8.1] — 2026-06-11

### Changed
- **Denser layout** — shorter top bar, tabs and request bar; tighter padding
  throughout so the UI wastes far less vertical space.
- **Removed duplicate cURL button** — the standalone *cURL* action was merged
  into the single **⧉ Copy** dialog (which already offers cURL / fetch / Python / HTTPie).

## [1.8.0] — 2026-06-11

### Added (find/navigation)
- **Command palette** (Ctrl/Cmd+K) — fuzzy-jump to any endpoint or run an action
  (send, → Fuzz/Matrix, attacks, load spec, switch tab) with keyboard nav.
- **Find in response** — a search box over the response body with match
  highlighting and a match count.
- **Result-table filters** — text filters added to the Attack Surface and Access
  Matrix tables (Fuzzer/Sweep already had them).
- **Pinned endpoints** — ★ any endpoint to keep it in a Pinned group at the top
  of the sidebar (persisted in localStorage).

## [1.7.0] — 2026-06-11

### Added (UX)
- **Per-tab descriptions** — a one-line explainer strip under the tab bar (and
  tooltips) says what each tab does, so the tabs are no longer indistinguishable.
- **Grouped top bar** — target/identity config and the tool buttons (Spec / cURL
  / JWT) are now visually grouped with icons, tooltips, and a divider.
- **Clearer endpoint find** — search field gains a ⌕ icon, a `/` shortcut hint,
  and a "path, method, tag" placeholder.

## [1.6.0] — 2026-06-11

### Changed
- **Titanium / Liquid-Glass UI** — frosted translucent surfaces (backdrop-blur),
  neutral metal tones, soft inner highlights, iOS-style blue accent and rounded
  geometry. Reverted the gold theme; kept high contrast for readability.

## [1.5.0] — 2026-06-11

### Added
- **Copy as code** — `</>` button on the request line generates the current
  request as `fetch`, Python `requests`, or HTTPie (alongside cURL) in a tabbed
  dialog, for reproducing findings outside Swaggernaut.

## [1.4.0] — 2026-06-11

### Changed
- **Dark-luxury UI redesign** — warm near-black palette with a champagne-gold
  accent, serif wordmark, layered panels with soft shadows, refined badges,
  jewel-tone status colours, gold focus rings, and a glass top bar — kept
  high-contrast for readability.

### Added (UX)
- **Cross-tab actions** — **→ Fuzz** / **→ Matrix** buttons push the current
  request straight into those tabs.
- **Keyboard shortcuts** — Ctrl/Cmd+Enter to send, `/` to focus the endpoint
  filter, Alt+1…8 to switch tabs, Esc to close dialogs.
- **Empty state** for the endpoint list when no spec is loaded.
- Unified in-app navigation through a single `goTab()` helper.

## [1.3.0] — 2026-06-11

### Added
- **Findings export** — CSV / Markdown / JSON export buttons on the Fuzzer,
  Auth Sweep, and Access Matrix result toolbars, with timestamped filenames.

## [1.2.0] — 2026-06-11

### Added
- **Response Analysis** — passive per-response checks: missing security headers
  (HSTS, CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors,
  Referrer-Policy), permissive CORS (`*`) and credentialed origin reflection
  (high), tech-disclosure banners, and weak cookie flags (HttpOnly/Secure/
  SameSite). Surfaced in an **Analysis** response subtab with a severity badge.

## [1.1.0] — 2026-06-11

### Added
- **Attack Surface / Recon tab** — static spec analysis: counts of unauthenticated,
  mutating+unauth, IDOR-candidate, mass-assignment-candidate, and deprecated
  operations, plus a prioritized target list that opens straight into the Request tab.
- **CLI** `--version` / `-v`, `update` self-update command, version shown in UI header and banner.

## [1.0.0] — 2026-06-11

Initial release.

### Added
- **Endpoint explorer** — parses OpenAPI 2.0 / 3.x, groups operations by tag,
  synthesizes example request bodies, flags operations with no security defined.
- **Request / Repeater** — schema-driven request builder over a raw `http`/`https`
  client with full header control (Host, Content-Length).
- **Identities** — named header sets for role-based access testing; `null` strips a header.
- **Fuzzer / Brute** — `§§`/`FUZZ` injection points, built-in payload sets, numeric
  IDOR range, custom wordlists, concurrency/delay, live SSE results, anomaly highlighting.
- **Access Matrix (BOLA/BFLA)** — replay a request across all identities and diff outcomes.
- **Quick Attacks** — one-click auth-strip / token / method / header bypass variants.
- **Auth Sweep** — fire every spec endpoint as each identity to map authorization coverage.
- **JWT Inspector** — client-side decode/tamper and `alg:none` forging.
- **cURL import/export**, **History**.
- **Dynamic spec loading** — CLI arg, URL, cwd auto-detect, or runtime UI (file/URL/paste).
- **CLI** — `--version`, `--help`, `--port`, `--host`, `update` (self-update via git pull).
