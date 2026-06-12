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

### Added
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
