# Changelog

All notable changes to PenAPI are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [1.6.0] — 2026-06-11

### Changed
- **Titanium / Liquid-Glass UI** — frosted translucent surfaces (backdrop-blur),
  neutral metal tones, soft inner highlights, iOS-style blue accent and rounded
  geometry. Reverted the gold theme; kept high contrast for readability.

## [1.5.0] — 2026-06-11

### Added
- **Copy as code** — `</>` button on the request line generates the current
  request as `fetch`, Python `requests`, or HTTPie (alongside cURL) in a tabbed
  dialog, for reproducing findings outside PenAPI.

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
