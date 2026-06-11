# Changelog

All notable changes to PenAPI are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
