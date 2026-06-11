# Repository Guidelines

## Project Structure & Module Organization

PenAPI is a zero-dependency Node.js application with a static browser UI. The main server entry point is `server.js`; it serves `public/` and exposes the local `/api/*` endpoints used by the UI. Reusable server modules live in `lib/`: `specParser.js` normalizes OpenAPI/Swagger specs, `httpClient.js` sends raw HTTP/HTTPS requests, `curl.js` handles cURL import/export, and `payloads.js` plus `attacks.js` power offensive testing helpers. Front-end ES modules live in `public/js/`, with `public/index.html` and `public/styles.css` holding the shell and styling.

## Build, Test, and Development Commands

- `npm start` or `node server.js`: run the workbench on `127.0.0.1:7331`.
- `node server.js ./openapi.json --port 8080`: start with an explicit spec and port.
- `SPEC=./openapi.json npm start`: load a spec from the environment.
- `node server.js --help`: inspect CLI options.
- `node server.js --version`: verify the package version.

There is no build step and no dependency install is required beyond Node.js `>=18`.

## Coding Style & Naming Conventions

Use CommonJS in server files and ES modules in `public/js/`, matching existing code. Keep two-space indentation, semicolons, `'use strict'` in server modules, and single quotes for strings unless interpolation is needed. Prefer small, focused functions and descriptive camelCase names. Keep UI state changes explicit and route shared logic into `lib/` or focused `public/js/*` modules instead of expanding `server.js` or `main.js` unnecessarily.

## Testing Guidelines

No automated test suite is currently defined in `package.json`. For changes, run targeted smoke checks: start the server, load a sample OpenAPI/Swagger spec, confirm the Explorer populates, send a harmless request, and exercise any affected tab such as Fuzzer, Matrix, History, or JWT. If adding tests, place them in a clear `test/` or `tests/` directory and add an `npm test` script.

## Commit & Pull Request Guidelines

Follow the existing Conventional Commit style, for example `feat: add endpoint filters`, `fix(ui): prevent empty matrix render`, or `refactor(ui): simplify request toolbar`. Pull requests should include a short behavior summary, manual test steps, linked issues when applicable, and screenshots or screen recordings for visible UI changes.

## Security & Configuration Tips

Use PenAPI only for authorized testing. Do not commit tokens, captured credentials, private specs, or target-specific secrets. Prefer environment variables such as `PORT`, `HOST`, and `SPEC` for local configuration. Validate any new input path, URL, header, or request-shaping feature at the server boundary.
