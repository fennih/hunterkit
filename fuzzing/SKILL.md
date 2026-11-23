---
name: fuzzing
description: "Web-focused fuzzing harness: content discovery, parameter name and value fuzzing, header and verb tampering, wordlist selection and target-derived dictionaries, response clustering and differential analysis to surface anomalies. Use when the focus is fuzzing a target or feeding anomalies to the payload skills. Not for exploit validation of a known bug (use the class-specific skill) or infrastructure/binary fuzzing."
---

# Web Fuzzing (Discovery Harness)

## When to use

- "Fuzz X", "find hidden endpoints/params on X", "brute-force the API surface of X"
- Discovery engine: produces *candidate anomalies*; the payload skills (`xss`, `sqli`, ...) turn anomalies into findings

## When NOT to use

- Targeted testing of one endpoint you already know (go straight to the class skill)
- Binary/infrastructure fuzzing (AFL etc. — different world)
- Already-found bug validation (`sqli` etc. own their confirmation)

## Inputs

- **Target**: base URL(s), ideally the recon profile
- **Budget**: request ceiling per phase (default: dirs 5k, params 500/endpoint, values 200/param — ask for more if needed)

## Rationalizations to reject

- "404s are useless" — diff your 404s. Custom 404s that differ in size/words/redirects often hide real endpoints behind soft-404 filters.
- "Ffuf found 500 responses, jackpot" — 500s from a wordlist run are *anomalies*, not findings. Reproduce each interesting one manually with a clean baseline before passing it anywhere.
- "The response is big, it must be real" — calibrate first with known-bogus words; without a calibrated filter your results are noise.

## Methodology

### 1. Calibrate (always first)
- Request a guaranteed-bogus path/param (`/nonexistent-<rand>`, `?bbnonexistent=1`). Record status, size, words, lines, and any redirect target. This is the baseline for filtering.
- Identify the soft-404 shape (e.g. SPA: everything 200 with the same index.html size; API: everything 404 JSON with constant size). Choose matchers/filters accordingly (`-fc`, `-fs`, `-fw`, `-mc`).

### 2. Wordlist selection
- Prefer target-derived over generic: harvest words from the app's JS (routes, strings), API docs (swagger paths/params), error messages, `robots.txt`/`sitemap.xml`, and the response bodies themselves.
- Generic fallback (SecLists or installed wordlists): `Discovery/Web-Content` for dirs, `burp-parameter-names` for params, `api/objects` for API keys/values. Build a small custom list per target as you learn its naming style (`camelCase`? `snake_case`? `id` vs `uuid`?).
- If no wordlists installed: derive from the app (`grep -oE` on JS for path-like strings, `jq` on swagger) before falling back to a built-in common list.

### 3. Content discovery
- `ffuf -u https://t/FUZZ -w wordlist` (or curl loop fallback): filter with the calibration baseline. Then recurse on interesting dirs (`-recursion -recursion-depth 2`, only on 200/301/401 parents).
- Extension fuzzing where relevant: `FUZZ.php`, `.aspx`, `.jsp`, `.bak`, `.old`, `.txt`, `.zip` — backups and old versions (cross-report to `info-leak`).
- API surface: version fuzzing (`/v1..v9`, `/api/v1..9`), `/api/FUZZ` with object nouns, GraphQL discovery (`graphql` owns the deep pass).
- Verb fuzzing on discovered paths: `OPTIONS` first (Allow header), then unallowed verbs (PUT/PATCH/DELETE) — misrouted verbs are logic bugs (`business-logic` leads).

### 4. Parameter fuzzing
- **Name discovery**: `ffuf` on `?FUZZ=test` (and in bodies: JSON key fuzzing via a small script or ffuf `POST` mode). Filter on non-baseline responses. `arjun` if installed.
- **Hidden/undocumented params**: from swagger diffs (fields in schema not used by UI), from JS (params in fetch calls), from other API versions.
- **Value fuzzing**: type abuse (string where int, negative, huge, empty, null, arrays, unicode), enum violation (role=admin), boundary values. Anomalies here feed `access-control` and `business-logic`.

### 5. Header fuzzing
- Injected headers on all requests: `X-Forwarded-For`, `X-Original-URL`/`X-Rewrite-URL` (bypass patterns), `X-HTTP-Method-Override`, debug headers (`X-Debug: 1`, `X-Env`, `X-Cache`), `X-Forwarded-Host` (cache/host poison leads → `request-smuggling`/`open-redirect`).
- Diff responses per header vs baseline.

### 6. Differential analysis (the core discipline)
For each fuzz batch:
- Cluster responses (status, size-band, words, lines, time-band). Use `ffuf -of json` + `jq`/python for clustering if volumes are high.
- Outliers = candidates. For each candidate, manually re-request: baseline (without the fuzzed value) vs candidate. Confirm the difference is stable (2 runs), then classify:
  - Error/stack trace → `info-leak`
  - Auth bypass / different data → `access-control`
  - Different user's data → `access-control` (IDOR)
  - Template/SQL error → `ssti` / `sqli`
  - Delay → blind sink for `sqli`/`cmd-injection` (they own time-based proof)
  - Redirect → `open-redirect`
  - Nothing reproducible → drop it, note in coverage.

### 7. Feed-forward and logging
- Write the candidate table to `recon/<target>/fuzz-anomalies.md`: `endpoint | fuzz input | observation | diff evidence | routed to`.
- The payload skills consume these with their own discipline — this skill never claims a finding, only anomalies with clean evidence.

## Rate and safety

- Default `ffuf -t 20 -rate 50` (or `-p 0.02`), tune down on fragile targets. Never hammer auth or payment endpoints.
- Mutating verbs (PUT/DELETE/POST) on unknown endpoints: one request per candidate max, on disposable resources only.

## Reporting

No findings file of its own — output is `recon/<target>/fuzz-anomalies.md` + updated recommendations in the profile. Findings emerge in the class skills.

## Focus discipline

This is the discovery harness: when an anomaly maps to a class, delegate to the class skill and move on. Don't start crafting XSS/SQLi payloads here.
