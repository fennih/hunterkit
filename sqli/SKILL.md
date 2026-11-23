---
name: sqli
description: "Focused hunt for SQL injection: error-based, boolean-based, time-based, and out-of-band, across URL params, JSON/XML bodies, headers, and GraphQL arguments. Use when the focus is SQLi on a web target. Not for NoSQL injection (report as variant), SSTI (use ssti), or blind guessing without response diffs."
---

# SQL Injection

## When to use

- "Hunt SQLi on X", "test these params for SQLi"
- OWASP coverage: A03, CWE-89

## When NOT to use

- Template engines (use `ssti`), OS commands (use `cmd-injection`)

## Inputs

- **Target** + params list; ideally a known-good baseline request per endpoint

## Rationalizations to reject

- "Response changed, so it's SQLi" — a changed response is a lead. SQLi is proven by a controlled differential (boolean pair) or a database-level effect (error, delay, OOB), not by generic diffs.
- "sqlmap said so" — verify the finding manually with one request pair before reporting; tools report blind false positives.
- "Sleep(5) worked once" — repeat once; network jitter isn't SQLi. Two consecutive controlled delays with matching baseline = proven.

## Methodology

### 1. Injection point enumeration
Every context: GET/POST params, JSON values (and keys!), XML, headers (Cookie, X-Forwarded-For, UA, Referer, sorting params like `?order=name`), GraphQL arguments, path segments. Sort/order/filter params are top candidates.

### 2. Error-based first (cheapest proof)
- `'` `"` `` ` `` `\` alone; then with syntax payloads: `'-- -`, `"))-- -`, `'+AND+'1'='1`.
- Read the error carefully: DB vendor + syntax position. A driver error in the response is already a finding candidate — confirm with one clean reproduction.

### 3. Boolean-based
- Pair payloads: `AND 1=1` vs `AND 1=2` (adapted to context: quote, paren, comment terminator). Diff full responses (hash, not just size). One true-pair = confirmed.

### 4. Time-based (only when blind)
- Single short delay probe (`SLEEP(2)`/`WAITFOR DELAY '0:0:2'`/`pg_sleep(2)` per vendor). Compare against baseline timing. Max 2 repeats. Shared infra — keep it minimal.
- Prefer OOB over time when a canary channel exists (DNS/HTTP callback with data in subdomain: `||(SELECT ...)||.canary.com` style) — cleaner proof, no delay impact.

### 5. Tool confirmation (optional, scoped)
If `sqlmap` is installed, confirm a single endpoint: `sqlmap -r request.txt --risk=1 --level=2 --batch`. Never point sqlmap site-wide. Its findings still need the manual pair above for the report.

### 6. Vendors and context quirks
- MySQL: `` ` `` backticks, `#` comments; Postgres: `::` casts, `$$` dollar quoting; MSSQL: `WAITFOR`, stacked queries common; SQLite: limited functions, `||` concat; Oracle: `FROM dual`.
- JSON: `"1'"` string breakouts; numeric JSON: `1 AND 1=1` without quotes.
- Second-order: input stored now, executed in a later query (reports/exports) — note as leads if suspected.

## Reporting

`findings/sqli-<date>.md` + coverage table `endpoint | param | context | technique | proven?`. Severity by impact: extracted data / auth bypass = high/critical; blind confirmed = high.

## Focus discipline

NoSQL/Mongo injection found → report in the same file but tag `[NoSQL variant]`. OS command via DB functions → lead for `cmd-injection`.
