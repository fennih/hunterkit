---
name: info-leak
description: "Focused hunt for information disclosure and privacy exposure: exposed secrets, debug endpoints, backup files, source maps, API docs, PII leakage, and privacy review of PRs or API responses. Use when the focus is secrets, info leak, sensitive data exposure, or reviewing a PR/API for privacy issues. Not for known CVE scanning (use known-cves)."
---

# Information Disclosure & Privacy

## When to use

- "Hunt info leak / secrets on X", "check for exposed files on X", "review this PR for privacy", "does X leak PII"
- OWASP coverage: A01/A02 (cryptographic failures, sensitive data), API Top 10 API3 (Excessive Data Exposure)
- Two modes: **target scan** (black/grey box) and **PR review** (grey box)

## When NOT to use

- Fingerprinting for CVE matching (use `known-cves`)
- Auth flow bugs (use `ato`)

## Mode A — Target scan

### 1. Common file discovery
With `ffuf` on each live host (use `recon` list): `/.env`, `/.git/config`, `/.git/HEAD`, `/backup.zip`, `/db.sql`, `/.DS_Store`, `/server-status`, `/phpinfo.php`, `/.svn/entries`, `/.htaccess`, `/web.config`, `/composer.json`, `/package.json`, `/debug`, `/trace`, `/actuator`, `/console`, `/admin/config`, `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`.
- `.git` found: if listing works, extract with git tools (`git-dumper` if installed, else fetch `.git/objects` manually); read-only, don't modify.
- `.env`/config found: record variable NAMES in the report; do not print full secret values (mask them), and never use them without asking the user.

### 2. API and docs exposure
`/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql` (run introspection), `/v1/../v3` versioned APIs, old API versions still live with weaker auth.

### 3. Source maps and JS
`.map` files live? Reconstruct source; grep for internal hostnames, keys, comments, TODOs, feature flags, internal API routes.

### 4. Response hygiene
- Verbose headers: `Server`, `X-Powered-By`, stack traces in 4xx/5xx (trigger safe errors: malformed JSON, weird types), `Via`, internal IPs in headers.
- Cookies: missing `Secure`/`HttpOnly`/`SameSite`, session tokens in URLs.
- Error messages: SQL/driver errors, path disclosure, framework version.

### 5. Excessive data exposure (API)
Authenticated as a normal user: GET every object endpoint. Diff what the API returns vs what the UI shows. Extra fields: hash of password, internal flags, other users' minimal data, emails, tokens. Report the exact fields leaked.

### 6. PII / privacy signals
- PII in URLs (emails/names as query params → logs/referrers), PII in client-side storage unencrypted, tracking of sensitive categories, data returned for other users.
- Exports (CSV/PDF): do they include more than the user's own data?

## Mode B — PR / privacy review

Given a diff or PR:
1. Enumerate personal data touched: which fields, where stored, where logged, where sent.
2. Check: PII in logs, PII in analytics/tracking calls, new data flows to third parties, consent/retention implications, PII in URLs or client storage, new telemetry events carrying user content.
3. Check secrets: any hardcoded keys/tokens in the diff (`grep -iE 'api[_-]?key|secret|token|password|bearer|AKIA'`).
4. Report as review findings: `file:line`, issue, why it matters (GDPR-style impact: purpose, minimization, retention), suggested fix. No code changes unless asked.

## Reporting

Write findings to `findings/info-leak-<date>.md`:

```
### [SEVERITY] Title
- Location: URL / file:line
- CWE: CWE-200 / CWE-540 / CWE-798
- Evidence: request + response snippet (mask secrets and PII values in the report)
- Reproduction: numbered steps
- Impact: what an attacker learns or gains
```

Live secrets (DB creds, API keys with write access) = high. PII exposure scale decides: few users low/medium, cross-user = high.

## Focus discipline

Fingerprint versions for CVEs → lead for `known-cves`. Login-related exposure → lead for `ato`.
