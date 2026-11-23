---
name: ssrf
description: "Focused hunt for Server-Side Request Forgery on a web target: URL parameters, webhooks, importers, PDF/image generators, redirects, and cloud metadata access. Use when the focus is SSRF or making the server fetch attacker-controlled URLs. Not for open redirects alone (report as leads) or general injection."
---

# SSRF (Server-Side Request Forgery)

## When to use

- "Hunt SSRF on X", "test webhook/import/export features of X", "make the server fetch my URL"
- OWASP coverage: A10 SSRF (and SFR in API Top 10)

## When NOT to use

- Pure open redirect (test here only as an SSRF vector, report separately as info/lead)
- LLM fetch tools (use `llm-security`, which covers indirect SSRF via agents)

## Inputs

- **Target**: endpoints accepting URLs or filenames (from `recon` profile: `[redirect]`, webhook, import, export features)
- **Canary**: an outbound-observable endpoint you control (interactsh if installed, a public request-bin, or a DNS name you monitor)

## Ground rules

- Use only canary/callback targets you control for callbacks. Never point SSRF at third-party systems.
- Cloud metadata probes are allowed but read-only, and prefer non-destructive paths.
- A finding needs server-side proof: callback received, or metadata/unique content in the response.

## Methodology

### 1. Enumerate URL sinks
Features that fetch: URL preview/unsplash-style embeds, webhooks, avatar-from-URL, import from URL (CSV/iCal), PDF/print of a URL, screenshot generators, RSS feed readers, SSO/OAuth `redirect_uri` (server-side fetch), "connect your site" verifications, file-from-URL uploads.

### 2. Basic canary
Submit your canary URL in each sink. Confirm a hit is from the server (UA header, source IP is the target's infra, not your browser). Record the full request the server made — headers it sent are valuable (some indicate internal service calls).

### 3. Scheme and target control
- Schemes: `file:///etc/passwd`, `file:///proc/self/environ` (creds!), `gopher://` (only if confirmed supported; gopher is powerful, use sparingly), `dict://`, `ftp://`, `data:`.
- Internal hosts: `http://localhost`, `127.0.0.1`, `169.254.169.254` (AWS/GCP metadata), `metadata.google.internal`, private ranges if scope explicitly allows the internal network.
- AWS IMDSv2 check: try `PUT /latest/api/token` (no token header) — if it works, IMDSv1 may still be enabled.

### 4. Filter bypasses
If the target validates the URL:
- DNS rebinding / TOCTOU (hostname resolves public then internal — note as advanced lead if simple bypasses fail).
- Redirect-based: allowed URL that 302s to internal.
- Encodings: decimal/octal/hex IPs (`http://2130706433/`), `0.0.0.0`, `127.1`, `localtest.me`, `[::1]`, `x.nip.io`.
- URL parser confusion: `http://allowed.com#@internal/`, `http://allowed.com\@internal/`, backslash tricks, `http://internal/#allowed.com` where the fetch follows the fragment differently.

### 5. Blind SSRF
No response reflection? Use: DNS canary, unique path per sink (`/ssrf-webhook`, `/ssrf-avatar`) to map which feature fired, response-time diffs between reachable/unreachable internal ports (small request counts).

### 6. Cloud metadata exploitation (when reachable)
- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — report role names + access key presence; do NOT exfiltrate or use the keys beyond listing unless the user asked. Never hardcode or store found keys in the report; reference them.
- GCP: `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google`.
- Report exposed metadata endpoints as high even without using the credentials.

## Reporting

Write findings to `findings/ssrf-<date>.md`:

```
### [SEVERITY] Title
- Endpoint: method + URL + param
- CWE: CWE-918
- Evidence: callback log or response content proving server-side fetch (include the request the server made)
- Reproduction: numbered steps
- Impact: internal access, metadata/credentials, pivot
```

Internal-only blind SSRF = medium. Metadata/credentials reachable = high/critical.

## Focus discipline

Open redirects found along the way: note as leads (often info). Don't chase full cloud credential abuse — report reachability and impact.
