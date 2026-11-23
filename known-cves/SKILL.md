---
name: known-cves
description: "Matches a web target's technology stack against known vulnerabilities: fingerprinting, nuclei scans with CVE tags, version-based CVE lookup, default credentials, exposed admin panels. Use when the focus is known vulns, CVEs, n-day exploitation, or 'is X running something vulnerable'. Not for logic or custom bugs."
---

# Known Vulnerabilities (CVE / n-day)

## When to use

- "Check X for known CVEs", "is X's stack vulnerable", "scan X with nuclei"
- Complements `recon`: fingerprint comes from there if available

## When NOT to use

- Custom/logic bugs (use the matching focused skill)
- Unverified version speculation without a confirmed fingerprint

## Inputs

- **Target**: live hosts (from `recon` profile if available)
- **Depth**: report-only (default) or validate (user explicitly allows PoC validation)

## Ground rules

- Destructive exploits forbidden by default. Validate with the least-intrusive PoC available (a version banner is often enough; if a PoC request is needed, prefer read-only ones).
- A CVE finding requires: confirmed component + confirmed version range + (if validating) proof the vulnerable path is reachable.
- Never report a CVE based on the `Server` header alone if the version is ambiguous — confirm via a second signal (error page, endpoint behavior, favicon, ETag).

## Methodology

### 1. Fingerprint
Collect per host:
- Headers: `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `X-Runtime`, `X-Version`, cookies (framework names), `ETag` patterns.
- Bodies: login page framework markers, `Generator` meta tag, error pages.
- Known paths: `/wp-login.php`, `/administrator`, `/metrics` (java), `/_next/`, `/static/django`, `/api/v1` shapes.
- `nuclei -target URL -tags tech` if installed; `httpx -tech-detect` if installed.

### 2. Version pinning
For each component, extract the exact version. Cross-check at least two signals when possible. Record how you know the version — evidence chain matters.

### 3. CVE matching
- For each component@version, look up known CVEs: prefer authoritative sources (NVD API: `curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<component> <version>"`), vendor advisories, GitHub advisories (`gh api` or `curl https://api.github.com/advisories?cwe_id=`-style queries).
- Filter by: does the deployed usage include the vulnerable feature? (e.g. a WordPress plugin CVE only matters if the plugin is present and the route reachable).

### 4. Nuclei scan (if installed)
- `nuclei -l live-hosts.txt -tags cve -severity medium,high,critical -rl 10` (rate-limited).
- Also `-tags misconfig,default-login,exposure` for a complementary pass.
- Every nuclei hit must be manually reviewed: verify the matched response actually proves the issue (no false-positive template matches). Use `fp`-style skepticism — verify the match semantically before reporting.

### 5. Default credentials and panels
Exposed panels (Grafana, Kibana, Jenkins, phpMyAdmin, admin interfaces): try known default creds only (admin/admin, etc.), a handful of attempts, then stop. Success = report credentials + screenshot-level evidence (request/response).

### 6. Validation (only if user allowed)
Pick the least-intrusive PoC per candidate: version banner proof first, harmless endpoint proof second, data-displaying proof last. Never run PoCs that modify state or dump large data without permission.

## Reporting

Write findings to `findings/known-cves-<date>.md`:

```
### [SEVERITY] CVE-YYYY-NNNN — Component vX.Y.Z
- Location: host + evidence path
- CWE
- Evidence: fingerprint signals + (if validated) PoC request/response
- Reachability: is the vulnerable feature actually deployed/reachable?
- Impact: from the advisory, in this deployment's terms
```

Include a coverage table: `host | component | version | how confirmed | CVEs considered | verified/ruled out`.

## Focus discipline

Fingerprint findings with no CVEs → hand the stack info to other skills (`sqli`, `ssti`, `upload-traversal`) as context, not as findings.
