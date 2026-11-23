---
name: recon
description: "Maps the attack surface of a web target in black box: subdomains, live hosts, endpoints, parameters, JS files, tech stack. Entry point for bug bounty and web pentest hunting. Use when given a target/scope and the task is recon, attack surface mapping, endpoint discovery, or preparation for focused hunts. Not for finding specific bug classes."
---

# Recon — Attack Surface Mapping

## When to use

- "Map the attack surface of X", "recon on X", "find endpoints/subdomains of X"
- Preparation before running any other `*` skill

## When NOT to use

- Hunting a specific bug class (use the matching skill instead)
- The target is a single known endpoint with no scope for discovery

## Inputs

- **Target**: domain, URL, or scope list (wildcards allowed, e.g. `*.example.com`)
- **Mode**: black box (default) or grey box (credentials/source provided — note them but recon stays external)

## Ground rules

- Stay strictly inside the given scope. Verify each discovered host against it before testing.
- Check tool availability with `command -v` and fall back to curl-based alternatives (documented below). Never install tools without asking.
- Work in a per-target directory, default `recon/<target>/`. All artifacts go there.

## Methodology

### 0. Deterministic discovery pass
Run `<skill-dir>/scripts/discover.sh <domain> [outdir] [--brute]` first. It executes steps 1–4 below deterministically (subfinder/crt.sh, httpx/curl, katana/wayback, JS collection with fallbacks built in) and writes `subdomains.txt`, `live.txt`, `urls.txt`, `js/`, `js-findings.txt`, `tools-used.txt` under `recon/<domain>/`. Steps 1–4 below are the reference for what it does — run them manually only if the script is unavailable. Steps 5–6 and the profile are yours.

### 1. Subdomain and host discovery
- `subfinder -d example.com` if installed; else `curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u`
- Also check: `curl -s "https://dns.google/resolve?name=example.com&type=NS"`, CNAME-only hosts, and scope wildcards.
- Probe liveness with `httpx` if installed, else a `curl -s -o /dev/null -w '%{http_code} %{url_effective}\n'` loop (follow redirects, note the final URL).

### 2. Endpoint and URL discovery
- `katana -u <live-hosts> -d 3` if installed; else Wayback: `curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" | sort -u`
- Look for: API docs (`/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`), admin panels, staging hosts, old/legacy paths.
- Bruteforce common paths with `ffuf` on the main host: wordlist (e.g. `/usr/share/wordlists` or SecLists if present; else a built-in list of ~200 common paths), filter by size (`-fs <common-size>`).

### 3. Parameter mining
- Collect all URLs with query strings from the discovered set. Group params per endpoint.
- For high-value endpoints (auth, profile, file, redirect, search), fuzz param names with `ffuf` or `arjun` if installed.

### 4. JavaScript analysis
- Download all JS files referenced by the live hosts (also `.map` source maps if present).
- Extract: API routes (`grep -oE '"/(api|v[0-9])/[^"]+"'` and similar), hardcoded keys (`grep -iE 'api[_-]?key|secret|token|password|bearer'`), internal hostnames, feature flags, commented-out endpoints.
- Feed hardcoded-key hits to `info-leak` — do not chase them here.

### 5. Tech fingerprinting
- Response headers (`Server`, `X-Powered-By`, `X-Generator`, cookies), favicon hash, `/.well-known/`, `robots.txt`, `security.txt`, login page frameworks.
- Record versions where visible. Feed to `known-cves`.

### 6. Output: target profile
Write `recon/<target>/profile.md` containing:
- Scope tested and out-of-scope hosts found (report, do not test)
- Live hosts with final URLs and tech stack
- Discovered endpoints grouped by host, marked: `[auth]`, `[api]`, `[admin]`, `[upload]`, `[redirect]`, `[params: a,b,c]`
- JS findings (routes, keys as *leads*, flags)
- A "recommended hunts" section: which `*` skills to run next and on which endpoints, ranked by attack-surface richness.

## Focus discipline

You are mapping, not exploiting. If you stumble on a live vuln, capture one evidence request/response, note it in `profile.md` under "leads", and continue recon.
