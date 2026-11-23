---
name: osint
description: "OSINT recon for bug bounty and pentest scoping: company assets, acquisitions, employee/tech footprint, exposed infrastructure, GitHub dorks, and scope-expansion candidates. Use when the focus is target intelligence before or during a hunt, not active scanning. Not for live endpoint discovery (use recon)."
---

# OSINT (Target Intelligence)

## When to use

- "OSINT on X Corp", "what does X own", "expand the scope for X"
- Pre-engagement: program policy analysis, acquisition mapping, tech stack hints, email/employee patterns

## When NOT to use

- Active scanning of live hosts (`recon`)
- People/social engineering (only as noted leads for the user)

## Inputs

- **Target**: company name, main domain, or the BB program policy page

## Methodology

### 1. Scope policy analysis
Read the program's policy: in-scope wildcards, forbidden (payments, third-party SaaS, DoS), special rules. Extract every allowed domain pattern. Note `*.example.com` vs explicit lists — acquisitions often fall outside; find them next.

### 2. Corporate footprint
- Acquisitions/subsidiaries: `curl -s "https://crt.sh/?q=%25.example.com"` for naming patterns, Wikipedia/press for M&A history, LinkedIn company tree hints.
- Naming conventions: acquisitions may use different domains (`example.io`, `getexample.com`, `example-assets.com`). Check trademark filings and product pages.
- Related infrastructure: ASNs (`curl -s "https://api.bgpview.io/search?query_term=Example"`), IP ranges → reverse DNS for hostnames.

### 3. Public code and docs
- GitHub dorks on the org: `curl -s "https://api.github.com/search/code?q=org:Example+apikey"` (use `gh api` when authenticated for higher limits), plus: `password`, `secret`, `AKIA`, `BEGIN PRIVATE KEY`, internal hostnames in `*.example.com` strings.
- Google dorks: `site:example.com intitle:"index of"`, `site:example.com ext:sql|env|log`, `site:trello.com OR site:notion.so "Example"` (leads only).
- Job posts: stack hints (Elastic, Kafka, k8s, frameworks) — shapes which `*` skills will pay off. Conference talks/blog engineering posts for architecture hints.

### 4. People and emails
- Email pattern discovery: `firstname@example.com` vs `f.lastname@` — verify via one password-reset-triggered response difference (info only, no ATO testing here; hand off to `ato` if interesting).
- Breach data: only report *existence* of corporate-pattern emails in public dumps as lead; never dump credentials.

### 5. Output
Write `recon/<target>/osint.md`:
- Program policy summary (in/out of scope, rules)
- Asset map: acquisitions, related domains, ASNs, naming patterns — each marked `in-scope` / `out-of-scope (candidate)` / `unknown (ask)`
- Tech stack hints and which hunts they suggest
- Code/doc leaks as *leads* (they become findings only via `info-leak` on live targets)

## Rules

- OSINT only collects public info. No credentialed scraping of social platforms, no intrusive people-lookup.
- Never test out-of-scope assets even if discovered here — list them and ask the user/program.

## Focus discipline

This skill produces intelligence, not findings. Everything actionable gets handed to `recon` (live discovery) or the payload skills.
