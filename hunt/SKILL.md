---
name: hunt
description: "Router for focused bug bounty / web pentest hunts: takes a target and a focus (e.g. account takeover, IDOR, SSRF, XSS, SQLi, JWT, OAuth, GraphQL, race, LLM, logic, known CVEs), ensures recon artifacts exist, and delegates to the matching * skill with a clear brief. Use when the user asks to 'hunt for X on target Y', 'do a focused scan', or names a bug class without a specific skill."
---

# Hunt Router

## When to use

- "Hunt for <class> on <target>", "focused pentest on X", or any request that names a web target plus a bug-class focus
- User gives an action ("take over an account", "read arbitrary files", "get admin") — translate it to the matching class below

## Routing table

| User focus / intent | Skill |
|---|---|
| Recon, attack surface, "map the target", endpoints | `recon` |
| OSINT, company/acquisition footprint, scope expansion | `osint` |
| Fuzzing, hidden endpoints/params, brute-force surface | `fuzzing` |
| Account takeover: reset flows, sessions, 2FA | `ato` |
| JWT tokens: forgery, alg confusion, claims | `jwt` |
| OAuth/OIDC/SSO flows: redirect_uri, state, codes | `oauth` |
| IDOR, BOLA, tenant isolation, mass assignment | `access-control` |
| XSS: reflected, stored, DOM | `xss` |
| SQLi | `sqli` |
| SSTI | `ssti` |
| Command/code injection, RCE via args | `cmd-injection` |
| SSRF, webhooks, metadata | `ssrf` |
| XXE, XML/SVG/DOCX parsers | `xxe` |
| File upload, path traversal, LFI/RFI | `upload-traversal` |
| Open redirect (+ chains) | `open-redirect` |
| GraphQL APIs | `graphql` |
| HPP, duplicate params, parser divergence | `param-pollution` |
| Request smuggling / desync | `request-smuggling` |
| Race conditions / TOCTOU | `race` |
| Business logic: prices, workflow, coupons, limits | `business-logic` |
| Secrets, exposed files, PII, PR privacy review | `info-leak` |
| Known CVEs, n-day, fingerprint + nuclei | `known-cves` |
| Cloud: buckets, takeover, exposed services, metadata | `cloud` |
| Chatbot/AI/LLM features, prompt injection, agents | `llm-security` |
| Write-up, consolidation, submission-ready report | `report` |

Ambiguous intents → mapping:
- "get RCE" → start with `upload-traversal` + `cmd-injection` (+ `ssti`), note leads
- "read other users' data" → `access-control` (+ `graphql` if GraphQL, `info-leak` for API over-exposure)
- "is it vulnerable to something known" → `recon` → `known-cves`
- "the AI feature" → `llm-security`
- "cloud stuff / buckets / takeover" → `cloud`
- "fuzz it / find hidden endpoints" → `fuzzing`, then route anomalies per its diff table
- "take over an account" → `ato`, escalate to `jwt` / `oauth` by token type
- "found a redirect, does it matter?" → `open-redirect` (chain hunter)

## Procedure

1. **Parse the brief**: target/scope, focus, mode (black box default; grey box if credentials or source provided), constraints (rate, accounts, budget, policy).
2. **Check recon artifacts**: does `recon/<target>/profile.md` exist and is it recent? If not, run `recon` first (or ask whether to skip straight to the focus with a known endpoint list). For corporate/asset questions run `osint` instead.
3. **Delegate**: read the matching skill's SKILL.md and execute it with: target, endpoints from the profile, mode, user constraints. Do not generalize the scope on your own.
4. **Collect**: after the focused skill finishes, verify `findings/<focus>-<date>.md` exists; summarize confirmed findings, leads for other skills, coverage.
5. **Suggest next hunts**: from the profile's "recommended hunts" minus what was done, ranked, one line each. When the engagement ends (or the user asks), run `report`.

## Rules

- Never run two bug-class skills in parallel on the same target without telling the user; findings get mixed.
- If the focus doesn't match any class, say so and propose the closest 1–2 skills instead of improvising a general scan.
- If the user asks for a "full/general scan": propose the sequence recon → top-2 recommended hunts and confirm first. Focused beats broad.
- Chain findings across skills (e.g. open redirect found by `open-redirect` enabling `oauth` code theft) are the highest-value output: keep the leads sections alive and follow them deliberately.
