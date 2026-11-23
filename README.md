# hunterkit

A set of 26 single-purpose skills for authorized web pentesting and bug bounty. Each skill hunts one vulnerability class, or runs one stage of the workflow, with a fixed methodology, explicit scope boundaries, and a bias toward the cheapest proof that settles whether a bug is real.

They are plain `SKILL.md` files. Any coding agent that loads skills in this format, such as Claude Code or pi, can route to them.

> Run these only against targets you are allowed to test: your own systems, an engagement with a signed scope, or a bug bounty program within its rules. The skills keep you in scope and make you prove findings, but the authorization is yours to hold.

## How a hunt runs

```
osint ──► recon ──► fuzzing ──► [focused hunt(s)] ──► report
(intel)   (surface)  (discovery)  (one class each)     (consolidate)
              │
              └──► hunt (router) picks the class skill for a stated focus
```

1. `osint` scopes the target and `recon` maps the attack surface into a reusable profile.
2. `fuzzing` surfaces anomalies and hands them to the class skills.
3. `hunt` routes a stated focus to the matching class skill, which produces evidence-backed findings.
4. `report` dedupes, calibrates severity, and writes submission-ready reports.

## Skills

**Orchestration and workflow**

| Skill | What it does |
| --- | --- |
| `hunt` | Router. Takes a target and a focus, checks that recon exists, delegates to the right class skill. |
| `osint` | Passive target intelligence: assets, acquisitions, tech and people footprint, scope expansion. No active scanning. |
| `recon` | Black-box surface mapping: subdomains, live hosts, endpoints, parameters, JS, tech stack. Produces the profile other skills read. |
| `fuzzing` | Content, parameter, header and verb fuzzing with response clustering. Feeds anomalies forward. |
| `report` | Turns findings into submission-ready reports: dedupe, severity, evidence hygiene, secret masking, policy alignment. |

**Authentication and authorization**

| Skill | What it hunts |
| --- | --- |
| `access-control` | IDOR, BOLA, horizontal and vertical privesc, mass assignment, tenant isolation. |
| `ato` | Account takeover through reset flows, sessions, 2FA, and email enumeration. |
| `jwt` | Algorithm confusion, weak secrets, missing expiry, `jku`/`x5u`/`kid` injection, claim tampering. |
| `oauth` | `redirect_uri` manipulation, missing state, code interception and reuse, missing PKCE, unverified account linking. |

**Injection and payload classes**

| Skill | What it hunts |
| --- | --- |
| `xss` | Reflected, stored and DOM XSS, context-aware, with sink and source tracing. |
| `sqli` | Error, boolean, time-based and out-of-band SQLi across params, bodies, headers and GraphQL args. |
| `ssti` | Server-side template injection with per-engine proof payloads. |
| `cmd-injection` | OS command and code injection, argument injection into binaries. |
| `xxe` | XML external entities: file read, SSRF, blind OOB, XInclude, and SVG/DOCX/XLSX parsers. |
| `ssrf` | URL params, webhooks, importers, PDF and image generators, redirects, cloud metadata. |
| `upload-traversal` | Upload bypasses, path traversal, and local or remote file inclusion. |

**Protocol and request level**

| Skill | What it hunts |
| --- | --- |
| `open-redirect` | Redirect-param bypasses and the chains they enable, plus Referer leaks. |
| `param-pollution` | Duplicate params, parser divergence, WAF bypass, type confusion. |
| `request-smuggling` | CL.TE, TE.CL, TE.TE and client-side desync, with safe low-volume detection. |
| `race` | Single-use redemption, balance math, limit checks, and state-machine races. |

**Logic, API and platform**

| Skill | What it hunts |
| --- | --- |
| `business-logic` | Price and quantity tampering, workflow bypass, coupon and limit abuse. |
| `graphql` | Introspection mapping, field-level authz gaps, IDOR, batching cost, resolver injection. |
| `info-leak` | Exposed secrets, debug endpoints, backups, source maps, PII, and a PR privacy review mode. |
| `known-cves` | Fingerprint the stack, pin versions, match CVEs, nuclei, default creds, exposed panels. |
| `cloud` | Storage misconfig and takeover, dangling-CNAME subdomain takeover, metadata and identity reuse, signed-URL abuse. |
| `llm-security` | OWASP LLM Top 10: prompt injection, system-prompt disclosure, unsafe output, excessive agency. |

## Routing

`hunt` maps a stated focus to a skill. A few ambiguous intents:

- "get RCE" starts at `upload-traversal` and `cmd-injection`, with `ssti` as a lead.
- "read other users' data" starts at `access-control`, with `graphql` and `info-leak`.
- "is it vulnerable to something known" goes `recon` then `known-cves`.
- "take over an account" starts at `ato`, escalating to `jwt` or `oauth` by token type.

## Layout

Every skill is `<name>/SKILL.md` with the same shape: when to use and when not, inputs, ground rules, methodology (cheapest proof first), reporting, and a focus-discipline reminder to hand off leads instead of chasing them. Findings are written to `findings/*.md`, and `report` consolidates them.

## Evaluation

`evals/routing/` holds a routing eval set: realistic queries across the confusable skill clusters. Some must route to one specific skill, some are near-misses that must not land on a neighbor, and some are negatives that must not start a hunt at all. Re-run it after any change to a skill's description, since the routing depends on those descriptions.

## Use

Copy the skill directories into your agent's skills folder:

- Claude Code: `~/.claude/skills/`
- pi: `~/.pi/agent/skills/`

Then ask the agent to hunt, for example "hunt for IDOR on `https://target.example`" or "map the attack surface of `target.example`".

## License

MIT
