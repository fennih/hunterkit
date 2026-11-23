---
name: request-smuggling
description: "Focused hunt for HTTP request smuggling (CL.TE, TE.CL, TE.TE) and client-side desyncs: safe differential detection with minimal request pairs, no sustained DoS. Use when the focus is smuggling/desync on a target with a front-end proxy. Requires careful, low-volume testing — this skill emphasizes the discipline."
---

# HTTP Request Smuggling / Desync

## When to use

- "Hunt request smuggling on X", "test the proxy chain of X"
- Target has: front-end (LB/CDN/proxy) + back-end with potentially differing body parsing; HTTP/1.1 with keep-alive, or HTTP/2 with downgrade

## When NOT to use

- No evidence of a proxy layer (headers like `Via`, `X-Forwarded-For`, CDN `Server` values, different headers front/back) — ask/infer first
- Programs that explicitly forbid smuggling (high impact on shared infra — check policy)

## Inputs

- **Target** + one or two vulnerable-looking endpoints (POST with body reflection preferred)
- Confirmation that you can afford 2 requests per candidate vector (plus baselines)

## Rationalizations to reject

- "405 or timeout = vulnerable" — ambiguous responses are noise. A finding needs a *differential*: the poisoned-next-request proof (second request's response contains evidence from the first request's body).
- "The error is different" — front/back errors differ for many reasons. Reproduce the differential cleanly twice.
- "More requests will clarify" — no. Smuggling probes poison *other users'* connections. Minimum volume, maximum analysis.

## Methodology

### 1. Fingerprint front/back
Headers from responses: `Server`, `Via`, CDN (Cloudflare/Fastly/Akamai signatures), `X-Served-By`, differing header case/order between endpoints (suggests two stacks). HTTP/2 support (`curl --http2 -I`). Keep-alive reuse confirmed via `curl -v` two requests on one connection.

### 2. Vector selection (safe-first)
Prefer POST endpoints where the back-end echoes the body. Vectors:
- CL.TE: front uses Content-Length, back uses Transfer-Encoding
- TE.CL: reverse
- TE.TE (obfuscated): duplicate/conflicting TE headers (e.g. `Transfer-Encoding: xchunked`, chunked with odd casing/spaces)
- H2.CL / H2.TE: HTTP/2 front-end downgrade smuggling (post-HTTP/2 desync)
- Client-side desync: server responds without Content-Length and no chunked → browser connection reuse poison (report carefully; verify with a local two-tab simulation before claiming victim impact)

### 3. Detection pairs
Standard proof shape (example CL.TE):
```
POST /endpoint HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
Followed immediately by a second, normal request: if the back-end treats the trailing `G` as the start of the next request → differential (e.g. `GPOST /endpoint` 404/405 in the second response, or the smuggled prefix visible in an error).
- One candidate vector = 1 baseline + 1 probe pair. If ambiguous, at most one repeat. Then move on.
- Use `curl` with two URLs in one invocation (connection reuse) or a tiny python script for precision.

### 4. Escalation (only after clean differential)
- Queue poisoning to capture another user's request (report captured headers, mask cookies in the report).
- Method override/routing bypass: smuggled prefix reaching internal-only paths.
- Cache poisoning via smuggling (if CDN cache in front) — one proof request.

## Reporting

`findings/smuggling-<date>.md`: vector, exact pair of requests, the two responses forming the differential, impact. Severity: cross-user capture = high; internal routing bypass = high; pure desync = medium.

## Focus discipline

If the desync comes from browser connection reuse only (client-side), label it distinctly — impact and remediation differ.
