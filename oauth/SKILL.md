---
name: oauth
description: "Focused hunt for OAuth 2.0 / OpenID Connect vulnerabilities: redirect_uri manipulation, missing state, code interception and reuse, PKCE absence, account linking without verification, token leakage. Use when the focus is the OAuth/SSO/social login flow of a target. Not for JWT signature attacks (use jwt) or password-reset ATO (use ato)."
---

# OAuth / OIDC Attacks

## When to use

- "Test the OAuth/social login of X", "SSO issues on X"
- Target has "Sign in with Google/Apple/GitHub/..." or an OIDC login

## When NOT to use

- JWT forging (use `jwt`)
- Password reset flows (use `ato`)

## Inputs

- **Target** + two test accounts; ideally your own app registration on the same IdP if the flow allows

## Rationalizations to reject

- "state is present, so no CSRF" — present ≠ validated. Remove/change it and test.
- "redirect_uri is checked" — checked ≠ exact match. Try every bypass shape before concluding.
- "It worked in the browser, so the flow is fine" — replay the requests manually with curl; browser success hides header and referrer leaks.

## Methodology

### 1. Map the flow
Identify: authorization endpoint, token endpoint, grant types in use (code, implicit, hybrid, device), `response_type`, PKCE presence, where the code/token exchange happens (backend vs frontend JS). Record all params of the authorization request.

### 2. redirect_uri attacks (highest yield)
Against the client's `redirect_uri` validation:
- Exact-match bypasses: append `.@your-domain`, `#`, `?`, `/..`, `%2e%2e%2f`, `//`, backslash, `@`.
- Subdomain/path confusion: register/point a subdomain or open redirect you control under an allowed domain, chain it.
- Missing scheme check, case tricks, unicode confusables.
- For each success: does the code/token arrive at your domain?

### 3. CSRF / state
- Remove `state`: does login still complete? → login CSRF (force-login your session into the victim's browser).
- Reuse `state` from an old flow. Replay the callback URL twice.

### 4. Code handling
- Code interception via referrer: code in URL + external links/images on the redirect page.
- Code reuse: exchange the same code twice.
- Implicit/hybrid: token in URL → browser history, referrer, logs.
- Exchange in frontend JS: client_secret or token visible in the page — cross-report to `info-leak`.

### 5. Identity binding
- Account linking by email without verification: register attacker account with victim's email on the client, trigger social login with matching email → merged?
- IdP email verification absent (some IdPs allow unverified emails): claim an email you don't own.
- `nonce` absent → replay of id_token.

### 6. Scope and privilege
- Widen `scope` in the authorization request; does the token get more?
- Access other users' resources via the RS with a stolen/shared token (leads to `access-control`).

## Reporting

`findings/oauth-<date>.md`. Full ATO chain via redirect_uri + state = critical. Missing state alone = medium.

## Focus discipline

JWT signature/alg bugs → `jwt`. Cross-user API access with a valid token → `access-control`.
