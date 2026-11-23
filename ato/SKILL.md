---
name: ato
description: "Focused hunt for account takeover via authentication flows: password reset, email manipulation, session management, 2FA/MFA, and email enumeration. Use when the focus is ATO, login bypass, or session hijacking. Not for JWT signature attacks (use jwt), OAuth flows (use oauth), or authorization between users (use access-control)."
---

# Account Takeover

## When to use

- "Hunt ATO on X", "test login/password reset of X", "check OAuth of X"
- OWASP coverage: A07 Identification and Authentication Failures

## When NOT to use

- JWT forging/tampering (use `jwt`)
- OAuth/OIDC flow issues (use `oauth`)
- Access control between authenticated users (use `access-control`)
- Secrets/keys exposure (use `info-leak`)

## Inputs

- **Target**: base URL(s) and relevant endpoints (from `recon` profile if available)
- **Accounts**: two test accounts (A=victim, B=attacker) if possible. In grey box you may have credentials; in black box register them if the target allows. Never test on real users.

## Ground rules

- Every finding must have a reproduced request/response pair as evidence.
- Two accounts minimum for cross-account tests. Mark account IDs clearly.
- Respect rate limits and lockout policies: don't lock out real users. Use low request counts.

## Methodology

### 1. Map the auth surface
Login, register, logout, password reset, email/username change, 2FA/MFA, "remember me", account deletion, OAuth/social login, magic links, API keys/tokens. Record which state each flow leaves (cookies, localStorage, JWTs).

### 2. Password reset flow (highest yield)
- **Host header injection**: trigger a reset while overriding `Host:` (and `X-Forwarded-Host:`) with a value you control (e.g. an interactsh/canary domain). Check if the poisoning leaks into the reset link.
- **Token in response**: check reset response body/headers for the token.
- **Token predictability/leak**: same token for two resets? Token reused after consumption? Token valid after password change?
- **Email manipulation**: `victim@x.com.attacker.com`, `victim+tag@x.com`, `VICTIM@x.com`, unicode/confusables, `victim@x.com%00@attacker.com`, trailing whitespace.
- **Reset to a new email**: does the confirmation go to the OLD email when changing email without re-auth?

### 3. Session management
- Cookie flags: `Secure`, `HttpOnly`, `SameSite`. Session fixation: set a session cookie pre-login, is it kept after login?
- Logout: does it invalidate server-side? Reuse an old cookie after logout.
- Session token entropy: are tokens predictable or derived from email/timestamp?
- Password change / email change: are all existing sessions invalidated?
- If the app uses JWTs, switch to `jwt` for token-specific attacks; if it uses OAuth/SSO, switch to `oauth`.

### 4. 2FA / MFA
- Brute-force space on OTP (response time, rate limit) — only a handful of attempts, don't lock accounts.
- "Remember device" cookie forging, OTP bypass via null/empty, response tampering leads (note for manual browser check), 2FA step skippable by direct navigation to post-login URL.
- Reset password → 2FA reset together?

### 5. Email enumeration
Compare responses/timing between existing and non-existing users at login, register, reset. Useful info disclosure but report as low/info unless chained.

### 6. Other ATO vectors
- Credential-stuffing-friendly patterns (no rate limit, generic errors) — report as hardening, not a bug.
- Type juggling on user IDs in profile APIs (leads to `access-control`).
- CSRF on email/password change: missing token, no SameSite protection, token not bound to session.

## Reporting

Write findings to `findings/ato-<date>.md`. One section per confirmed finding:

```
### [SEVERITY] Title
- Endpoint(s): method + URL
- CWE: (e.g. CWE-640 for weak password recovery)
- Evidence: full request(s) and response snippet(s) proving the takeover or bypass
- Reproduction: numbered steps from a fresh state
- Impact: what an attacker gains (full ATO? session?)
```

Full ATO chain = critical/high. Single broken control (e.g. missing state) = medium unless chained.

## Focus discipline

Do not drift into JWT/OAuth mechanics (`jwt`, `oauth`), IDOR on non-auth endpoints, or secrets hunting. Record them as leads in the report and point to the matching `*` skill.
