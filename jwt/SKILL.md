---
name: jwt
description: "Focused hunt for JSON Web Token vulnerabilities: algorithm confusion, weak secrets, missing expiration validation, jku/x5u/kid header injection, claim tampering. Use when the target uses JWTs for auth/session and the focus is token forgery or tampering. Not for the full OAuth flow (use oauth) or general account takeover (use ato)."
---

# JWT Attacks

## When to use

- "Test the JWTs of X", "can I forge a token on X"
- Target uses JWTs (bearer tokens, session cookies starting `eyJ`)

## When NOT to use

- OAuth/OIDC flow issues (use `oauth`)
- Non-JWT session bugs (use `ato`)

## Inputs

- **Target** + one valid JWT (decode it first: `python3 -c "import jwt,sys; print(jwt.decode(sys.argv[1], options={'verify_signature':False}))"`, or base64-decode the parts manually)

## Rationalizations to reject

- "The header says RS256, so it's safe" — the header is attacker-controlled; the question is what the verifier does.
- "Token looks long, secret must be strong" — test the secret, don't assume.
- "Tampered token got a 200" — confirm the tampered claim actually mattered (different user/data), not that the endpoint ignored it.

## Methodology

### 1. Map the token
Decode header and payload. Record: algorithm, key IDs, issuer/audience claims, expiry fields, role/user claims, where the token lives (cookie/header/localStorage), how it's refreshed.

### 2. Algorithm attacks
- `alg: none`: strip signature, keep `alg` as `none`/`None`/`nOnE`, empty signature segment.
- RS256→HS256 confusion: re-sign with the public key (fetch via JWKS endpoint) as HMAC secret.
- `jku` header: point to your own JWKS URL (key you control), keep `kid` matching.
- `x5u`/`x5c` header injection: same idea with certs.
- `kid` injection: path traversal (`kid: "../../dev/null"` with empty secret), SQL in kid (old stacks).

### 3. Claim validation
- Remove claims: `exp` removed and still valid? `aud`/`iss` removed?
- Swap `sub`/`user_id`/`email` to another test user's value.
- Escalate role claims: `role: admin`, `isAdmin: true`, `scope` widening.
- Negative/expired times, `nbf` in the future, `exp` far past (some verifiers only check one direction).

### 4. Secret strength
If HS256: try common secret lists (`jwt` wordlists if installed, else top ~100 candidates manually via python). A small, quick run only — then report "weak secret space" as a lead if exhausted.

### 5. Transport and lifecycle
- Token in URL (logs/referrer leak), token long-lived (30d+ with no revocation), token not invalidated on logout/password change — cross-report to `ato` as leads.

## Reporting

`findings/jwt-<date>.md`, format per family convention. Severity: forged token for another user = high/critical; alg confusion proven = high; missing expiry = medium.

## Focus discipline

OAuth-specific flows (code, state, redirect_uri) belong to `oauth`. Session-cookie management to `ato`.
