---
name: param-pollution
description: "Focused hunt for HTTP Parameter Pollution and parameter handling differences: duplicate params overriding validation, client/server parser divergence, WAF bypass via HPP, and JSON/array type confusion in the same spirit. Use when the focus is parameter pollution on a web target. Not for mass assignment (use access-control) or generic logic bugs."
---

# HTTP Parameter Pollution (HPP)

## When to use

- "Test HPP on X", "bypass the validation of X with duplicate params"
- Classic chain: duplicate param → server takes last value, validation took first (or vice versa)
- Also applies to JSON duplicate keys and array-vs-scalar type confusion

## When NOT to use

- Role/permission fields in single requests (mass assignment → `access-control`)
- Race conditions (→ `race`)

## Inputs

- **Target** + endpoints with validation + effect on the same param

## Rationalizations to reject

- "I sent two values" — HPP is a finding only when the two components disagree: one consumed the first, the other the last. Prove the disagreement (validation passed + effect changed).
- "Weird, it worked" — reproduce with a clean pair: baseline (single param) vs polluted (double param), showing exactly which side read which value.

## Methodology

### 1. Identify parser positions
For a param `amount` (example):
- Frontend/WAF validation: reads first or last?
- Backend processing: reads first or last?
Tech rules of thumb (verify, don't trust): PHP/ASP read LAST; Node/Python frameworks vary by router; Java Servlet `getParameter` returns first; Rails takes first occurrence for non-array params.

### 2. Duplicate in every position
- Query string: `?amount=100&amount=1`
- Body (urlencoded): same
- Mixed: query + body (`?amount=100` with body `amount=1`) — which wins?
- Headers: duplicate `Cookie:` headers (esp. legacy WAFs), duplicate `X-Forwarded-For`.
- JSON: duplicate keys `{"amount": 100, "amount": 1}` (parsers differ: JS keeps last, some keep first); array `{"amount": [100, 1]}` where the backend casts.

### 3. Exploitation patterns
- Validation bypass: `?role=user&role=admin` (validation on first, processing on last).
- Price/limit override: `?quantity=1&quantity=100` — cross-report chains to `business-logic`.
- Auth/ownership: `?userId=A&userId=B` — chain to `access-control`.
- WAF bypass: duplicate the param the WAF inspects (`?q=benign&q=<payload>`) where the backend reads last, to smuggle payloads past inspection — then test the payload class with the matching skill.
- Logout/token revocation: `?token=old&token=new` (JWT/validation on first, session lookup on last) — chain to `jwt`/`ato`.

### 4. Parser divergence bonus
- Different content types: send `Content-Type: application/x-www-form-urlencoded` body to a JSON endpoint (and vice versa) — does validation and processing read the same source?
- Unicode/percent-encoding of the param NAME (`?user%5fid=`, `?USER_ID=`) creating two "different" params for different layers.

## Reporting

`findings/hpp-<date>.md` with the exact pair: baseline request, polluted request, which component read which value, and the security impact of the disagreement. Severity from the chain (WAF bypass + XSS = the XSS severity; price override = business-logic severity).

## Focus discipline

HPP is a multiplier for other classes: once proven on an endpoint, hand the technique to the matching payload skill and cross-reference.
