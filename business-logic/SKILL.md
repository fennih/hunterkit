---
name: business-logic
description: "Focused hunt for business logic flaws on a web target: price/quantity tampering, workflow bypass, negative/edge values, coupon and limit abuse. Use when the focus is logic bugs, e-commerce/payment flows, or 'abuse the intended behavior of X'. Not for race conditions (use race), access control between users (use access-control), or injection (use the payload skills)."
---

# Business Logic Flaws

## When to use

- "Hunt logic bugs on X", "test the checkout of X", "can I get X for free / bypass the limit"
- OWASP coverage: A04 Insecure Design, API Top 10 API8 (BFLA-adjacent logic abuse)

## When NOT to use

- Authorization between users (use `access-control`)
- Pure injection (use the payload skills: `sqli`, `ssti`, `xss`, `cmd-injection`)
- Race conditions needing concurrency (use `race`)

## Inputs

- **Target**: the business flow to test (checkout, coupon, subscription, voting, referral, withdrawal, booking, transfer)
- **Accounts**: one or two test accounts; small real value at stake only if the user allows (ask before spending money)

## Ground rules

- Do not complete real purchases/transfers unless the user explicitly allowed it; abort at the last safe step and document.
- Race tests: small bursts (5–20 parallel requests), then stop and analyze.
- Every finding needs: the intended business rule (state it), the abuse, and reproduced requests proving the rule break.

## Methodology

### 1. Model the intended rules
For the target flow, write down the invariants the business assumes: "one coupon per account", "price = server-side value", "a vote counts once", "withdrawal ≤ balance", "quantity > 0", "coupon valid once globally". You need the rule to prove the break.

### 2. Parameter tampering
- Client-controlled values sent to the server: price, quantity, discount, currency, tax, total, plan, interval.
- Negative values (`quantity=-1`, `-5.00` money), zero, huge values, float precision (`0.1+0.2` style), decimal places beyond allowed, scientific notation, comma vs dot.
- Currency/units mismatch: pay in cents as dollars, currency switch after quote.

### 3. Workflow bypass
- Skip steps: jump to step 3 URL/payload of a 4-step flow; reuse a session artifact from an incomplete flow.
- Replay: repeat a completion step (double redemption, double points), repeat with modified params.
- Order manipulation: apply coupon after price confirmation; change items after payment initiation.

### 4. Limits and quotas
- Rate-limit style limits (free uses per day, trial restarts): reset via new email `+tag`, delete/recreate account, device/IP rotate — only your own accounts.
- Trial/subscription: downgrade after upgrade, keep premium features; cancel-then-use same second.

### 5. Coupon / promo / referral
- Coupon reuse per account/global, stacking, expired coupons, format bruteforce on small pattern spaces (a few dozen max, then stop), case sensitivity, whitespace/Unicode tricks on codes.
- Single-use enforcement under concurrency → hand off to `race` (it owns burst mechanics and proof).

### 6. State and consent
- OTP/verification steps: does verifying email A then changing to email B keep verified state? Accept terms later bypassed?
- Export/report endpoints: can totals be tampered client-side?

## Grey box bonus (source available)

- Trace the server-side validation for each tampered param with Semgrep/grep: find where price/quantity is trusted from the client (`p/owasp-top-ten`, mass assignment patterns) and confirm live.

## Reporting

Write findings to `findings/logic-<date>.md`:

```
### [SEVERITY] Title
- Flow & intended rule: one line stating the business invariant
- Endpoint(s): method + URL
- CWE: CWE-840 / CWE-367 (race) / CWE-841
- Evidence: request(s) + response/state proof (e.g. two successful redemptions)
- Reproduction: numbered steps
- Impact: money, inventory, fairness, abuse at scale
```

## Focus discipline

If the abuse requires reading another user's object → lead for `access-control`. If it requires SQL/template/command payloads → `sqli` / `ssti` / `cmd-injection`.
