---
name: race
description: "Focused hunt for race conditions and TOCTOU on web targets: single-use resource redemption, balance math, limit checks, and state-machine races. Small controlled bursts with curl/ffuf, single-packet style where possible. Use when the focus is race conditions. Not for general business logic that needs no concurrency (use business-logic)."
---

# Race Conditions / TOCTOU

## When to use

- "Test race conditions on X", "can I redeem this coupon twice"
- Single-use or check-then-act resources: coupons, bonuses, votes, withdrawals, transfers, gift cards, stock, signup limits, email verification

## When NOT to use

- Non-concurrent logic bugs (`business-logic`)

## Inputs

- **Target** + the endpoint to race; your own resources only (own coupon, own balance)
- **Mode**: default burst 5–20 requests; the user may allow larger bursts

## Rationalizations to reject

- "One of 50 requests succeeded twice" — analyze before celebrating: was it a race, or does the endpoint simply lack dedup (a plain logic bug, no concurrency needed)? Report the *actual* root cause class.
- "Timing jitter proves the race" — the finding is the *outcome* (two successes against a one-use rule), not request timing.
- "More concurrency = more findings" — no. After a clean negative at 20, the window is likely closed or protected; report coverage and stop.

## Methodology

### 1. Identify the check-then-act window
Where the server reads state, decides, then writes: `SELECT balance` → `UPDATE balance`, `if !coupon.used` → `mark used`. Any gap is a candidate. Multi-step flows (initiate → confirm) widen windows.

### 2. Baseline first
Single request: success. Single repeat: blocked (the rule works serially). This proves the resource is single-use — required before racing.

### 3. Burst mechanics
- curl parallel: `seq 1 N | xargs -P N -I{} curl -s -X POST <url> -d ... -o out{}`; N=5..20 default.
- `ffuf` if installed: wordlist of N identical lines, `-t N`, one URL — request timing aligns at connect.
- Python socket-level if precision needed (single-packet-ish alignment: pre-connect, send bodies back-to-back).
- Record every response. Count successes vs the rule.

### 4. Classic patterns
- Double redemption: coupon/gift/vote/withdrawal (own resources).
- Balance race: two concurrent withdrawals where each passes `amount <= balance` but sum exceeds it. Use small amounts; abort before real settlement if possible (ask user if money is at stake).
- Limit race: free-tier limits (5 exports/day) — 20 parallel exports, count granted.
- State machine: cancel + use concurrently (cancel subscription while redeeming the included credit), delete + access concurrently (token revocation window).
- Email verify race: request two codes / verify + change email concurrently.

### 5. Analysis
- Successes > rule allows = confirmed. Record request count, successes, and the exact rule broken.
- 0/20 successes: note "window closed at 20 parallel" in coverage, don't retry endlessly. If the two-step flow suggests a wider window (initiate-then-confirm), one targeted retry with alignment on the confirm step.

## Reporting

`findings/race-<date>.md`: the rule, baseline proof (serial repeat blocked), burst size, successes, requests. Severity: money/inventory at scale = high; quota abuse = medium.

## Focus discipline

If success needs no concurrency → report under `business-logic` instead, with the serial proof.
