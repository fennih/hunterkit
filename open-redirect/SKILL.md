---
name: open-redirect
description: "Focused hunt for open redirects: redirect param validation bypasses, chains into OAuth/SSRF/filters, and Referer-based leaks. Use when the focus is open redirect on a web target. Usually reported as info/low unless chained — this skill exists to find the chain, not the bare redirect."
---

# Open Redirect

## When to use

- "Hunt open redirect on X", "find redirect chains on X"
- Chain material for: OAuth `redirect_uri` (`oauth`), SSRF filters (`ssrf`), token/secret leak via Referer, CSRF-ish flows

## When NOT to use

- Server-side URL fetching (that's `ssrf` — the server fetches; open redirect = victim's browser moves)

## Inputs

- **Target** + params list; look for `?url=`, `?next=`, `?redirect=`, `?return=`, `?continue=`, `?dest=`, `?target=`, `?r=`, `?u=`, and post-login redirects

## Rationalizations to reject

- "It redirects to my site" — that IS the finding, but bare redirects are info/low in most programs. Spend the effort on the chain before reporting.
- "Param validated, closed" — you tested your bypass list, not all bypasses. Exhaust the list below before concluding.

## Methodology

### 1. Bypass list (in order)
Against the redirect validation:
- `https://target.com@your-domain.com` (userinfo trick)
- `https://your-domain.com/target.com`, `https://your-domain.com#@target.com`
- `//your-domain.com` (protocol-relative)
- `https:your-domain.com`, `\/\/your-domain.com`
- `\/your-domain.com`, `/\/your-domain.com`
- `https://target.com/your-domain.com` (path confusion)
- `https://target.com\.your-domain.com`, `https://target.com%2F@your-domain.com`
- `@`, `#`, `?`, `%23`, `%2f`, `%5c` combos
- Subdomain of an allowed domain you control, or an open redirect on an allowed domain (redirect chain: allowed → allowed → yours)
- POST-based redirect endpoints (often forgotten)
- Header-based: `Location` reflected from `?url=` without validation on error paths

### 2. Chain construction (the value)
- **OAuth**: use the open redirect as `redirect_uri` target if the client allows a path under the redirect domain.
- **SSRF filters**: server fetching a URL that redirects (allowed URL → yours) — hand off to `ssrf`.
- **Token leak**: redirect with token/code in URL → does the destination page load external resources (Referer leak to your host)?
- **Phishing credibility**: same-domain redirect chain for credential harvesting (report as impact narrative).

### 3. DOM redirects
JS: `location = params.get('next')`, `location.href = unvalidated`, `window.open(userInput)`. Same bypass list client-side. Check `postMessage`-driven redirects too.

## Reporting

`findings/open-redirect-<date>.md`. Bare = info/low; chained (OAuth/token leak) = medium/high. Always state the chain explicitly, with the full request sequence as evidence.

## Focus discipline

If the *server* fetches your URL → hand off to `ssrf`. If the redirect is part of an OAuth flow → `oauth`.
