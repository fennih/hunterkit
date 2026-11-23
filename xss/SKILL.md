---
name: xss
description: "Focused hunt for Cross-Site Scripting: reflected, stored, and DOM-based, with context-aware payload selection, DOM sink/source tracing in JavaScript, and framework-aware bypasses. Use when the focus is XSS on a web target. Not for SSTI (use ssti), XSS delivered via LLM output only (use llm-security), or other injection classes."
---

# XSS (Reflected / Stored / DOM)

## When to use

- "Hunt XSS on X", "test for XSS on these params"
- OWASP coverage: A03 (XSS), CWE-79

## When NOT to use

- Server-side template rendering (use `ssti`)
- XSS through AI chatbot output (use `llm-security`, LLM05)

## Inputs

- **Target** + params list (from `recon`); one account for stored payloads

## Rationalizations to reject

- "The param is reflected, so it's XSS" — reflection is not execution. Prove the payload executes (rendered DOM, alert, or a controlled callback), not just that it appears in the response.
- "The browser blocked it" — check whether sanitization is app-side or browser-side; don't report browser-blocked vectors as findings.
- "It fired once" — reproduce from a clean state (new session/cache) for the report.

## Methodology

### 1. Context classification (per reflection point)
Determine exactly where the input lands: HTML body / attribute (quoted? which quotes?) / JS string / JS code block / URL / CSS / comment. Choose breakout per context: `</tag>`, `" onmouseover=`, `'-alert()-'`, `</script>`. A payload outside its context is noise.

### 2. Reflected
- Send canary + breakout per context. Diff baseline vs payload response.
- Watch for WAF: try case (`<ScRiPt>`), backticks, encodings (`&#x61;`), unclosed tags (`<svg/onload=`), junk padding.

### 3. DOM
- Run `<skill-dir>/scripts/dom-sinks.sh <js-dir>` first: it enumerates sinks and sources with file:line references and ranks files containing both (candidate flows — trace those first). The lists below are the script's reference patterns, for manual tracing:
- Sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`, `location=`, `location.href=`, `location.assign`, jQuery `$()`/`.html()`, `element.src=` with controllable URL.
- For each sink, trace sources: `location.hash`, `location.search`, `document.referrer`, `postMessage` (check origin validation!), `name`.
- Craft the URL/sequence that reaches the sink. `postMessage` without origin check = DOM XSS via another window you open.

### 4. Stored
- Plant canaries (`bbxss<random>`) in every persisted field: names, bio, address, filenames, UA, language, timezone, export contents, ticket titles.
- Find where each renders. Check the rendering context (attribute? JS string?) and use the right breakout.
- Second-order: field stored then shown to another user/admin (support tickets → admin panel). Mark admin-facing stored XSS as high (admin session theft).

### 5. Framework awareness
- React: only `dangerouslySetInnerHTML`, `href` with `javascript:` sinks, DOM refs.
- Vue: `v-html`, template injection via delimiters.
- AngularJS (v1): `{{constructor.constructor('alert(1)')()}}` anywhere user input reaches an interpolated scope — powerful and often missed.
- Markdown/HTML sanitizers: test mutation/mXSS (`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`), sanitizer bypass lists.

### 6. Impact proof
Default payload: `alert(document.domain)` or a marker `console.log`. Never exfiltrate real cookies of others. For the report, show the executing payload and a screenshot-level description of the rendered state.

## Reporting

`findings/xss-<date>.md` + coverage table `endpoint | param | context | payload | executed?`. Severity: stored on other users/admin = high; reflected on main origin = medium/high depending on placement; only-in-dev-tools = not a finding.

## Focus discipline

Template syntax executing server-side → `ssti`. Payload triggering server fetch → `ssrf`.
