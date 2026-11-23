---
name: report
description: "Consolidates findings into submission-ready reports: dedupe, severity calibration, evidence formatting, secret masking, program-policy alignment, and an executive summary. Use when a hunt (or several) finished and findings need collection, cleanup, or write-up for a bug bounty program or pentest client. Not for hunting (use the payload skills)."
---

# Reporting & Consolidation

## When to use

- "Write up the findings", "prepare the report for the program", "consolidate findings"
- After one or more focused hunts produced `findings/*.md`

## When NOT to use

- During a hunt (findings collection happens in each skill's own file)

## Inputs

- `findings/*.md` for the engagement; the program policy or client report requirements if given

## Methodology

### 1. Collect and dedupe
- Read every findings file. Merge duplicates across skills (the same root cause found by two skills = ONE finding, cross-referenced).
- Classify every entry: **confirmed** (has reproduced evidence) vs **lead** (hypothesis, no clean proof). Leads go to an appendix, never to the main report.

### 2. Severity calibration (reality check)
- For each finding, re-derive impact from evidence, not from the class label: "IDOR" isn't automatically high — whose data, how much, what action?
- Apply the program's severity table if available (BB programs override your intuition).
- Sanity pairs: if two similar findings have different severities, justify why or align them.

### 3. Evidence hygiene
- Every finding must contain: the exact request(s), the response proving impact, reproduction steps from a clean state.
- Mask secrets and PII: credentials → `AKIA...XXXX`, tokens → first/last 4 chars, user emails of others → `[redacted]`. Never include usable credentials in a report.
- No tool screenshots in place of the raw evidence: paste request/response text (reports must be reproducible by a triager).

### 4. Report structure (submission-ready)
For each finding:
```
## [SEVERITY] Title
### Summary
One paragraph: what, where, impact.
### Steps to reproduce
Numbered, from a clean state, exact requests.
### Impact
Concrete attack scenario.
### Supporting material
Request/response evidence (masked).
### Remediation (optional, if program wants it)
```
Plus an executive summary: target, scope tested, coverage (what was tested and found clean — from each skill's coverage table), counts by severity.

### 5. Program alignment
- Check policy compliance: rate limits respected, no destructive actions, scope adherence. State it in the summary (triagers love it).
- Match the submission format the program asks for (some want HackerOne fields, some want markdown).
- If policy forbids something you did, disclose it proactively.

## Harness

`scripts/summarize.py` builds the summary table from all `findings/*.md` files:

```bash
python3 <skill-dir>/scripts/summarize.py findings/
```

It parses `### [SEVERITY] Title` headers and outputs a severity-grouped index with file references. It does not invent content — everything else is your analysis.

## Output

Write `findings/report-<date>.md` (submission-ready) and optionally `findings/leads.md` (hypotheses for future hunts).
