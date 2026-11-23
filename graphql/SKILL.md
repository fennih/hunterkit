---
name: graphql
description: "Focused hunt for GraphQL-specific vulnerabilities: introspection-enabled surface mapping, field-level authorization gaps, IDOR via queries/mutations, batching/DoS probes, error-based info leak, and mutation abuse. Use when the focus is a GraphQL endpoint. Not for generic REST IDOR (use access-control) or injection outside GraphQL contexts."
---

# GraphQL

## When to use

- "Test the GraphQL API of X", "hunt GraphQL issues on X"
- Endpoint found: `/graphql`, `/api/graphql`, `/v1/graphql` (also check `/graphiql`, `/graphql-console`)

## When NOT to use

- REST API access control (use `access-control`)

## Inputs

- **Target** + the GraphQL endpoint; two accounts for cross-user tests

## Rationalizations to reject

- "Introspection is open" — that's recon, not a finding (report as info/lead). Findings need a specific field/mutation with proven impact.
- "The query works" — works with WHOSE data? Cross-account reproduction is the proof for authz findings.
- "Aliases = DoS" — only report DoS if you demonstrated controlled, bounded impact (e.g. 100x amplification with a few requests), never by hammering.

## Methodology

### 1. Surface mapping
- Introspection query (full: `__schema { types { name fields { name } } }`, plus args/mutations). If disabled: try field suggestions (`"quer"` → "Did you mean 'query'?" error-based enumeration), Clairvoyance-style guessing if installed.
- Record queries, mutations, subscriptions, and their argument types. Mark admin/internal-looking fields.

### 2. Field-level authorization
GraphQL servers often check at the resolver level only — or not at all:
- As user B, query objects owned by user A (IDs from A's data): `user(id: "<A>") { email orders { total } }`.
- Enumerate: private fields on public queries (`email`, `apiKey`, `tokens`, `mfa` fields), disabled/deleted users still queryable.
- Mutations as B on A's objects: `updateUser(id: A, ...)`, `deleteOrder(id: A)` (destructive only on your own objects first).

### 3. Mutation abuse
- Enumerate all mutations. Check: missing ownership checks, mass-assignment-ish extra args (`role`, `isAdmin`), mutations reachable without the UI flow.
- Test each with two accounts (B acting on A's resources).

### 4. Batching and cost
- Alias-based batching: `a: user(id:1) b: user(id:2) ...` — measure amplification with ~20 aliases, report as DoS lead with the number.
- Query depth/complexity: nested recursive types (if the schema has cycles) — one deep query, note cost.
- Introspection + `__directives`, debug fields (`_service`, `_entities` if federation).

### 5. Info leak and errors
- Verbose errors: invalid type → stack, internal paths. `suggestions` revealing field names.
- Debug/Playwright endpoints: `/graphiql`, `/playground`, `/altair` exposed in prod.

### 6. Injection in resolvers
Arguments reaching DB/templates/commands: test with the matching skill's payloads (`sqli`, `ssti`) — note cross-reference in both reports.

## Reporting

`findings/graphql-<date>.md` + coverage table `query/mutation | args | as-user B on A's data | result`. Field-level authz bypass = high; DoS leads = low unless impact proven.

## Focus discipline

Login/session issues → `ato`. REST equivalents of the same authz bug → cross-note with `access-control`.
