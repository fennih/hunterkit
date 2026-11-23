---
name: access-control
description: "Focused hunt for broken access control: IDOR/BOLA, horizontal and vertical privilege escalation, forced browsing, mass assignment, tenant isolation. Use when the focus is authorization bugs between authenticated users/roles on a web target or API. Not for authentication/ATO (use ato) or business logic abuse (use business-logic)."
---

# Access Control (IDOR / BOLA / Privilege Escalation)

## When to use

- "Hunt IDOR on X", "test authorization of X", "check tenant isolation on X"
- OWASP coverage: A01 Broken Access Control
- Works best with two accounts of different users and, if possible, different roles (grey box)

## When NOT to use

- Login/session bugs (use `ato`)
- Price tampering, race conditions (use `business-logic`)

## Inputs

- **Target**: base URL(s) and API endpoints (from `recon` profile if available)
- **Accounts**: two user accounts (A=victim, B=attacker). Optionally one admin account for vertical tests.
- **Artifacts**: API docs (swagger/openapi) if discovered — enumerate all state-changing endpoints first.

## Ground rules

- Every finding needs a reproduced cross-account request: the same request succeeds as B using A's resource ID.
- Swap IDs one at a time; never mutate both identity and object at once.
- Record the exact "object reference" you abused (numeric ID, UUID, email, filename, path).

## Methodology

### 1. Enumerate object references (identifier source discovery)
With A's session, walk the app/API: collect every identifier in URLs, bodies, headers (`X-User-Id`), and cookies. Classify: user IDs, order IDs, document IDs, tenant/org IDs, role fields.

Before concluding an ID is unguessable, check every source of OTHER users' identifiers from A's own account:
- Verbose responses: GET every list/detail endpoint as A; diff the full JSON against what the UI renders. Fields the UI never shows (other users' GUIDs, tenant IDs, `owner`/`createdBy`, internal flags) are prime IDOR fuel.
- Hidden/nested fields: arrays, `*Guid`/`refId`/`parent*` keys, embedded objects of related records, response envelopes.
- Exports and documents: CSV/PDF/invoice/order confirmation endpoints that embed references to other objects or users.
- Shared-context responses: search results, public listings, comments, collaborator lists, support tickets.
- Client storage and JS: localStorage, IndexedDB, source maps, state embedded in the page bundle.

Record for each source: endpoint, field path, and whether the identifier is A's own or plausibly someone else's. A response returning an `orderGuid` that is not A's is a source — hunt it before brute-forcing.

### 2. Horizontal tests (same role, different user)
For each state-changing or data-reading endpoint: replay B's request with A's object reference.
- Read endpoints: B reads A's data (BOLA).
- Write endpoints: B modifies A's resource (e.g. delete, update email/phone of A).
- Watch for UUIDs: even non-sequential, they can leak via any source in step 1 — always establish where the app learns the ID from.

### 3. Confirm identifier validity with an authorization oracle
When one endpoint DOES enforce ownership (e.g., returns 200 for A's GUID and 403/404 for a foreign one), use it as an oracle before spending requests on endpoints that may lack the check:
- Fire the candidate GUID at the enforcing endpoint first: 200 = valid and yours, 403/404 = valid-but-foreign or invalid, and note which.
- A GUID confirmed valid-but-foreign (distinguish 403 "not yours" from 404 "not found" if the API differentiates) is the ideal payload for testing the endpoints suspected to skip the check.
- Same differential on the enforcing endpoint maps its own error semantics — needed to interpret results on the unguarded ones.
- Rate-limit oracle calls; the oracle is a reconnaissance tool, never the finding. The finding is the cross-account success on the endpoint missing the check (step 2 rules still apply: same request succeeds as B on A's object).

### 4. Vertical tests (role escalation)
If roles exist (user/admin, member/owner, free/paid):
- Reach admin/privileged endpoints as a low-priv user (forced browsing: `OPTIONS`, direct POST, guessing admin routes from JS/admin JS files).
- Admin response tampering: remove UI but does the API still authorize?
- Role field in requests: `role: "admin"`, `isAdmin: true`, `admin=true` params (mass assignment).
- Register a user with extra fields; check profile update accepting `role`/`plan`/`active` fields.

### 5. Mass assignment
On profile/update endpoints, add hidden fields: `role`, `permissions`, `plan`, `price`, `verified`, `balance`, `tenantId`. Compare the stored object before/after.

### 6. Multi-tenant isolation
If org/workspace IDs appear: switch `tenantId`/`orgId` in A's requests to B's tenant. Test data reads, invites, exports, and webhooks cross-tenant.

### 7. Indirect object references and GraphQL
- GraphQL: query another user's object by ID; check field-level authz (query user A's fields as B); introspection for hidden queries/mutations.
- Pre-signed URLs, tokens: does the URL expire, is it bound to the object only, can it be reused by another user?

### 8. Verify absence of checks, not just presence
For each endpoint, record whether authorization was enforced. A table `endpoint | authz enforced? | notes` is part of the report — negative results are valuable coverage evidence.

## Grey box bonus (source or PR available)

- Run Semgrep over the source: `p/owasp-top-ten` and `p/idor`-style rules on the API handlers; confirm each hit with a live cross-account request before reporting (source hints are hypotheses, not findings).

## Reporting

Write findings to `findings/access-control-<date>.md`. Format per finding:

```
### [SEVERITY] Title
- Endpoint(s): method + URL
- CWE: CWE-639 (IDOR) / CWE-284 / CWE-915 (mass assignment)
- Evidence: B's request against A's object + response showing A's data or the modified state
- Reproduction: numbered steps
- Impact: data exposure, data tampering, privilege gained
```

Also include the coverage table from step 7.

## Focus discipline

If exploitation requires race conditions or price tampering, hand off to `business-logic` as a lead.
