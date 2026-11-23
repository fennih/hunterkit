# Routing eval — * suite

Test set for the highest-risk failure mode of this suite: **routing**. 26 skill
descriptions compete for activation; `hunt` delegates to one of them. This
set measures whether queries land on the right skill, on a confusable neighbor,
or on nothing.

## Coverage

Three confusable clusters plus the router, per `skills-review.md` F2:

- **auth** — ato / jwt / oauth / access-control
- **server** — ssrf / cloud / open-redirect
- **surface** — recon / osint / info-leak / known-cves
- **router** — hunt ambiguous intents, bare-tool queries, Italian phrasing

Query kinds:

- `positive` — must activate exactly the expected skill (directly or via hunt
  delegating to it).
- `near-miss` — phrased to tempt a confusable neighbor; must land on the
  expected skill (or one in `accept`).
- `negative` — must NOT activate any class skill. Direct answers or clarifying
  questions are passes; a hunt that runs is a fail.

## How to run

Automated (recommended): the SDK runner in `harness/routing-eval/` (see its
README) spawns a fresh in-memory session per run, pastes each query, detects
activation as `*/SKILL.md` reads, scores automatically, appends to
`results.csv`, and dumps transcripts to `runs/`.

```bash
cd harness/routing-eval
bun install
bun run run.ts                    # full set
bun run run.ts --ids E01,N12     # subset
bun run run.ts --kinds negative  # one kind
```

Targets use the RFC 2606 reserved `.test` TLD, so default runs generate no
third-party traffic — routing decisions happen on phrasing, and hunts die on
DNS. Use `--domain <your-lab-target>` to run end-to-end against a target you
control.

Manual (fallback, or for spot checks):

1. One fresh conversation per query. Never reuse a conversation between queries —
   earlier context contaminates activation.
2. Paste the query verbatim from `queries.jsonl`. Where `context` is set, the
   runner copies the fixture from `harness/routing-eval/fixtures/` into the
   scratch cwd and appends `(attached: <file>)` to the prompt.
3. Observe activation: the agent states which skill it consults / reads a
   `*/SKILL.md`. Record every skill that activated.
4. Runs per query: `positive` x2, `near-miss` and `negative` x3 (outputs are
   stochastic; single runs prove nothing).
5. Append one row per run to `results.csv`.

## Scoring

- `positive` pass = expected skill executed its methodology (hunt activating
  and correctly delegating counts).
- `near-miss` pass = landed on expected, or on a skill listed in `accept`.
- `negative` pass = no class skill ran a hunt. hunt activating, declining,
  and proposing skills instead of scanning = pass.
- The runner scores positives/near-misses mechanically (skill-read intersection)
  and flags negatives that hit the tool cap (`review: possible bare hunt`) for
  transcript reading.

## Iteration rules

- Change one description at a time, and only for a query failing ≥2 of 3 runs.
- After any description or SKILL.md change, re-run the full set — it is the
  regression suite.
- Do not tune on passing queries; the set is only ~27 queries, overfitting is
  one edit away.
- When a cluster reaches zero failures across a full pass, add harder queries to
  that cluster before declaring it done.

## Expected failure modes to watch

- Under-activation on osint, known-cves, open-redirect (skills whose
  task the model can do bare — see review F5).
- auth cluster drift: ATO phrasings landing on jwt/oauth and vice versa.
- info-leak mode B (PR review) never triggering because the description reads
  as target-scan-only.
- Italian queries (N12-class) routing worse than English ones.
