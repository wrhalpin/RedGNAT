# RedGNAT — Cross-Tool Investigation Context Plan

**Scope:** RedGNAT’s side of the GNAT-o-sphere investigation-context work. The shared contract lives in the GNAT repo at `docs/reference/investigation-context-schema.md`. **Read that first.**

**Intended audience:** Claude Code working in the `wrhalpin/RedGNAT` repo.

-----

## Context that must not be re-derived

RedGNAT’s actual layout (high-level — confirm specifics in-repo):

- `redgnat/` — the package.
- `config/config.ini.example` — INI-style config, same convention as GNAT.
- `migrations/` — Postgres schema migrations.
- Docker Compose stack with Postgres + Redis.
- Celery worker (`make worker`) + REST API (`make api`).
- Already described in README as ingesting “live threat intelligence from GNAT and SandGNAT, builds scoped adversary-emulation scenarios, executes them under layered safety controls, and feeds detection gaps back into GNAT as structured intelligence requirements.”

GNAT-side infrastructure RedGNAT integrates with:

- `gnat.analysis.investigations.Hypothesis` — already exists. Each investigation has zero or more hypotheses. Emulation validates hypotheses.
- `gnat.analysis.investigations.InvestigationService` — state machine and CRUD for investigations.
- GNAT’s cross-tool investigation endpoints (see GNAT plan Phase 1.1), especially `GET /api/investigations/{id}/hypotheses`.

If any of the above has changed, confirm the current state in-conversation before proceeding.

-----

## Goal

Let RedGNAT emulation runs attach their results to a specific GNAT investigation — and, when applicable, to a specific hypothesis within that investigation — so the emulation findings appear in the investigation’s evidence graph and report with `link_type = "confirmed"`.

RedGNAT is the only addon where `"confirmed"` is the common case. A detonation or detection may or may not truly belong to an investigation, but an emulation run was *intentionally scoped* to validate something. That’s a confirmed link by construction.

-----

## The shared contract (quick reference)

Three custom STIX properties, stamped on every emitted object:

- `x_gnat_investigation_id`
- `x_gnat_investigation_origin = "redgnat"`
- `x_gnat_investigation_link_type` — `"confirmed"` when the engagement was launched under an investigation (the common case). `"inferred"` only for opportunistic linking.

Every emulation run with an investigation context also emits a STIX `Grouping` wrapping the run’s objects.

Additionally — RedGNAT-specific — if the run was scoped to a specific hypothesis, add:

- `x_gnat_hypothesis_id` — the GNAT `Hypothesis.id` the emulation validated.

-----

## Phase 0 — Schema migration

Path: `migrations/00X_investigation_context.sql` (pick next available number).

Add nullable columns to the engagement/run table(s). Names may need adjusting after confirming the current schema:

```sql
ALTER TABLE engagements
    ADD COLUMN investigation_id TEXT,
    ADD COLUMN hypothesis_id TEXT,
    ADD COLUMN investigation_tenant_id TEXT;

CREATE INDEX idx_engagements_investigation_id
    ON engagements (investigation_id)
    WHERE investigation_id IS NOT NULL;

CREATE INDEX idx_engagements_hypothesis_id
    ON engagements (hypothesis_id)
    WHERE hypothesis_id IS NOT NULL;
```

If the primary run table has a different name, adjust accordingly. The linking should be on the outermost run/engagement, not on every step — a run is a single unit of scoping.

No `investigation_link_type` column — it’s always `"confirmed"` when set via the engagement-planning path. The `"inferred"` case is Phase 5 (optional, post-hoc tagging).

-----

## Phase 1 — Engagement plan / execution request

### 1.1 Accept investigation context on engagement creation

RedGNAT’s API accepts engagement plans. Extend the plan DTO (and the API endpoint) to accept optional fields:

```json
{
  "engagement_name": "...",
  "techniques": ["T1566.001", "T1059.001"],
  "safety_controls": {...},
  "investigation_id": "IC-2026-0001",
  "hypothesis_id": "HYP-2026-0001-01",
  "investigation_tenant_id": "tenant-a"
}
```

All three new fields are optional.

### 1.2 Hypothesis validation

If `hypothesis_id` is provided:

- Call GNAT’s `GET /api/investigations/{investigation_id}/hypotheses` to fetch the hypothesis list.
- Verify the hypothesis exists and belongs to the investigation.
- If validation fails: `400 Bad Request` with a clear message.
- If GNAT is unreachable: accept the engagement (store the IDs) but emit a warning log and mark the engagement with `investigation_validation_pending = true`.

If `investigation_id` is provided without a hypothesis_id, skip hypothesis validation.

### 1.3 Fetch hypothesis details for scoping

When hypothesis_id is set, fetch the hypothesis content (the narrative and any ATT&CK technique hints) and attach to the engagement record. This lets the engagement planner narrow techniques to what the hypothesis actually asks about, rather than running a general emulation.

The hypothesis scoping is a *suggestion* to the planner, not a hard constraint. Analysts may still override.

### 1.4 Models

Plumb the three new fields through the engagement dataclass, Celery task signature, and persistence layer.

-----

## Phase 2 — STIX output stamping

RedGNAT emits STIX `Note`, `Report`, and potentially `Attack Pattern` / `Relationship` objects representing findings and emulation results.

### 2.1 Helper

Add `apply_investigation_context(stix_obj, investigation_id, hypothesis_id, link_type="confirmed")` mirroring SandGNAT’s helper but adding the `x_gnat_hypothesis_id` property when a hypothesis was provided.

### 2.2 Thread through all factories

Every STIX factory in the findings/reporting path must call this helper before returning. The context is threaded from the engagement row.

### 2.3 Grouping envelope

One `Grouping` per engagement run when an investigation is present:

- `name`: `"RedGNAT engagement <engagement_id>"`
- `context`: `"suspicious-activity"` (or a more specific value if one fits better — confirm in STIX 2.1 spec; `"malware-analysis"` is wrong for emulation).
- `object_refs`: every object emitted by the engagement.
- Custom properties: all four (three shared + `x_gnat_hypothesis_id` when set).

### 2.4 Validation result objects

RedGNAT’s validation reports and detection-gap findings are the highest-value output for the investigation. Ensure these specifically get stamped and referenced in the Grouping.

-----

## Phase 3 — Push to GNAT on engagement completion

RedGNAT’s current integration with GNAT involves posting results. Hook the push into the new GNAT endpoint:

### 3.1 Endpoint selection

When the engagement has `investigation_id` set: POST the bundle to `/api/investigations/{id}/evidence` on GNAT.

When it doesn’t: retain the existing post path (whatever it is today — ingest via TAXII or direct API).

### 3.2 Error handling

- On `409 Conflict` (investigation closed): log, persist the bundle locally with status `pending_reopen`. Analyst can request a retry with the `X-Reopen-Investigation` header.
- On `404` (investigation deleted): log, mark the engagement as orphaned, keep the bundle.
- On tenant mismatch `403`: log loudly. This is a configuration bug.
- On GNAT unreachable: retry with exponential backoff (Celery already supports this). Engagement results are not lost.

### 3.3 Idempotency

The push must be idempotent by engagement ID. Re-posting the same engagement’s bundle should be a no-op on GNAT’s side (this is a property of the `/evidence` endpoint, specified in the GNAT plan — confirm it’s honoured).

-----

## Phase 4 — API surface additions

Two new endpoints on RedGNAT’s REST API:

|Method|Path                               |Purpose                                                  |
|------|-----------------------------------|---------------------------------------------------------|
|`GET` |`/engagements?investigation_id=...`|List engagements tagged with this investigation.         |
|`GET` |`/engagements/{id}`                |Include the investigation/hypothesis IDs in the response.|

These support an analyst workflow where GNAT’s UI drills into “what validation runs have we done for this investigation?”

-----

## Phase 5 — Post-hoc tagging (optional)

Same pattern as SandGNAT’s Phase 5. If an analyst wants to retroactively associate an engagement with an investigation:

```
POST /engagements/{id}/investigation
Body: {"investigation_id": "...", "hypothesis_id": "...", "tenant_id": "...", "link_type": "inferred"}
```

This updates the row. The stored STIX bundle is *not* mutated. GNAT can re-pull if it needs restamped objects.

**Skip this phase if schedule is tight.** The plan path (Phase 1) covers the primary use case.

-----

## Phase 6 — Hypothesis feedback loop (consider; might defer)

RedGNAT uniquely can report *back* on hypothesis validation:

- Hypothesis held up (detection fired as expected) → post a `Note` marked `validation_result: "confirmed"`.
- Hypothesis failed (detection gap found) → post a `Note` marked `validation_result: "detection_gap"` and feed into GNAT’s intelligence-requirements flow.
- Hypothesis inconclusive → `validation_result: "inconclusive"`.

This is a small addition to Phase 2’s Note emission, but it requires GNAT’s `Hypothesis` model to have a `validation_results` field or equivalent — confirm in-conversation before planning.

**Deferrable.** Useful but not required for the minimum viable investigation-context integration.

-----

## Phase 7 — Tests

### Unit

- `tests/test_engagement_investigation_fields.py` — plan DTO accepts, validates, and persists the three new fields.
- `tests/test_hypothesis_validation.py` — hypothesis_id is validated against GNAT; missing hypothesis → 400; GNAT unreachable → accept with warning.
- `tests/test_stix_stamping.py` — stamped objects carry all four custom properties when hypothesis_id is set; three when it isn’t; none when no investigation_id.
- `tests/test_grouping_envelope.py` — Grouping exists for investigation-scoped runs, doesn’t for unscoped.
- `tests/test_push_routing.py` — engagement with investigation_id posts to `/api/investigations/{id}/evidence`; without, posts to the existing path.
- `tests/test_push_error_handling.py` — 409 / 404 / 403 / network error branches behave as specified in Phase 3.2.

### Integration

- `tests/integration/test_end_to_end_engagement.py` — mock GNAT: create an engagement with investigation_id and hypothesis_id, run through to completion, verify bundle posted, verify stamping.

-----

## Phase 8 — Docs

- Update `README.md` quick-start with the new engagement-creation fields.
- Add `docs/how-to/run-engagement-for-investigation.md`.
- Add `docs/reference/investigation-context.md` — link to canonical spec in GNAT.
- Update the engagement-plan schema reference.

-----

## Out of scope

- Authoring hypotheses. RedGNAT references them; GNAT owns them.
- Automatic engagement creation from hypotheses. A future analyst-copilot feature; not this pass.
- Changing the safety-control model. Unchanged by this work.
- Cross-run dependencies (engagement A validates hypothesis X, engagement B depends on A’s result). Out of scope.

-----

## Acceptance criteria

1. An engagement can be created with `investigation_id` and (optionally) `hypothesis_id`. GNAT is consulted to validate the hypothesis.
1. On engagement completion, the STIX bundle is posted to `/api/investigations/{id}/evidence` on GNAT. Every object is stamped with the three (or four) custom properties. The bundle contains a wrapping Grouping.
1. Link type is `"confirmed"` for engagement-driven runs.
1. Engagements without investigation context work unchanged — same post path, same output format.
1. Failures on the push path (GNAT unreachable, closed investigation, bad tenant) are logged and recoverable — results are never silently lost.
1. `GET /engagements?investigation_id=...` returns the expected list.

-----

## Risks

|Risk                                                                                   |Mitigation                                                                               |
|---------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
|Hypothesis validation adds latency to engagement creation.                             |Short timeout (3s); accept-with-warning on GNAT unreachable.                             |
|Analyst scopes engagement too narrowly to the hypothesis and misses related techniques.|Hypothesis scoping is a suggestion, not a hard constraint. Document clearly.             |
|Engagement results orphaned by deleted investigation.                                  |Orphan detection in Phase 3.2. Results persist locally, marked orphaned, visible via API.|
|RedGNAT’s push path becomes dependent on GNAT being reachable.                         |Celery retry with exponential backoff. Max retries surface as alert, not data loss.      |
|Bundle posted to a closed investigation causes confusion.                              |Explicit `X-Reopen-Investigation` flow; orphaned engagement clearly flagged.             |

-----

## Handoff checklist

- [ ] GNAT’s `/api/investigations/{id}/hypotheses` and `/api/investigations/{id}/evidence` endpoints exist and are tested.
- [ ] Shared contract doc finalised in the GNAT repo.
- [ ] Confirmed in-conversation that the primary engagement-level table name matches the migration. If not, adjust before running.
- [ ] Decide whether Phase 5 (post-hoc tagging) and Phase 6 (hypothesis feedback loop) are in or deferred.
- [ ] Confirmed the existing GNAT push path name so the Phase 3.1 routing logic picks the right fallback when no investigation_id is set.