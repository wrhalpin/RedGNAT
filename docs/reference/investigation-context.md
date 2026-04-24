---
layout: default
title: Investigation context schema
description: The shared STIX properties that link RedGNAT emulation results to GNAT investigations and hypotheses.
---

# Investigation context schema

RedGNAT implements a shared cross-tool STIX contract that lets emulation results surface directly inside GNAT investigations. The canonical specification lives in the GNAT repo at `docs/reference/investigation-context-schema.md`. This page documents the RedGNAT-specific additions and how to consume them.

---

## Shared custom properties

Every STIX object emitted by an investigation-scoped run carries these properties:

| Property | Type | Always present | Value |
|----------|------|---------------|-------|
| `x_gnat_investigation_id` | `string` | Yes | GNAT investigation ID (e.g. `"IC-2026-0001"`) |
| `x_gnat_investigation_origin` | `string` | Yes | Always `"redgnat"` |
| `x_gnat_investigation_link_type` | `string` | Yes | `"confirmed"` for engagement-driven runs; `"inferred"` for post-hoc tagging |
| `x_gnat_hypothesis_id` | `string` | When hypothesis was provided | GNAT Hypothesis ID (e.g. `"HYP-2026-0001-01"`) |

`"confirmed"` is the common case for RedGNAT: an emulation run was **intentionally scoped** to validate something, so the link to the investigation is confirmed by construction.

---

## RedGNAT-specific additions

### `x_gnat_hypothesis_validation` (on gap Note objects)

When a run is hypothesis-scoped, the STIX gap Note carries:

```json
"x_gnat_hypothesis_validation": "detection_gap"
```

| Value | Meaning |
|-------|---------|
| `"detection_gap"` | Technique(s) ran without triggering detection — the hypothesis that the attack would be caught was **not** confirmed. |
| `"confirmed"` | All executed techniques were detected — defensive controls behaved as the hypothesis predicted. |
| `"inconclusive"` | No clear signal (e.g. all techniques were BLOCKED or DRY_RUN). |

---

## STIX object types emitted per run

| STIX type | ID pattern | Stamped? | Description |
|-----------|-----------|----------|-------------|
| `course-of-action` | `course-of-action--{run_id}` | Yes | Run-level summary |
| `sighting` | `sighting--{result_id}` | Yes | Per-technique outcome |
| `note` | `note--{gap_id}` | Yes | Gap intelligence requirements |
| `grouping` | `grouping--{run_id}` | N/A (is the envelope) | Wraps all of the above |

---

## Grouping envelope

When a run has an `investigation_id`, RedGNAT emits a STIX 2.1 `Grouping` that envelopes all objects from the run. Retrieve it via:

```
GET /api/v1/stix/groupings
```

Example Grouping:

```json
{
  "type": "grouping",
  "spec_version": "2.1",
  "id": "grouping--{run_id}",
  "name": "RedGNAT engagement {run_id}",
  "context": "suspicious-activity",
  "object_refs": [
    "course-of-action--{run_id}",
    "sighting--{result_id}",
    "note--{gap_id}"
  ],
  "x_gnat_investigation_id": "IC-2026-0001",
  "x_gnat_investigation_origin": "redgnat",
  "x_gnat_investigation_link_type": "confirmed",
  "x_gnat_hypothesis_id": "HYP-2026-0001-01"
}
```

---

## STIX API endpoints (investigation-aware)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/stix/results` | CourseOfAction objects, stamped when investigation-scoped |
| `GET` | `/api/v1/stix/sightings` | Sighting objects, stamped when investigation-scoped |
| `GET` | `/api/v1/stix/gaps` | Gap Note objects, stamped + hypothesis validation when scoped |
| `GET` | `/api/v1/stix/groupings` | Grouping objects (investigation-scoped runs only) |

---

## Database schema

Migration `003_investigation_context.sql` adds four nullable columns to `emulation_runs`:

| Column | Type | Description |
|--------|------|-------------|
| `investigation_id` | `TEXT` | GNAT investigation ID |
| `hypothesis_id` | `TEXT` | GNAT Hypothesis ID |
| `investigation_tenant_id` | `TEXT` | GNAT tenant (multi-tenant deployments) |
| `investigation_validation_pending` | `BOOLEAN` | True when hypothesis validation couldn't be completed at creation time |

---

## Configuration

```ini
[gnat]
api_base_url = http://gnat-host:8000   # Enables hypothesis validation + evidence push
api_key      = <gnat-api-key>
```

If `api_base_url` is not set, hypothesis validation is skipped and the gap report falls back to the existing `GNATClient.upsert_object()` path.

---

## See also

- [How to: run an engagement for an investigation](../how-to/run-engagement-for-investigation.md)
- [Safe-harbor design](../explanation/engagement/safe-harbor.md)
