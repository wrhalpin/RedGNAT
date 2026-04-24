---
layout: default
title: Run an engagement for a GNAT investigation
description: How to link a RedGNAT emulation run to a GNAT investigation and optional hypothesis.
---

# Run an engagement for a GNAT investigation

RedGNAT can attach emulation results directly to a GNAT investigation so that findings appear in the investigation's evidence graph with `link_type = "confirmed"`. When a run is scoped to a specific hypothesis, the hypothesis validation result is also reported back.

---

## Prerequisites

- RedGNAT 0.1.0+ with migration 003 applied (`make migrate`)
- A GNAT investigation ID (e.g. `IC-2026-0001`) — create one in GNAT first
- (Optional) A GNAT Hypothesis ID within that investigation (e.g. `HYP-2026-0001-01`)
- `gnat.api_base_url` and `gnat.api_key` set in `redgnat.ini` if you want automatic hypothesis validation:

```ini
[gnat]
api_base_url = http://gnat-host:8000
api_key      = <your-gnat-api-key>
```

---

## Launch an investigation-scoped run

Pass the investigation context in the `POST /scenarios/{id}/run` body:

```bash
curl -X POST http://redgnat-host:8000/api/v1/scenarios/SCENARIO_ID/run \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "IC-2026-0001",
    "hypothesis_id":    "HYP-2026-0001-01",
    "triggered_by":     "manual"
  }'
```

### What happens next

1. RedGNAT validates `hypothesis_id` against GNAT's `GET /api/investigations/{id}/hypotheses`.
   - If the hypothesis is not found → `400 Bad Request`.
   - If GNAT is unreachable → run is accepted with `investigation_validation_pending: true` (see response).
2. The run executes normally under all existing scope and safety controls.
3. On completion, the gap report bundle is POSTed to `POST /api/investigations/IC-2026-0001/evidence` on GNAT.
4. Every emitted STIX object is stamped with `x_gnat_investigation_id`, `x_gnat_investigation_origin`, `x_gnat_investigation_link_type`, and (when a hypothesis was set) `x_gnat_hypothesis_id`.
5. A STIX `Grouping` enveloping all run objects is created and available via `GET /api/v1/stix/groupings`.

### Sample response

```json
{
  "run_id": "...",
  "scenario_id": "...",
  "status": "queued",
  "investigation_id": "IC-2026-0001",
  "hypothesis_id": "HYP-2026-0001-01",
  "investigation_validation_pending": false,
  "triggered_by": "manual"
}
```

---

## Query runs by investigation

```bash
curl "http://redgnat-host:8000/api/v1/runs?investigation_id=IC-2026-0001"
```

Returns all runs tagged with that investigation, including their status and technique counts.

---

## Post-hoc tagging

To associate an existing completed run with an investigation after the fact:

```bash
curl -X POST http://redgnat-host:8000/api/v1/runs/RUN_ID/investigation \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "IC-2026-0001",
    "hypothesis_id":    "HYP-2026-0001-01",
    "link_type":        "inferred"
  }'
```

The stored STIX bundle is not retroactively mutated. GNAT can re-pull updated objects from the STIX endpoints once the tag is applied.

---

## Hypothesis feedback (Phase 6)

When a run includes a `hypothesis_id`, the gap Note carries an additional `x_gnat_hypothesis_validation` property:

| Value | Meaning |
|-------|---------|
| `detection_gap` | At least one technique went undetected — hypothesis that defenses would catch it was **not** confirmed. |
| `confirmed` | All executed techniques triggered detection — defenses behaved as expected. |
| `inconclusive` | No clear signal either way (e.g. all techniques were BLOCKED or DRY_RUN). |

---

## See also

- [Reference: investigation context schema](../reference/investigation-context.md)
- [Safe-harbor design](../explanation/engagement/safe-harbor.md) — scope controls are unchanged by investigation context.
- [The feedback loop](../explanation/automation/feedback-loop.md)
