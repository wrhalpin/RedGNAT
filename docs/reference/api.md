# REST API reference

The RedGNAT API is a FastAPI application served on port `8000` by default. All endpoints are under the `/api/v1` prefix.

## Authentication

Every request must include an `X-API-Key` header matching the `REDGNAT_API_KEY` environment variable set on the server.

```bash
curl -H "X-API-Key: $REDGNAT_API_KEY" http://localhost:8000/api/v1/health
```

A missing or incorrect key returns `403 Forbidden`.

---

## Health

### `GET /api/v1/health`

Returns service status. Used by load balancers and the GNAT connector's `health_check()`.

**Response**
```json
{"status": "ok", "service": "redgnat"}
```

---

## Scenarios

### `GET /api/v1/scenarios`

List all emulation scenarios.

**Response** — array of scenario objects:
```json
[
  {
    "scenario_id": "uuid",
    "name": "APT29 Phishing Campaign",
    "description": "...",
    "feed_id": "uuid",
    "technique_ids": ["T1566.002", "T1110.003", "T1621"],
    "status": "active",
    "created_at": "2026-04-18T09:00:00+00:00"
  }
]
```

### `GET /api/v1/scenarios/{scenario_id}`

Get one scenario by ID.

**Response** — single scenario object (same shape as list item). Returns `404` if not found.

### `POST /api/v1/scenarios/{scenario_id}/run`

Trigger an emulation run for a scenario.

**Request body**
```json
{
  "triggered_by": "manual",
  "async": true
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `triggered_by` | string | `"manual"` | Audit label — who or what triggered this run |
| `async` | bool | `true` | If `true`, enqueues a Celery task and returns immediately. If `false`, runs synchronously (blocks until complete) |

**Response**
```json
{
  "run_id": "uuid",
  "scenario_id": "uuid",
  "status": "queued",
  "triggered_by": "manual"
}
```

---

## Runs

### `GET /api/v1/runs`

List emulation runs. Optionally filter by scenario.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scenario_id` | string (optional) | Filter to runs of a specific scenario |

**Response** — array of run objects:
```json
[
  {
    "run_id": "uuid",
    "scenario_id": "uuid",
    "status": "completed",
    "triggered_by": "intel_event",
    "started_at": "2026-04-18T09:00:00+00:00",
    "completed_at": "2026-04-18T09:05:23+00:00"
  }
]
```

### `GET /api/v1/runs/{run_id}`

Get one run by ID. Returns `404` if not found.

### `GET /api/v1/runs/{run_id}/results`

Get all `TechniqueResult` objects for a run.

**Response** — array of result objects:
```json
[
  {
    "result_id": "uuid",
    "run_id": "uuid",
    "scenario_id": "uuid",
    "technique_id": "T1046",
    "tactic": "discovery",
    "status": "success",
    "findings": [{"host": "10.0.0.5", "open_ports": [{"port": 22, "service": "ssh"}]}],
    "evidence": [],
    "error": null,
    "executed_at": "2026-04-18T09:01:15+00:00"
  }
]
```

`status` values: `success`, `partial`, `blocked`, `detected`, `error`, `dry_run`

### `GET /api/v1/runs/{run_id}/report`

Get the full CART report for a run as a structured dict.

**Response** — CART report object with keys: `executive_summary`, `attack_coverage`, `technique_details`, `gap_summary`.

---

## Intel

### `POST /api/v1/intel/ingest`

Manually trigger intel ingestion from GNAT and SandGNAT. Equivalent to what `ingest_intel_task` does on a schedule.

**Response**
```json
{"feeds_ingested": 3, "feed_ids": ["uuid-1", "uuid-2", "uuid-3"]}
```

### `POST /api/v1/intel/probe-request`

Submit a `ProbeRequest` from a GNAT AI agent or external system. Enqueues `run_probe_task` on the Celery queue.

**Request body** — `ProbeRequest.to_dict()` shape:
```json
{
  "technique_id": "T1621",
  "priority": "critical",
  "rationale": "Password spray succeeded without lockout — test MFA fatigue.",
  "suggested_params": {},
  "source_gap_id": "uuid-of-gap-report",
  "source_run_id": "uuid-of-source-run"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `technique_id` | string | Yes | ATT&CK technique ID to probe |
| `priority` | string | No | `"critical"`, `"high"`, or `"medium"` (default: `"high"`) |
| `rationale` | string | No | Human-readable reason for this probe |
| `suggested_params` | object | No | Per-technique parameter overrides |
| `source_gap_id` | string | No | GapReport ID that triggered this probe |
| `source_run_id` | string | No | EmulationRun ID that produced the gap |

**Response**
```json
{"queued": true, "task_id": "celery-task-uuid", "technique_id": "T1621"}
```

Returns `422` if `technique_id` is missing.

### `GET /api/v1/intel/techniques`

List all registered ATT&CK technique IDs with their metadata.

**Response**
```json
[
  {
    "technique_id": "T1046",
    "name": "Network Service Discovery",
    "tactic": "discovery",
    "description": "Scan networks to identify active services..."
  }
]
```

---

## STIX Export

These endpoints are consumed by the GNAT `RedGNATConnector` plugin. GNAT operators typically access them via `connector.list_objects(type)` rather than directly.

### `GET /api/v1/stix/results`

Return all emulation run summaries as STIX 2.1 `course-of-action` objects.

**Response** — array of STIX CoA objects:
```json
[
  {
    "type": "course-of-action",
    "spec_version": "2.1",
    "id": "course-of-action--uuid",
    "created": "2026-04-18T09:05:23+00:00",
    "modified": "2026-04-18T09:05:23+00:00",
    "name": "CART Run: APT29 Phishing Campaign",
    "description": "Automated red team emulation run. Techniques: 5. Status breakdown: {...}",
    "x_redgnat_metadata": {
      "run_id": "uuid",
      "scenario_id": "uuid",
      "status": "completed",
      "triggered_by": "intel_event",
      "technique_results": {"success": 2, "detected": 2, "blocked": 1}
    }
  }
]
```

### `GET /api/v1/stix/results/{run_id}`

Single run as a STIX CoA object. Returns `404` if run not found.

### `GET /api/v1/stix/sightings`

Return all `TechniqueResult` records as STIX 2.1 `sighting` objects.

**Response** — array of STIX Sighting objects:
```json
[
  {
    "type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--uuid",
    "sighting_of_ref": "attack-pattern--T1046",
    "count": 1,
    "x_redgnat_metadata": {
      "run_id": "uuid",
      "technique_id": "T1046",
      "status": "success",
      "findings": [...]
    }
  }
]
```

### `GET /api/v1/stix/gaps`

Return gap reports as STIX 2.1 `note` objects. A gap is any technique that executed with `status = success` (meaning no detection alert was triggered).

**Response** — array of STIX Note objects:
```json
[
  {
    "type": "note",
    "spec_version": "2.1",
    "id": "note--uuid",
    "abstract": "RedGNAT gap report: 2 undetected techniques",
    "content": "RedGNAT CART gap report — run ...\nUndetected techniques (2):\n- [T1046] ...",
    "authors": ["redgnat-cart"],
    "labels": ["redgnat-gap", "intelligence-requirement"],
    "x_redgnat_gap": {
      "run_id": "uuid",
      "scenario_id": "uuid",
      "undetected_technique_ids": ["T1046", "T1110.003"],
      "is_critical": true,
      "gap_id": "uuid"
    }
  }
]
```
