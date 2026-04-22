---
layout: default
title: Configure GNAT Integration
description: Set up bidirectional intel flow between RedGNAT and GNAT.
---

# How to configure GNAT integration

RedGNAT has a bidirectional relationship with GNAT:

- **GNAT → RedGNAT**: campaigns and TTPs become emulation scenarios; AI agents inject targeted probe requests
- **RedGNAT → GNAT**: emulation results, STIX sightings, and gap intelligence requirements flow back

This guide covers setting up both directions.

---

## Direction 1 — GNAT → RedGNAT (intel intake)

### 1a — Configure the GNAT connection

In your `~/.redgnat/config.ini`:

```ini
[gnat]
# Path to an existing GNAT config file on this host
config_path = ~/.gnat/config.ini

# How often Celery beat polls for new campaigns (seconds)
poll_interval_seconds = 300

# Minimum confidence to act on intel (0.0–1.0)
# Campaigns below this threshold are ignored
min_confidence = 0.6
```

RedGNAT uses `GNATClient(config_path=...)` to authenticate. The GNAT config controls which platform connectors are used (Shodan, Crowdstrike, MISP, etc.) — RedGNAT only reads from it.

### 1b — Start the Celery beat scheduler

The beat scheduler drives periodic polling. Run it alongside your worker:

```bash
# Terminal 1 — worker
celery -A redgnat.emulation.tasks worker --loglevel=info -Q redgnat

# Terminal 2 — beat scheduler
celery -A redgnat.emulation.tasks beat --loglevel=info
```

Or with Docker Compose:

```bash
docker compose up worker beat
```

You should see periodic log entries like:

```
[INFO] ingest_intel_task: ingested 2 new feed records
[INFO] ingest_intel_task: 1 run(s) enqueued
```

### 1c — Verify ingestion

Trigger a manual poll to confirm connectivity:

```bash
curl -s -X POST http://localhost:8000/api/v1/intel/ingest \
  -H "X-API-Key: $REDGNAT_API_KEY"
```

List the scenarios that were built:

```bash
curl -s http://localhost:8000/api/v1/scenarios \
  -H "X-API-Key: $REDGNAT_API_KEY" | python -m json.tool
```

### 1d — GNAT AI agent probe requests

GNAT's LLM agents can inject targeted probes directly into the RedGNAT Celery queue via the intake API. On the GNAT side this looks like:

```python
# GNAT side — after an agent analyses a gap report
from redgnat.plugins.gnat_plugin import RedGNATConnector

connector = RedGNATConnector(
    base_url="http://redgnat.internal:8000",
    api_key="REDGNAT_API_KEY",
)

connector.push_probe_request({
    "technique_id": "T1621",
    "priority": "critical",
    "rationale": "Password spray succeeded on Okta without lockout — test MFA fatigue.",
    "suggested_params": {},
    "source_gap_id": "gap-uuid-from-stix-note",
    "source_run_id": "run-uuid",
})
```

Or directly via the API:

```bash
curl -s -X POST http://localhost:8000/api/v1/intel/probe-request \
  -H "X-API-Key: $REDGNAT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "technique_id": "T1621",
    "priority": "critical",
    "rationale": "Follow-on probe from gap analysis.",
    "suggested_params": {},
    "source_gap_id": "",
    "source_run_id": ""
  }'
```

---

## Direction 2 — RedGNAT → GNAT (results + gap intelligence)

### 2a — Register the RedGNAT connector in GNAT

RedGNAT ships a GNAT-compatible connector as a PyPI entry point. Once installed, add it to your GNAT workspace:

```python
from gnat import GNATClient
from redgnat.plugins.gnat_plugin import RedGNATConnector

client = GNATClient(config_path="~/.gnat/config.ini")

connector = RedGNATConnector(
    base_url="http://redgnat.internal:8000",
    api_key="REDGNAT_API_KEY",
    verify_ssl=True,   # set False for self-signed certs in dev
)

# Verify connectivity
assert connector.health_check(), "RedGNAT is not reachable"
```

### 2b — Pull results into GNAT

```python
# Pull all emulation run summaries as STIX CourseOfAction objects
runs = connector.list_objects("course-of-action")
for run in runs:
    client.upsert_object(run)

# Pull per-technique STIX Sighting objects
sightings = connector.list_objects("sighting")
for sighting in sightings:
    client.upsert_object(sighting)

# Pull gap intelligence requirements as STIX Note objects
# These describe which techniques went undetected and what GNAT should collect
gap_notes = connector.list_objects("note")
for note in gap_notes:
    client.upsert_object(note)
    print(f"Gap: {note['abstract']}")
```

### 2c — Configure automatic gap push

RedGNAT can push gap STIX Notes directly to GNAT after each run (rather than waiting for GNAT to pull). Enable this in your config:

```ini
[feedback]
enabled = true
push_to_gnat = true
probe_generation_enabled = true
probe_model = claude-3-5-sonnet-20241022
max_probes_per_report = 10
```

When `push_to_gnat = true`, `GapReporter.push_to_gnat()` is called automatically at the end of every run. It calls `GNATClient.upsert_object(stix_note)` so GNAT operators see new intelligence requirements in near-real-time.

### 2d — Verify gap reports are being generated

After a real (non-dry-run) emulation run, check the STIX gaps endpoint:

```bash
curl -s http://localhost:8000/api/v1/stix/gaps \
  -H "X-API-Key: $REDGNAT_API_KEY" | python -m json.tool
```

Each gap note includes:
- Which techniques succeeded without detection
- GNAT connector enrichment hints (what intel to task)
- Whether the gap is `CRITICAL` (credential-access or initial-access techniques)

---

## Troubleshooting

### "GNAT not installed, cannot push gap report"

The `gnat` Python package is not installed in your environment. Install it:

```bash
pip install gnat
```

Or use API-mode only (RedGNAT stores notes locally for GNAT to pull via `GET /stix/gaps`):

```ini
[feedback]
push_to_gnat = false  # GNAT pulls via GET /stix/gaps instead
```

### Poll interval isn't respected

The Celery beat schedule is baked into the `app.conf.beat_schedule` at startup. After changing `poll_interval_seconds` in your config, restart the beat process:

```bash
pkill -f "celery.*beat" && celery -A redgnat.emulation.tasks beat --loglevel=info
```

### Connector returns empty lists

Check that:
1. `REDGNAT_API_KEY` matches the `REDGNAT_API_KEY` environment variable set on the API server
2. The API server is reachable at `base_url` from the GNAT host
3. At least one emulation run has completed (no runs = no results to pull)
