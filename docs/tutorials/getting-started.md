# Getting started with RedGNAT

**What you'll build:** A running RedGNAT instance connected to GNAT, with a first emulation scenario executed in dry-run mode so nothing touches production targets.

**Time:** ~30 minutes.

**Prerequisites:**
- Python 3.11+ and `pip`
- Docker and Docker Compose (for Postgres + Redis)
- A working GNAT installation with `gnat.ini` accessible from this host
- Network access to your GNAT instance

---

## Step 1 — Install RedGNAT

Clone the repository and install the package with all extras:

```bash
git clone https://github.com/wrhalpin/RedGNAT.git
cd RedGNAT
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"
```

The `[all]` extra pulls in optional dependencies for every technique category (nmap bindings, ldap3, boto3, msal, etc.). In production you only need the extras for techniques you actually use.

Verify the install:

```bash
python -c "import redgnat; print(redgnat.__version__)"
# 0.1.0
```

---

## Step 2 — Start backing services

RedGNAT needs Postgres (scenario + result storage) and Redis (Celery broker). For local development, start only those two services so you can run the worker and API directly on your machine with live code reloading:

```bash
docker compose up -d postgres redis
```

> **Full Docker path:** If you prefer to run everything in containers (no local worker or API processes), use `make docker-up` instead — it starts all five services (postgres, redis, worker, beat, api). In that case skip Steps 5 and 6; the worker and API are already running inside Docker.

The `postgres:16-alpine` and `redis:7-alpine` containers expose their ports on `localhost` only by default.

---

## Step 3 — Create your configuration file

Copy the example and edit it:

```bash
cp config/config.ini.example ~/.redgnat/config.ini
$EDITOR ~/.redgnat/config.ini
```

For this tutorial you only need to fill in four sections. Everything else can stay at its default.

### 3a — Database and Redis

```ini
[redgnat]
db_url = postgresql://redgnat:redgnat@localhost:5432/redgnat
redis_url = redis://localhost:6379/0
dry_run = true   # ← important for this tutorial
```

Setting `dry_run = true` means every technique will log what it *would* do and return `DRY_RUN` status. No network activity reaches any target.

### 3b — Point at your GNAT config

```ini
[gnat]
config_path = ~/.gnat/config.ini
poll_interval_seconds = 300
min_confidence = 0.6
```

### 3c — Set a safe scope

```ini
[scope]
target_ranges = 10.0.0.0/8
excluded_ranges =
target_domains = example.com
target_accounts = redteam-test@example.com
max_rate_per_minute = 30
```

Even in dry-run mode the scope is validated — techniques will be BLOCKED rather than DRY_RUN if a target isn't in scope, which is intentional.

---

## Step 4 — Apply database migrations

```bash
make migrate
```

This runs `migrations/001_initial_schema.sql` against the Postgres instance. The migration is idempotent — safe to run multiple times.

---

## Step 5 — Start the Celery worker

Open a second terminal:

```bash
source .venv/bin/activate
make worker
```

You should see Celery start and connect to Redis:

```
[2026-04-18 09:00:00,000: INFO/MainProcess] Connected to redis://localhost:6379/0
[2026-04-18 09:00:00,000: INFO/MainProcess] mingle: searching for neighbors
[2026-04-18 09:00:00,000: INFO/MainProcess] celery@hostname ready.
```

---

## Step 6 — Start the API server

Open a third terminal:

```bash
source .venv/bin/activate
make api
```

The FastAPI server starts on `http://localhost:8000`. Check it's healthy:

```bash
curl -s http://localhost:8000/api/v1/health
# {"status":"ok","service":"redgnat"}
```

---

## Step 7 — Trigger your first intel ingestion

RedGNAT polls GNAT for campaigns with ATT&CK technique mappings and SandGNAT for sandbox analyses. Trigger a manual poll:

```bash
curl -s -X POST http://localhost:8000/api/v1/intel/ingest \
  -H "X-API-Key: changeme"
```

If GNAT has any recent campaigns mapped to registered techniques you'll see:

```json
{"feeds_ingested": 3, "feed_ids": ["uuid-1", "uuid-2", "uuid-3"]}
```

If GNAT has no matching data yet, `feeds_ingested` will be `0` — that's fine, you can create a scenario manually in the next step.

---

## Step 8 — Run your first scenario

### Option A — Run a scenario from ingested intel

List the scenarios that were built from intel:

```bash
curl -s http://localhost:8000/api/v1/scenarios \
  -H "X-API-Key: changeme" | python -m json.tool
```

Pick a `scenario_id` and run it:

```bash
curl -s -X POST http://localhost:8000/api/v1/scenarios/<scenario_id>/run \
  -H "X-API-Key: changeme" \
  -H "Content-Type: application/json" \
  -d '{"triggered_by": "tutorial", "async": true}'
```

### Option B — Run programmatically

```python
from redgnat.client import RedGNATClient

client = RedGNATClient()  # reads ~/.redgnat/config.ini
feeds = client.ingest_latest()
scenarios = client.list_scenarios()

if scenarios:
    run = client.run_scenario(scenarios[0].scenario_id, triggered_by="tutorial")
    print(f"Run {run.run_id} queued — status: {run.status.value}")
```

---

## Step 9 — Review results

Check the run's results:

```bash
curl -s http://localhost:8000/api/v1/runs/<run_id>/results \
  -H "X-API-Key: changeme" | python -m json.tool
```

Because `dry_run = true`, every result will have `"status": "dry_run"` and a description of what the technique *would* have done. No network packets left the machine.

You can also fetch the full CART report:

```bash
curl -s http://localhost:8000/api/v1/runs/<run_id>/report \
  -H "X-API-Key: changeme" | python -m json.tool
```

---

## Step 10 — Check the gap report

After the run completes, RedGNAT automatically builds a gap report and makes it available for GNAT to pull:

```bash
curl -s http://localhost:8000/api/v1/stix/gaps \
  -H "X-API-Key: changeme" | python -m json.tool
```

In dry-run mode all results are `DRY_RUN` (not `SUCCESS`), so the gap list will be empty — gaps only appear when a technique completes without triggering a detection alert in a real run.

---

## What's next?

- **Enable real execution** — set `dry_run = false` in your config, configure the `[scope]` section carefully, and re-run against actual test targets
- **Configure GNAT integration** — follow [Configure GNAT integration](../how-to/configure-gnat-integration.md) to enable bidirectional results flow
- **Add a technique** — follow [Add a new technique](../how-to/add-technique.md) to extend the technique library
- **Deploy to production** — follow [Deploy with Docker](../how-to/deploy-docker.md)
