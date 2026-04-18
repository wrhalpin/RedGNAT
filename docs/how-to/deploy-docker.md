# How to deploy RedGNAT with Docker Compose

This guide covers a production-ready Docker Compose deployment with Postgres, Redis, the Celery worker and beat scheduler, and the FastAPI server.

---

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A `config.ini` with real credentials (see [Getting started](../tutorials/getting-started.md) for the template)
- A GNAT config file reachable from the Docker host

---

## 1 — Prepare configuration

Create a `config/` directory with your production config:

```bash
cp config/config.ini.example config/redgnat.ini
$EDITOR config/redgnat.ini
```

Minimum changes from the template for a Docker deployment:

```ini
[redgnat]
# Use Docker service hostnames, not localhost
db_url = postgresql://redgnat:redgnat@postgres:5432/redgnat
redis_url = redis://redis:6379/0
dry_run = false

[gnat]
config_path = /run/secrets/gnat.ini
```

The `docker-compose.yml` mounts `./config/redgnat.ini` into every service at `/app/config/redgnat.ini`.

---

## 2 — Set the API key

The API server reads its key from the `REDGNAT_API_KEY` environment variable. Set it in a `.env` file (never commit this):

```bash
echo "REDGNAT_API_KEY=$(openssl rand -hex 32)" > .env
```

The compose file references `${REDGNAT_API_KEY}` for the `api` service.

---

## 3 — Build and start

```bash
docker compose up --build -d
```

Services start in dependency order:

```
postgres (healthy) ─┬─► worker ─► beat
redis (healthy)    ─┘─► api
```

Check that everything is running:

```bash
docker compose ps
```

```
NAME        IMAGE      STATUS          PORTS
postgres    postgres   Up (healthy)    0.0.0.0:5432->5432/tcp
redis       redis      Up (healthy)    0.0.0.0:6379->6379/tcp
worker      redgnat    Up
beat        redgnat    Up
api         redgnat    Up              0.0.0.0:8000->8000/tcp
```

---

## 4 — Apply migrations

Migrations run automatically on first Postgres start (they are mounted into `/docker-entrypoint-initdb.d/`). Verify the schema was applied:

```bash
docker compose exec postgres psql -U redgnat -c "\dt"
```

You should see `intel_feeds`, `emulation_scenarios`, `emulation_runs`, and `technique_results` tables.

---

## 5 — Verify the deployment

```bash
curl -s http://localhost:8000/api/v1/health
# {"status":"ok","service":"redgnat"}

curl -s -X POST http://localhost:8000/api/v1/intel/ingest \
  -H "X-API-Key: $(grep REDGNAT_API_KEY .env | cut -d= -f2)"
```

---

## 6 — View logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f worker
docker compose logs -f api
```

---

## Updating

```bash
git pull
docker compose build
docker compose up -d
```

Rolling updates are not currently supported — all services restart together.

---

## Stopping and data retention

```bash
# Stop without deleting data
docker compose down

# Stop AND delete the Postgres volume (loses all scenario/run data)
docker compose down -v
```

The `redgnat_pgdata` Docker volume persists all database state across restarts. Back it up before any destructive operation:

```bash
docker compose exec postgres pg_dump -U redgnat redgnat | gzip > redgnat-backup.sql.gz
```

---

## Production hardening checklist

- [ ] Change `REDGNAT_API_KEY` from the example value
- [ ] Change Postgres password from the default `redgnat`
- [ ] Put the API server behind a TLS-terminating reverse proxy (nginx, Caddy, or ALB)
- [ ] Restrict `0.0.0.0:5432` and `0.0.0.0:6379` — they should not be internet-facing
- [ ] Mount GNAT config as a Docker secret rather than a bind mount
- [ ] Set `dry_run = false` only after confirming scope is correct
- [ ] Configure log aggregation for the worker and api containers
