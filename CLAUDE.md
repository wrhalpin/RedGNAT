# CLAUDE.md — RedGNAT AI Assistant Guide

This file provides context for AI assistants (Claude Code and similar) working in this repository.

---

## Project Overview

**RedGNAT** is a **Continuous Automated Red Teaming (CART)** platform built on top of GNAT and SandGNAT.
It ingests live threat intelligence from GNAT's 158+ platform connectors and malware behavioral profiles
from SandGNAT's detonation sandbox, then automatically generates and executes adversary emulation
scenarios against the enterprise environment.

**Core loop:**
1. GNAT detects a new campaign / IOC cluster / emerging TTP → RedGNAT ingests it
2. SandGNAT detonates a related sample → RedGNAT ingests the behavioral STIX bundle
3. RedGNAT builds an `EmulationScenario` (ATT&CK-mapped techniques, targets, scope)
4. RedGNAT executes the scenario (Phase 1: emulation and probing; Phase 2+: controlled offensive testing)
5. Results (detections, gaps, coverage) flow back to GNAT as STIX Course-of-Action objects
6. **Feedback loop:** GNAT's AI agents analyze gaps → generate ProbeRequests → RedGNAT executes refined follow-on probes

**Design phases:**
- **Phase 1 (current):** Emulation and probing — observe, enumerate, phish, spray, but never exploit.
  The `emulation_only = True` class attribute is the Phase 1 default, not a permanent hard constraint.
- **Phase 2 (delivered):** Controlled offensive testing — exploitation techniques with explicit opt-in,
  three-factor engagement gate (config flag + env var + Redis token), global kill switch, and
  `EngagementRunner` with per-step kill/expiry checks. Infrastructure lives in `redgnat/engagement/`.
  Exploitation techniques live in `redgnat/techniques/exploitation/` and require `emulation_only = False`
  set deliberately on a per-technique basis after individual design review.

**Package name (PyPI):** `redgnat`
**Import root:** `redgnat`
**Version:** 0.1.0
**Python support:** 3.11+
**License:** Apache-2.0
**Dependencies:** `gnat` (GNAT library), PostgreSQL (via psycopg3), Celery + Redis, FastAPI

---

## Dependency Relationship

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              GNAT (gnat)                                     │
│  158+ connectors · STIX ORM · agents · ingest · reports                     │
│  gnat.connectors.sandgnat ─────────────────────────────────────────────┐    │
│  LLMClient (Claude/GPT) ────────────────────────────────────────────┐  │    │
└──────────┬──────────────────────────────────────────────────────────┼──┼────┘
           │ GNATClient                       ▲                        │  │
           │ (intel feed: campaigns,          │ STIX CoA/Sighting      │  │
           │  IOCs, TTPs)                     │ gap reports             │  │
           │                                  │ enrichment requests     │  │
           │ ProbeRequests ◄──────────────────┘                        │  │
           │ (AI-generated follow-on probes)   AI probe generation ◄───┘  │
           ▼                                                               │ SandGNAT
┌──────────────────────────────────────────────────────────────────────┐  │ export API
│                         RedGNAT (this repo)                          │  │
│                                                                      │  │
│  intake/ ──► scenarios/ ──► emulation/ ──► techniques/              │  │
│    ▲                                         ├── discovery/          │  │
│    │ probe_requests                          ├── phishing/           │  │
│    │ from GNAT agents                        ├── identity/           │  │
│    │                                         └── exploitation/        │  │
│  feedback/ ◄── results                                               │  │
│    │  gap_reporter.py  → gap STIX Notes ──────────────────────────►  │  │
│    │  probe_generator.py → new ProbeRequests via GNAT LLMClient      │  │
│    │                                                                  │  │
│  api/ ──► REST management + ProbeRequest intake                      │  │
└──────────────────────────────────────────────────────────────────────┘  │
           │                                                               │
           ▼ SandGNAT export_api (HTTP) ◄─────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                      SandGNAT                                   │
│  Detonation sandbox · STIX 2.1 behavioral profiles             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Layout

```
redgnat/                          # Main Python package
├── __init__.py                   # Public API (RedGNATClient, ORM types)
├── client.py                     # RedGNATClient — top-level facade
├── config.py                     # INI-based configuration management
├── orm/                          # Data models (STIX-aligned)
│   ├── base.py                   # RedGNATBase — common fields + serialization
│   └── models.py                 # EmulationScenario, EmulationRun, TechniqueResult, IntelFeed
├── intake/                       # Intel ingestion from GNAT + SandGNAT
│   ├── base.py                   # IntelSubscriber ABC
│   ├── gnat_subscriber.py        # Polls GNATClient for new campaigns/TTPs
│   ├── sandgnat_subscriber.py    # Polls SandGNAT export API for new analyses
│   └── normalizer.py             # STIX bundle → EmulationScenario
├── scenarios/                    # Scenario construction from intel
│   ├── builder.py                # ScenarioBuilder — assembles technique lists
│   ├── ttp_mapper.py             # STIX AttackPattern → ATT&CK technique IDs
│   └── store.py                  # ScenarioStore — PostgreSQL persistence
├── emulation/                    # Emulation orchestration
│   ├── plan.py                   # EmulationPlan — ordered technique schedule
│   ├── result.py                 # RunResult, TechniqueResult, ResultStatus
│   ├── runner.py                 # EmulationRunner — dispatches to technique modules
│   └── tasks.py                  # Celery task definitions
├── techniques/                   # Technique library (ATT&CK-mapped)
│   ├── base.py                   # Technique ABC + Scope + TechniqueContext
│   ├── registry.py               # TECHNIQUE_REGISTRY — id → Technique class map
│   ├── discovery/                # TA0007 Discovery + TA0043 Reconnaissance
│   │   ├── network_scan.py       # T1046, T1595.001 — nmap-based scanning
│   │   ├── ad_enum.py            # T1087, T1069, T1482 — LDAP enumeration
│   │   ├── service_enum.py       # T1046 — service banner grabbing
│   │   └── cloud_enum.py         # T1087.004, T1069.003, T1526 — Entra/Okta/AWS
│   ├── phishing/                 # TA0001 Initial Access (phishing subtechniques)
│   │   ├── base.py               # GoPhish API client wrapper
│   │   ├── spearphishing_link.py # T1566.002 — link-based campaign via GoPhish
│   │   ├── spearphishing_attachment.py  # T1566.001 — attachment campaign
│   │   └── mfa_phishing.py       # T1566 + adversary-in-the-middle MFA capture
│   ├── identity/                 # TA0006 Credential Access + TA0001 Valid Accounts
│   │   ├── base.py               # Identity provider client base (Entra, Okta, AD)
│   │   ├── password_spray.py     # T1110.003 — controlled spray against test accounts
│   │   ├── credential_stuffing.py # T1110.004 — test credential list replay
│   │   ├── mfa_fatigue.py        # T1621 — MFA push bombing simulation
│   │   ├── oauth_abuse.py        # T1528 — OAuth consent phishing via GoPhish
│   │   └── token_theft.py        # T1539 — session token pattern detection
│   └── exploitation/             # Phase 2 — controlled offensive techniques
│       └── README.md             # Per-technique design review checklist
├── engagement/                   # Phase 2 gate, token, kill switch, runner
│   ├── gate.py                   # EngagementGate — three-factor authorization check
│   ├── token.py                  # EngagementToken — time-bounded Redis-backed token
│   ├── kill_switch.py            # KillSwitch — Redis fast path + Postgres durable record
│   └── runner.py                 # EngagementRunner — EmulationRunner + gate/kill re-check
├── feedback/                     # Closed-loop intelligence feedback
│   ├── gap_reporter.py           # Converts gaps → STIX Notes pushed back to GNAT
│   └── probe_generator.py        # Uses GNAT's LLMClient to suggest follow-on probes
├── reports/                      # Reporting (wraps gnat.reports)
│   └── cart_report.py            # CART-specific PDF/DOCX report generator
├── plugins/                      # GNAT integration plugin
│   └── gnat_plugin.py            # ConnectorMixin — bidirectional GNAT integration
└── api/                          # FastAPI REST management interface
    ├── app.py                    # Application factory
    └── routes/
        ├── scenarios.py          # GET/POST /scenarios
        ├── runs.py               # GET/POST /runs, GET /runs/{id}
        ├── intel.py              # GET /intel/feeds, POST /intel/trigger, POST /intel/probe-request
        └── stix.py               # STIX export for GNAT connector pull

migrations/                       # Forward-only SQL migrations (never edit applied)
│   001_initial_schema.sql        # Core tables

tests/
├── conftest.py                   # Shared fixtures
└── unit/
    ├── intake/                   # Normalizer + subscriber unit tests
    ├── scenarios/                # Builder + TTP mapper tests
    ├── emulation/                # Runner + plan tests
    └── techniques/               # Per-technique unit tests (offline, mocked)

config/
└── config.ini.example            # Configuration template

Makefile                          # Dev targets (test, lint, fmt, typecheck, docker)
pyproject.toml                    # Build config, deps, tool configs
```

---

## Development Workflow

### Setup

```bash
python -m venv .venv && source .venv/bin/activate
make install        # pip install -e ".[dev]"
```

### Make Targets

| Target | Description |
|--------|-------------|
| `make test` | Run unit tests (pytest tests/unit/) |
| `make coverage` | pytest + coverage HTML report |
| `make lint` | ruff check + format check |
| `make fmt` | ruff format |
| `make typecheck` | mypy |
| `make check` | lint + typecheck |
| `make worker` | Start Celery worker |
| `make api` | Start FastAPI server (uvicorn) |
| `make docker-up` | Start Postgres + Redis (docker compose) |
| `make docker-down` | Stop services |
| `make migrate` | Apply pending SQL migrations |

### Configuration

RedGNAT uses INI-based configuration (same pattern as GNAT). Search order:
1. `REDGNAT_CONFIG` environment variable (path to file)
2. `~/.redgnat/config.ini`
3. `./redgnat.ini`

Key sections:

```ini
[redgnat]
db_url = postgresql://redgnat:secret@localhost:5432/redgnat
redis_url = redis://localhost:6379/0
dry_run = false

[gnat]
config_path = /path/to/gnat.ini   # Path to GNAT config file
poll_interval_seconds = 300        # How often to poll GNAT for new intel

[sandgnat]
base_url = http://sandgnat-host:5000
api_key = SANDGNAT_API_KEY
poll_interval_seconds = 120

[gophish]
base_url = https://gophish.example.com:3333
api_key = GOPHISH_API_KEY
sending_profile_id = 1
landing_page_base_url = https://redir.example.com

[scope]
# Safe-harbor: ALL techniques validate against this before acting
target_ranges = 10.0.0.0/8,172.16.0.0/12
excluded_ranges = 10.0.0.1/32
target_domains = example.com,corp.example.com
target_accounts = redteam-test@example.com,pentest-user@example.com
max_rate_per_minute = 30

[entra]
tenant_id = <azure-tenant-id>
client_id = <app-client-id>
client_secret = <app-client-secret>

[okta]
base_url = https://example.okta.com
api_token = <okta-api-token>

[ldap]
server = ldap://dc.example.com
bind_dn = CN=redgnat-svc,OU=ServiceAccounts,DC=example,DC=com
bind_password = <service-account-password>
base_dn = DC=example,DC=com
```

---

## Code Conventions

- **Style/linter:** Ruff (same config as GNAT)
- **Type checking:** mypy at Python 3.11 target
- **Docstrings:** NumPy-style on all public classes and methods
- **Imports:** stdlib → third-party → local
- **Error handling:** Never bare `except Exception`; raise `RedGNATError` for top-level failures
- **No `requests`:** Use `urllib3` (sync) or `httpx` (async) matching GNAT conventions

Always run `make fmt && make lint` before committing.

---

## Key Architecture Decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Intel intake | Poll-based (Celery beat) | Decoupled from GNAT's push cadence |
| Scenario storage | PostgreSQL (psycopg3) | Consistent with SandGNAT, supports JSONB for STIX |
| Emulation dispatch | Celery tasks | Async, retryable, rate-limited |
| Technique interface | ABC with `Scope` guard | Every technique must validate scope before acting |
| Phishing campaigns | GoPhish REST API | Industry-standard, audit trail, template library |
| Identity attacks | Direct IdP APIs (Entra/Okta/LDAP) | Authentic emulation; scoped to test accounts only |
| Results format | STIX 2.1 Course-of-Action | Native push-back into GNAT |
| GNAT integration | Thin `ConnectorMixin` plugin | GNAT pulls results; no GNAT internals modified |
| Config | INI (configparser) | Matches GNAT convention, zero extra deps |

---

## Safe Harbor Controls (Non-Negotiable)

Every technique module **must** enforce these before any network activity:

1. **Scope check** — `Scope.allows_ip()`, `Scope.allows_domain()`, `Scope.allows_account()` gate every target
2. **Dry-run mode** — when `scope.dry_run = True`, techniques log what they *would* do and return `ResultStatus.DRY_RUN`
3. **Rate limiting** — all techniques respect `scope.max_rate_per_minute`; identity techniques add random jitter
4. **Test-account-only** — password spray, MFA fatigue, credential stuffing ONLY target accounts explicitly listed in `scope.target_accounts`
5. **Phase flag** — `Technique.emulation_only = True` is the default for all Phase 1 techniques (observe, probe, enumerate — no exploitation). Phase 2 exploitation techniques set this to `False` only after explicit design review and with additional safety controls.

Controls 1–4 are invariant across all phases. Control 5 relaxes in Phase 2 for designated exploitation techniques only.
The scope guard lives in `redgnat/techniques/base.py:Technique._check_scope()`.

---

## Technique Library

### Discovery (TA0007 / TA0043)

| Module | ATT&CK ID | Description |
|--------|-----------|-------------|
| `discovery/network_scan.py` | T1046, T1595.001 | nmap-based port + service discovery |
| `discovery/ad_enum.py` | T1087.002, T1069.002, T1482 | LDAP user/group/trust enumeration |
| `discovery/service_enum.py` | T1046 | Banner grabbing, service fingerprinting |
| `discovery/cloud_enum.py` | T1087.004, T1069.003, T1526 | Entra/Okta/AWS identity + resource enum |

### Phishing (TA0001)

| Module | ATT&CK ID | Description |
|--------|-----------|-------------|
| `phishing/spearphishing_link.py` | T1566.002 | Link campaign via GoPhish |
| `phishing/spearphishing_attachment.py` | T1566.001 | Attachment campaign via GoPhish |
| `phishing/mfa_phishing.py` | T1566 + T1621 | AiTM-style credential + OTP harvest page |

### Identity (TA0006 / TA0001)

| Module | ATT&CK ID | Description |
|--------|-----------|-------------|
| `identity/password_spray.py` | T1110.003 | Controlled spray against Entra/Okta/AD |
| `identity/credential_stuffing.py` | T1110.004 | Test credential replay against IdPs |
| `identity/mfa_fatigue.py` | T1621 | Push-bomb enrolled test users |
| `identity/oauth_abuse.py` | T1528 | OAuth consent phishing via GoPhish |
| `identity/token_theft.py` | T1539 | Session cookie pattern detection |

---

## Adding a New Technique

1. Create `redgnat/techniques/<tactic>/<name>.py`
2. Subclass `Technique` from `redgnat.techniques.base`
3. Set class attributes: `technique_id`, `tactic`, `name`, `emulation_only = True`
4. Implement `execute(ctx: TechniqueContext) -> TechniqueResult`
5. Call `self._check_scope(ctx.scope, target)` before **any** network activity
6. In dry-run mode, return `self._make_result(..., status=ResultStatus.DRY_RUN, ...)`
7. Register in `redgnat/techniques/registry.py` (`TECHNIQUE_REGISTRY[technique_id] = MyTechnique`)
8. Add unit tests in `tests/unit/techniques/test_<name>.py` — mock all external calls

---

## Intel → Scenario → Run → Feedback Data Flow

```
GNAT campaign STIX bundle          ProbeRequest from GNAT AI agent
       │                                     │
       ▼                                     ▼
intake/gnat_subscriber.py          api/routes/intel.py (POST /intel/probe-request)
       │  polls GNATClient                   │
       │  list_objects("campaign")           │ direct API inject
       │                                     │
       ▼                                     ▼
intake/normalizer.py ◄────────── feedback/probe_generator.py
       │  maps STIX Campaign +                  (merges AI-generated probe specs
       │  AttackPattern → IntelFeed              with scope + technique registry)
       │
       ▼
scenarios/builder.py
       │  ttp_mapper resolves ATT&CK IDs → registered Technique classes
       │  builds ordered EmulationPlan
       │
       ▼
emulation/tasks.py (Celery)
       │  EmulationRunner.run(plan, scope)
       │  dispatches each Technique.execute(ctx)
       │
       ▼
emulation/result.py
       │  RunResult (aggregates TechniqueResults)
       │
       ├──► scenarios/store.py ──────► PostgreSQL
       │
       ├──► plugins/gnat_plugin.py
       │      converts results → STIX CourseOfAction + Sighting
       │      available via GNAT connector pull (GET /api/v1/stix/results)
       │
       ├──► feedback/gap_reporter.py
       │      identifies SUCCESS results (= undetected techniques)
       │      pushes STIX Note objects back to GNAT as intelligence requirements
       │      ("T1110.003 succeeded — need: lockout policy intel, Okta risk signal check")
       │
       └──► feedback/probe_generator.py
              calls GNAT's LLMClient (Claude backend) with gap context
              suggests follow-on techniques + refined parameters
              emits ProbeRequest objects → queued for next intake cycle
              ▼
        reports/cart_report.py
               ATT&CK matrix coverage map + gap analysis
               └──► PDF / DOCX report
```

---

## Bidirectional GNAT Integration

### GNAT → RedGNAT (intel + probe requests)

The existing `intake/gnat_subscriber.py` polls GNAT campaigns and TTPs.
In addition, GNAT's AI agents can inject targeted **ProbeRequests** directly:

```python
# GNAT side: agent generates a probe request after analyzing a gap report
from gnat.agents import LLMClient
# ... agent analyzes STIX Note gap → produces ProbeRequest JSON
# GNAT POSTs it to RedGNAT's intake API:
POST /api/v1/intel/probe-request
{
  "technique_ids": ["T1621", "T1110.004"],
  "context": "Password spray succeeded on Okta without lockout. Test MFA fatigue and stuffing.",
  "source": "gnat_agent",
  "priority": "high"
}
```

### RedGNAT → GNAT (results + gap intelligence)

RedGNAT registers as a thin GNAT connector via `redgnat.plugins.gnat_plugin.RedGNATConnector`.
GNAT operators add it to pull emulation results and gap intelligence:

```python
from gnat import GNATClient
from redgnat.plugins.gnat_plugin import RedGNATConnector

client = GNATClient(config_path="gnat.ini")
connector = RedGNATConnector(base_url="http://redgnat-host:8000", api_key="...")
results = connector.list_objects("course-of-action")  # emulation run summaries
sightings = connector.list_objects("sighting")        # per-technique STIX sightings
gaps = connector.list_objects("note")                 # gap intelligence requirements
```

RedGNAT exposes:
- `GET /api/v1/stix/results` — run results as STIX CoA objects
- `GET /api/v1/stix/results/{run_id}` — single run result
- `GET /api/v1/stix/sightings` — technique-level STIX Sighting objects
- `GET /api/v1/stix/gaps` — STIX Note objects (gap intelligence requirements for GNAT)
- `POST /api/v1/intel/probe-request` — GNAT agents inject targeted probe specs

### The Feedback Loop in Practice

1. RedGNAT executes a password spray (T1110.003) → no lockout triggered → `ResultStatus.SUCCESS`
2. `feedback/gap_reporter.py` creates a STIX Note: *"T1110.003 undetected. Need: Okta lockout policy,
   smart lockout threshold, Entra ID Protection risk signal for spray patterns."*
3. GNAT ingests the Note → enriches with Okta connector + Silverfort connector
4. GNAT's `LLMClient` (Claude) reads the enriched Note + gap context →
   suggests `ProbeRequest(technique_ids=["T1621"], context="No lockout on spray — test MFA fatigue")`
5. ProbeRequest is POSTed to `POST /api/v1/intel/probe-request`
6. RedGNAT queues the follow-on emulation → executes MFA fatigue → reports back
7. Repeat until coverage converges

---

## ORM Models

| Model | Purpose |
|-------|---------|
| `IntelFeed` | Tracks a GNAT/SandGNAT intel source record (STIX bundle ref + metadata) |
| `EmulationScenario` | A named scenario built from intel (ATT&CK techniques, scope, targets) |
| `EmulationRun` | One execution of a scenario (timestamps, Celery task ID, status) |
| `TechniqueResult` | Per-technique outcome within a run (findings, evidence, STIX sighting) |

All models implement `to_dict()` / `from_dict()` and `to_stix()` for CoA/Sighting export.

---

## Database Schema

All persistence goes through `scenarios/store.py`. Never scatter SQL across modules.

Tables:
- `intel_feeds` — ingested intel records (GNAT campaigns, SandGNAT analyses)
- `emulation_scenarios` — built scenarios with JSONB technique list + scope
- `emulation_runs` — run records with status tracking
- `technique_results` — per-technique outcomes with JSONB findings + evidence

Migration files in `migrations/` are forward-only numbered SQL (same convention as SandGNAT).

---

## Testing Conventions

- All technique tests run **offline** — mock every network call (nmap, LDAP, HTTP)
- `tests/conftest.py` provides: `mock_scope()`, `mock_ctx()`, `minimal_config()`
- Minimum coverage: **70%** (enforced in pyproject.toml)
- Test markers: `@pytest.mark.integration` (real IdP/network), `@pytest.mark.slow`

```bash
pytest tests/unit/ -v --tb=short        # All unit tests
pytest tests/unit/techniques/ -v        # Technique tests only
pytest tests/integration/ --run-integration -v  # Requires live creds
```

---

## Git & Branch Conventions

Matches GNAT conventions:
- **`main`** — stable
- **Feature branches** — `claude/<description>-<id>` or `feature/<name>`
- Commit messages: imperative mood
- Keep `CHANGELOG.md` under `[Unreleased]` updated

---

## What NOT to Do

- Do not add `requests` — use `urllib3` or `httpx`
- Do not introduce Pydantic or SQLAlchemy — use the dataclass ORM pattern
- Do not add Phase 2 exploitation techniques without a design review and `emulation_only = False` set deliberately — the flag has meaning; don't flip it casually
- Do not bypass `Scope` checks — every technique **must** call `_check_scope()` first, in both Phase 1 and Phase 2
- Do not target accounts not listed in `scope.target_accounts` for credential attacks
- Do not commit real credentials — only example values in `config/config.ini.example`
- Do not scatter SQL — all DB access goes through `scenarios/store.py`
- Do not modify GNAT source — integration is via the `ConnectorMixin` plugin and the `/api/v1/intel/probe-request` intake endpoint only
- Do not call GNAT's LLMClient in hot paths (emulation runner) — keep AI calls in `feedback/probe_generator.py` which runs post-completion

---

*Licensed under the Apache License, Version 2.0*
