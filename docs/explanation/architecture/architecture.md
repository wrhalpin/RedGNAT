# Architecture

RedGNAT sits between three systems: GNAT (threat intelligence platform), SandGNAT (malware sandbox), and the defender's enterprise environment. Its job is to translate live threat intelligence into emulation runs, execute them safely, and return results back to GNAT as structured intelligence.

---

## System context

```mermaid
graph TB
    subgraph GNAT["GNAT — Threat Intelligence Platform"]
        GC[GNATClient<br/>158+ connectors]
        AI[LLMClient<br/>Claude / GPT]
        GC <-->|campaigns · TTPs| AI
    end

    subgraph SandGNAT["SandGNAT — Malware Sandbox"]
        DET[Detonation Engine<br/>Proxmox VMs]
        EXP[Export API<br/>/analyses]
        DET --> EXP
    end

    subgraph RedGNAT["RedGNAT — CART Platform"]
        INT[Intake<br/>gnat_subscriber<br/>sandgnat_subscriber]
        SCN[Scenarios<br/>builder · store]
        EMU[Emulation<br/>runner · tasks]
        TEC[Techniques<br/>discovery · phishing · identity · exploitation]
        FBK[Feedback<br/>gap_reporter · probe_generator]
        API[REST API<br/>FastAPI :8000]

        INT --> SCN --> EMU --> TEC
        TEC --> EMU
        EMU --> FBK
        FBK --> API
        API --> INT
    end

    subgraph Enterprise["Enterprise Environment"]
        NET[Network targets]
        IDP[Identity providers<br/>Entra ID · Okta · AD]
        MAIL[Email targets<br/>GoPhish campaigns]
    end

    GC -->|"campaigns · attack patterns"| INT
    EXP -->|"STIX behavioral bundles"| INT
    AI -->|"ProbeRequests"| API

    TEC -->|"port scans · enum"| NET
    TEC -->|"credential tests"| IDP
    TEC -->|"phishing campaigns"| MAIL

    FBK -->|"STIX CoA · Sightings · Gap Notes"| GC
    API -->|"STIX results via connector"| GC
```

---

## Component overview

### Intake layer

`redgnat/intake/` has two subscribers that poll their respective sources on a Celery beat schedule:

- **`GNATSubscriber`** — polls `GNATClient.list_objects("campaign")`, fetches associated `attack-pattern` objects, extracts ATT&CK IDs from `external_references`, and filters by `min_confidence`
- **`SandGNATSubscriber`** — polls SandGNAT's `/analyses` endpoint, fetches full STIX bundles, and filters to emulatable technique families

Both subscribers produce `IntelFeed` records, which `IntelNormalizer` converts into `EmulationScenario` objects.

**`IntelNormalizer`** maps ATT&CK IDs to registered `Technique` classes, deduplicates, and sorts by kill-chain order (reconnaissance → initial-access → credential-access).

### Scenario layer

`redgnat/scenarios/` manages:

- **`ScenarioBuilder`** — builds an `EmulationPlan` from a scenario: resolves technique classes from the registry, applies scope from config, creates ordered `PlannedStep` objects
- **`ScenarioStore`** — all SQL in one module; upserts are idempotent so re-ingesting the same campaign is safe
- **`TTPMapper`** — static ATT&CK metadata (name, tactic, description) for 30+ techniques

### Emulation layer

`redgnat/emulation/` drives execution:

```mermaid
sequenceDiagram
    participant Beat as Celery Beat
    participant Task as run_scenario_task
    participant Runner as EmulationRunner
    participant Technique as Technique.execute()
    participant Store as ScenarioStore
    participant Feedback as _run_feedback()

    Beat->>Task: ingest_intel_task()
    Task->>Store: upsert_scenario()
    Task->>Task: run_scenario_task.delay(run_id)

    Task->>Runner: execute(run, scenario)
    Runner->>Store: mark run RUNNING
    loop Each PlannedStep
        Runner->>Technique: execute(ctx)
        Technique-->>Runner: TechniqueResult
        Runner->>Store: insert_result()
        Runner->>Runner: _inter_technique_pause()
    end
    Runner->>Store: mark run COMPLETED
    Runner-->>Task: list[TechniqueResult]

    Task->>Feedback: _run_feedback(results)
    Feedback->>Feedback: GapReporter.build_report()
    Feedback->>Feedback: push_to_gnat()
    Feedback->>Feedback: ProbeGenerator.generate()
    Feedback->>Task: run_probe_task.delay(probe)
```

### Technique layer

`redgnat/techniques/` implements the ATT&CK technique library across four categories:

| Directory | Tactics | Runner required |
|-----------|---------|----------------|
| `discovery/` | TA0007, TA0043 | `EmulationRunner` |
| `phishing/` | TA0001 | `EmulationRunner` |
| `identity/` | TA0006 | `EmulationRunner` |
| `exploitation/` | various | `EngagementRunner` (Phase 2 only) |

Every technique follows the same contract enforced by the `Technique` abstract base class:

1. Check `scope.dry_run` first → return `DRY_RUN` immediately if true
2. Validate every target with `_check_scope_*()` before touching it
3. Call `_rate_sleep()` before each network request
4. Return a `TechniqueResult` with structured findings

Phase 2 exploitation techniques additionally require `emulation_only = False`, pass through the three-factor `EngagementGate`, and have their execution interleaved with kill-switch and token-expiry checks via `EngagementRunner`.

### Feedback layer

`redgnat/feedback/` closes the loop:

- **`GapReporter`** — identifies `SUCCESS` results (= undetected), builds `GapReport`, serialises to STIX 2.1 Note with per-technique GNAT enrichment hints, pushes to GNAT
- **`ProbeGenerator`** — calls `gnat.agents.LLMClient` with gap context; parses the LLM's JSON suggestions into `ProbeRequest` objects; falls back to a static rule table if the LLM is unavailable

### API layer

`redgnat/api/` exposes two audiences:

| Audience | Endpoints |
|----------|-----------|
| Operators (human) | `GET/POST /scenarios`, `GET/POST /runs`, `POST /intel/ingest`, `GET /intel/techniques` |
| Engagement control | `GET /engage/status`, `POST /engage/authorize`, `POST /engage/kill`, `DELETE /engage/kill` |
| GNAT connector (machine) | `GET /stix/results`, `GET /stix/sightings`, `GET /stix/gaps` |
| GNAT AI agents (machine) | `POST /intel/probe-request` |

---

## Data model

```mermaid
erDiagram
    IntelFeed {
        uuid feed_id PK
        string source
        string source_ref_id
        json stix_bundle
        string campaign_name
        json attack_pattern_ids
        float confidence
        datetime ingested_at
    }

    EmulationScenario {
        uuid scenario_id PK
        uuid feed_id FK
        string name
        string description
        json technique_ids
        json scope_overrides
        string status
        datetime created_at
    }

    EmulationRun {
        uuid run_id PK
        uuid scenario_id FK
        string celery_task_id
        string status
        string triggered_by
        datetime started_at
        datetime completed_at
    }

    TechniqueResult {
        uuid result_id PK
        uuid run_id FK
        uuid scenario_id FK
        string technique_id
        string tactic
        string status
        json findings
        json evidence
        string error
        datetime executed_at
    }

    IntelFeed ||--o{ EmulationScenario : "produces"
    EmulationScenario ||--o{ EmulationRun : "executed as"
    EmulationRun ||--o{ TechniqueResult : "contains"
```

---

## Technology choices

| Decision | Choice | Reason |
|----------|--------|--------|
| Config format | INI (`configparser`) | Matches GNAT / SandGNAT convention; zero extra dependencies |
| Database | PostgreSQL + psycopg3 | JSONB for STIX bundles and findings; same choice as SandGNAT |
| All SQL in one module | `scenarios/store.py` | Prevents SQL scattered across the codebase |
| Task queue | Celery + Redis | Async, retryable, rate-limited; beat scheduler drives periodic polling |
| HTTP | `urllib.request` / `urllib3` | Matches GNAT's no-`requests` convention |
| Serialisation | STIX 2.1 dicts | Native GNAT ORM format; no additional translation layer |
| GNAT integration | `ConnectorMixin` plugin + PyPI entry point | GNAT discovers the connector automatically; no GNAT source modifications |
| AI calls | `gnat.agents.LLMClient` | Reuses GNAT's existing LLM infrastructure; supports Claude, GPT, and Grok backends |
