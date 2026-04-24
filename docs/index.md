---
layout: default
title: RedGNAT
description: Continuous Automated Readiness Testing addon for GNAT. Safe red teaming made simple.
---

<div style=”display: flex; align-items: center; gap: 2.5rem; margin-bottom: 2rem;”>
  <div style=”flex: 1; min-width: 0;”>
    <p style=”margin: 0 0 .35rem 0; font-size: .95rem; color: #606c71; text-transform: uppercase; letter-spacing: .06em;”>GNAT-o-sphere / readiness testing</p>
    <h1 style=”margin-top: 0;”>RedGNAT</h1>
    <p>Continuous Automated Readiness Testing (CART) addon for the <strong>GNAT-o-sphere</strong>: ingest live threat intelligence from GNAT and SandGNAT, build scoped adversary-emulation scenarios, execute them under layered safety controls, and feed detection gaps back into GNAT as structured intelligence requirements.</p>
    <p>Source: <a href=”https://github.com/wrhalpin/RedGNAT”><code>github.com/wrhalpin/RedGNAT</code></a>.</p>
  </div>
  <div style=”flex-shrink: 0;”>
    <img src=”assets/logo-256.png” alt=”RedGNAT logo” width=”288” style=”border-radius: 8px;”>
  </div>
</div>

---

## Documentation

Organised with the [Diátaxis](https://diataxis.fr/) framework. Four quadrants for four kinds of reader intent:

|  | **Action (doing)** | **Study (reading)** |
|---|---|---|
| **Learning** | [Tutorials](tutorials/README.md) | [Explanation](explanation/architecture/architecture.md) |
| **Working** | [How-to guides](how-to/README.md) | [Reference](reference/README.md) |

### Start here if you're…

- **New to RedGNAT** → [Getting started](tutorials/getting-started.md)
- **Adding a technique** → [How to add a technique](how-to/add-technique.md)
- **Connecting to GNAT** → [Configure GNAT integration](how-to/configure-gnat-integration.md)
- **Curious about the safety model** → [Safe-harbor design](explanation/engagement/safe-harbor.md)
- **Standing up production** → [Deploy with Docker](how-to/deploy-docker.md)

---

## What RedGNAT does, end to end

1. **Intake** — `GNATSubscriber` polls GNAT for new campaigns and TTPs; `SandGNATSubscriber` polls SandGNAT for fresh STIX behavioral bundles.
2. **Normalise** — `IntelNormalizer` maps STIX AttackPattern objects to registered `Technique` classes and builds an ordered `EmulationScenario`.
3. **Execute** — `EmulationRunner` dispatches each technique via Celery, enforcing scope, dry-run, and rate-limit controls at every step.
4. **Report gaps** — `GapReporter` converts undetected techniques into STIX 2.1 Note objects and pushes them back to GNAT as intelligence requirements.
5. **Generate probes** — `ProbeGenerator` calls GNAT's `LLMClient` (Claude) with gap context; suggests follow-on techniques as `ProbeRequest` objects.
6. **Repeat** — probe tasks re-enter the same pipeline, deepening coverage until detected or the runaway guard trips.

Full architecture diagrams and component breakdown in [explanation/architecture](explanation/architecture/architecture.md).

## Key design choices

- **Scope guard is non-negotiable.** Every technique calls `_check_scope()` before any network activity. Out-of-scope targets produce `BLOCKED` results, not errors. See [safe-harbor design](explanation/engagement/safe-harbor.md).
- **Phase 2 requires three independent factors.** Exploitation techniques need a config flag, a runtime env var, and a time-bounded Redis token — all simultaneously. See [Phase 2 activation](explanation/engagement/phase2-activation.md).
- **The feedback loop is the point.** A single-shot emulation run has limited value. The gap→probe→emulate cycle is what drives coverage convergence over time. See [feedback loop](explanation/automation/feedback-loop.md).
- **AI calls stay out of the hot path.** `ProbeGenerator` runs post-completion. A slow or unavailable LLM cannot block an active run.

## The GNAT-o-sphere

RedGNAT is one part of a family of standalone capabilities that extend GNAT without modifying it.

[Canonical workflow documentation →](https://wrhalpin.github.io/gnat-o-sphere/workflow.html)

<div class="gnatophere-grid">

  <div class="gnat-card gnat-card-gnat">
    <span class="gnat-card-tag">Core Platform</span>
    <h3>GNAT</h3>
    <p>The hub platform for threat intelligence. 159 connectors, STIX 2.1 modeling, AI agents, investigations, and workflow automation.</p>
    <a class="gnat-card-link gnat-link-gnat" href="https://wrhalpin.github.io/GNAT/">Learn more</a>
  </div>

  <div class="gnat-card gnat-card-sand">
    <span class="gnat-card-tag">Addon</span>
    <h3>SandGNAT</h3>
    <p>Automated malware sandbox — detonate binaries in isolated Windows VMs, capture behavioral artifacts, emit STIX 2.1 objects.</p>
    <a class="gnat-card-link gnat-link-sand" href="https://wrhalpin.github.io/SandGNAT/">Learn more</a>
  </div>

  <div class="gnat-card gnat-card-sense">
    <span class="gnat-card-tag">Addon</span>
    <h3>SenseGNAT</h3>
    <p>Behavior analytics companion — build per-entity baselines from network telemetry, run explainable detectors, push STIX 2.1 findings into GNAT.</p>
    <a class="gnat-card-link gnat-link-sense" href="https://wrhalpin.github.io/SenseGNAT/">Learn more</a>
  </div>

</div>

## Status

v0.1.0 — Phase 1 (emulation and probing) and Phase 2 engagement infrastructure shipped. See [releases/v0.1.0](releases/v0.1.0.md).

Licensed under [Apache 2.0](https://github.com/wrhalpin/RedGNAT/blob/main/LICENSE).
