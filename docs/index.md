# RedGNAT

<div class="redgnat-hero">
  <img src="assets/logo-256.png" alt="RedGNAT logo" />
  <div class="redgnat-hero-text">
    <h1>RedGNAT</h1>
    <p class="tagline">Continuous Automated Red Teaming &mdash; CART Addon for GNAT</p>
  </div>
</div>

<div class="badge-strip">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" />
  <img alt="License Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-green" />
  <img alt="MITRE ATT&CK" src="https://img.shields.io/badge/MITRE-ATT%26CK-red" />
  <img alt="Phase 1" src="https://img.shields.io/badge/phase-1%20emulation-orange" />
</div>

RedGNAT ingests live threat intelligence from **GNAT** and **SandGNAT**, automatically builds
adversary emulation scenarios mapped to MITRE ATT&CK, executes them against your environment,
and feeds results back as actionable intelligence requirements — closing the CART loop continuously.

---

## Documentation map

This documentation follows the [Diataxis](https://diataxis.fr) framework.
Pick the quadrant that matches what you need right now.

<div class="diataxis-grid">
  <a class="diataxis-card" href="tutorials/getting-started/">
    <h3>📖 Tutorials</h3>
    <p>Learning-oriented. Start here if you are new to RedGNAT — install, configure, and run your first scenario end-to-end.</p>
  </a>
  <a class="diataxis-card" href="how-to/add-technique/">
    <h3>🛠 How-to Guides</h3>
    <p>Task-oriented. Step-by-step guides for adding techniques, wiring GNAT integration, and deploying to production.</p>
  </a>
  <a class="diataxis-card" href="reference/configuration/">
    <h3>📐 Reference</h3>
    <p>Information-oriented. Every configuration key, REST endpoint, and technique parameter — precise and complete.</p>
  </a>
  <a class="diataxis-card" href="explanation/architecture/">
    <h3>💡 Explanation</h3>
    <p>Understanding-oriented. Architecture decisions, the feedback loop, safe-harbor design, and Phase 2 activation model.</p>
  </a>
</div>

---

## Quick links

| I want to… | Go to |
|------------|-------|
| Install and run my first scenario | [Getting started](tutorials/getting-started.md) |
| Add a new ATT&CK technique | [Add a technique](how-to/add-technique.md) |
| Wire up GNAT ↔ RedGNAT | [Configure GNAT integration](how-to/configure-gnat-integration.md) |
| See all config keys | [Configuration reference](reference/configuration.md) |
| Understand the kill switch | [Phase 2 activation](explanation/phase2-activation.md) |
| Browse the REST API | [API reference](reference/api.md) |

---

## What RedGNAT does

```mermaid
flowchart LR
    G([GNAT\n158+ connectors]) -->|campaign STIX| I[intake/]
    S([SandGNAT\ndetonation sandbox]) -->|behavioral STIX| I
    I --> B[scenarios/\nbuilder]
    B --> E[emulation/\nrunner]
    E --> T[techniques/\ndiscovery · phishing · identity]
    T -->|TechniqueResult| F[feedback/\ngap_reporter]
    F -->|STIX Notes| G
    F -->|ProbeRequests| I
```

**Phase 1 (current):** emulation and probing — observe, enumerate, phish, spray. Never exploit.

**Phase 2 (planned):** controlled exploitation with three-factor authorization and a global kill switch.
