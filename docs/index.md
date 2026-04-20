# RedGNAT Documentation

RedGNAT is a **Continuous Automated Red Teaming (CART)** platform that ingests live threat intelligence from [GNAT](https://Wrhalpin.github.io/GNAT/) and [SandGNAT](https://wrhalpin.github.io/SandGNAT/), automatically builds adversary emulation scenarios, executes them against your environment, and feeds results back into GNAT as actionable intelligence requirements.

## Documentation map

This documentation follows the [Diataxis](https://diataxis.fr) framework — four distinct modes matched to what you need right now.

---

### [Tutorials](tutorials/getting-started.md) — learning by doing

Start here if you are new to RedGNAT.

| Guide | What you'll learn |
|-------|------------------|
| [Getting started](tutorials/getting-started.md) | Install, configure, and run your first emulation scenario end-to-end |

---

### [How-to guides](how-to/add-technique.md) — solving specific problems

Practical step-by-step guides for operators and developers.

| Guide | What you'll do |
|-------|---------------|
| [Add a new technique](how-to/add-technique.md) | Implement and register a new ATT&CK-mapped emulation technique |
| [Configure GNAT integration](how-to/configure-gnat-integration.md) | Set up bidirectional GNAT↔RedGNAT intel and results flow |
| [Deploy with Docker](how-to/deploy-docker.md) | Run RedGNAT in production with Docker Compose |

---

### [Reference](reference/configuration.md) — precise technical information

Complete specifications for operators, developers, and integrators.

| Reference | Contents |
|-----------|---------|
| [Configuration](reference/configuration.md) | Every INI key, its type, default, and effect |
| [REST API](reference/api.md) | All endpoints, request/response schemas, authentication |
| [Technique library](reference/techniques.md) | All ATT&CK techniques, their scope requirements, and result schema |

---

### [Explanation](explanation/architecture.md) — understanding the design

Background reading on why RedGNAT works the way it does.

| Article | What you'll understand |
|---------|----------------------|
| [Architecture](explanation/architecture.md) | System components, data flow, and integration boundaries |
| [Bidirectional feedback loop](explanation/feedback-loop.md) | How gaps become new attacks — the closed CART loop |
| [Safe-harbor design](explanation/safe-harbor.md) | Scope controls and the philosophy of responsible emulation |
