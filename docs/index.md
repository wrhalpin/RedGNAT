# RedGNAT

![RedGNAT logo](assets/RedGNAT-logo.png)

**CART Addon for GNAT**  
**Safe Red Teaming Made Simple**

RedGNAT is the **continuous automated red teaming** module in the GNAT-o-sphere. It ingests intelligence from GNAT and SandGNAT, turns that intelligence into ATT&CK-mapped scenarios, executes those scenarios inside explicit scope and safety controls, and pushes the resulting gaps back into the wider platform.

## Why RedGNAT exists

A lot of red-team tooling is either too manual to sustain continuously, too detached from current intelligence to stay relevant, or too loosely controlled to fit a safer operating model.

RedGNAT is intended to be:
- **intelligence-led**
- **automation-friendly**
- **scope-aware**
- **phase-gated**
- **feedback-oriented**

## Documentation map

This documentation follows the **DiÃ¡taxis** framework.

| | **Action (doing)** | **Study (reading)** |
|—|—|—|
| **Learning** | [Tutorials](tutorials/) | [Explanation](explanation/) |
| **Working** | [How-to guides](how-to/) | [Reference](reference/) |

### Start here if you areâ€¦

- **new to RedGNAT** â†’ [Getting started](tutorials/getting-started.md)
- **adding or tuning techniques** â†’ [How-to guides](how-to/)
- **looking up config or API details** â†’ [Reference](reference/)
- **trying to understand the safety model** â†’ [Explanation](explanation/)

## Safety model

### Phase 1
Observation, enumeration, validation, phishing simulation, scoped probing, and other controlled techniques that do **not** cross into uncontrolled exploitation.

### Phase 2
Controlled exploitation paths that remain disabled until the explicit activation model is satisfied.

### Operational guards
- dry-run mode
- scope checks before target interaction
- rate limiting
- kill-switch capability
- design review before enabling new classes of technique

## System flow

1. GNAT and SandGNAT provide current intelligence.
2. RedGNAT builds scenarios from that intelligence.
3. Techniques run inside policy and scope boundaries.
4. Results are normalized into structured outputs.
5. Gaps flow back into GNAT as actionable follow-up work.

## Quick links

- [Getting started](tutorials/getting-started.md)
- [Add a new technique](how-to/add-technique.md)
- [Configure GNAT integration](how-to/configure-gnat-integration.md)
- [Configuration reference](reference/configuration.md)
- [API reference](reference/api.md)
- [Phase 2 activation](explanation/phase2-activation.md)