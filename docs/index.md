# RedGNAT

**CART Addon for GNAT**  
**Safe Red Teaming Made Simple**

RedGNAT is the controlled adversary-emulation arm of the **GNAT-o-sphere**. It ingests intelligence from GNAT and SandGNAT, turns that intelligence into scoped emulation scenarios, executes them under explicit safety controls, and feeds the resulting gaps back into GNAT as follow-up work.

## Why RedGNAT exists

A lot of red-team tooling is either:
- too manual to sustain continuously,
- too detached from current intelligence to stay relevant,
- or too loosely controlled to fit a safer operating model.

RedGNAT is intended to sit in the middle:
- intelligence-led
- automation-friendly
- scope-aware
- phase-gated
- feedback-oriented

## Documentation

RedGNAT documentation is organized using **[Diátaxis](https://diataxis.fr/)**:

- **[Tutorials](tutorials/README.md)** — get running safely
- **[How-to guides](how-to/README.md)** — perform concrete operating tasks
- **[Reference](reference/README.md)** — exact configuration and API behavior
- **[Explanation](explanation/architecture/architecture.md)** — safety model, phase model, and architecture

## In the GNAT-o-sphere

- **GNAT** supplies core intelligence and integration patterns
- **SandGNAT** supplies malware-analysis output
- **RedGNAT** turns those inputs into scoped adversary-emulation workflows

## License

Apache 2.0.
