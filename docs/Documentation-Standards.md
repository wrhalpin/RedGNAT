# Documentation Standards

RedGNAT documentation uses the [Diátaxis](https://diataxis.fr/) framework.

## Framework

| Type | Purpose | Question answered |
|------|---------|-------------------|
| Tutorial | Learning by doing | "Help me learn this" |
| How-to | Solving a task | "How do I accomplish X?" |
| Reference | Exact technical details | "What is the exact value/behaviour of X?" |
| Explanation | Design rationale | "Why does it work this way?" |

## Rules

1. Each document serves exactly one Diátaxis purpose — do not mix types in a single file.
2. Link between documents rather than duplicating content.
3. Reference documentation is the authoritative source for exact values (config keys, API endpoints, status codes).
4. Use Architecture Decision Records (ADRs) in `explanation/architecture/adrs/` for significant design choices.

## Directory layout

```
docs/
├── tutorials/      # Learning-oriented walkthroughs
├── how-to/         # Task-oriented recipes
├── reference/      # Technical reference material
├── explanation/
│   ├── architecture/   # System architecture + ADRs
│   ├── engagement/     # Safety model + Phase 2 design
│   └── automation/     # Feedback loop + AI-driven automation
└── releases/       # Per-version release notes
```

## Section README files

Each section directory contains a `README.md` that lists its contents in a table. Keep this index up to date when adding documents.

## Philosophy

Documentation should match user intent.

---

_Licensed under the Apache License, Version 2.0_
