---
layout: default
title: Add a Technique
description: Add and register a new ATT&CK-mapped technique in RedGNAT.
---

# How to add a new emulation technique

This guide walks through adding a new ATT&CK-mapped technique to RedGNAT's library. After completing it the technique will be discovered, scoped, executed, and reported automatically alongside existing ones.

**You'll need:** Python 3.11+, a development install of RedGNAT (`pip install -e ".[dev]"`).

---

## 1 — Create the module file

Technique modules live under `redgnat/techniques/<tactic>/`. Choose the right tactic directory or create one:

| ATT&CK Tactic | Directory |
|--------------|-----------|
| Discovery / Reconnaissance | `redgnat/techniques/discovery/` |
| Initial Access (phishing) | `redgnat/techniques/phishing/` |
| Credential Access / Identity | `redgnat/techniques/identity/` |
| Exploitation (Phase 2 only) | `redgnat/techniques/exploitation/` |

Create your file. Example: implementing T1135 (Network Share Discovery):

```bash
touch redgnat/techniques/discovery/network_shares.py
```

---

## 2 — Implement the Technique class

Every technique follows the same pattern:

```python
"""T1135 — Network Share Discovery via SMB enumeration."""
from __future__ import annotations

from redgnat.techniques.base import Technique, TechniqueContext
from redgnat.orm.models import ResultStatus, TechniqueResult


class NetworkSharesTechnique(Technique):
    technique_id = "T1135"
    tactic = "discovery"
    name = "Network Share Discovery"
    emulation_only = True  # Phase 1 default — observe, do not exploit

    def execute(self, ctx: TechniqueContext) -> TechniqueResult:
        # 1. Dry-run guard — MUST be first
        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would enumerate SMB shares on {ctx.scope.target_ranges}",
            )

        findings = []
        errors = []

        for cidr in ctx.scope.target_ranges:
            # 2. Scope check — validates BEFORE any network activity
            if not ctx.scope.allows_cidr(cidr):
                continue

            try:
                self._rate_sleep(ctx.scope)
                shares = self._enumerate_shares(cidr, ctx.params)
                if shares:
                    findings.append({"cidr": cidr, "shares": shares})
            except Exception as exc:
                errors.append(str(exc))

        status = ResultStatus.SUCCESS if findings else ResultStatus.PARTIAL
        return self._make_result(
            ctx,
            status=status,
            findings=findings,
            error="; ".join(errors) if errors else None,
        )

    def _enumerate_shares(self, cidr: str, params: dict) -> list[dict]:
        # Your enumeration logic here.
        # Use stdlib or an approved library (no `requests`).
        # Keep all calls read-only.
        return []
```

### Rules you must follow

| Rule | Why |
|------|-----|
| Check `ctx.scope.dry_run` first, return `_dry_run_result()` | Enables safe testing without any network activity |
| Call `_check_scope_ip/domain/account()` or `allows_*()` before touching each target | Every target is validated; out-of-scope targets raise `OutOfScopeError` or are silently skipped |
| Call `_rate_sleep(ctx.scope)` before each network request | Respects `max_rate_per_minute` |
| Keep `emulation_only = True` (Phase 1) | Techniques in Phase 1 observe and enumerate; they do not deliver payloads or modify state |
| Return a `TechniqueResult` from `_make_result()` always | Structured results feed the gap reporter and STIX export |
| Mock all external calls in unit tests | Technique tests must run offline |

---

## 3 — Register the technique

Open `redgnat/techniques/registry.py` and add your class:

```python
from redgnat.techniques.discovery.network_shares import NetworkSharesTechnique

TECHNIQUE_REGISTRY: dict[str, Type[Technique]] = {
    # ... existing entries ...
    "T1135": NetworkSharesTechnique,
}
```

---

## 4 — Add ATT&CK metadata to the TTP mapper

Open `redgnat/scenarios/ttp_mapper.py` and add an entry to `_TECHNIQUE_MAP`:

```python
"T1135": TechniqueInfo(
    technique_id="T1135",
    name="Network Share Discovery",
    tactic="discovery",
    description="Enumerate network shares accessible from the current context.",
),
```

This entry is used by the normalizer (to include the technique in scenarios built from intel), the gap reporter (to name techniques in STIX Notes), and the CART report (for the ATT&CK coverage matrix).

---

## 5 — Add a GNAT intel ask (optional but recommended)

If a defender should know what GNAT intel to collect when this technique goes undetected, add it to `redgnat/feedback/gap_reporter.py`:

```python
_INTEL_ASKS: dict[str, str] = {
    # ... existing entries ...
    "T1135": (
        "Check SMB share audit events in Sentinel/Splunk. "
        "Review DFS namespace access logs. "
        "Verify net share enumeration detection rule in SIEM."
    ),
}
```

---

## 6 — Write unit tests

Create `tests/unit/techniques/test_network_shares.py`. All external calls must be mocked:

```python
"""Unit tests for NetworkSharesTechnique (offline — all network calls mocked)."""
from unittest.mock import patch

import pytest

from redgnat.techniques.discovery.network_shares import NetworkSharesTechnique
from redgnat.orm.models import ResultStatus


def test_dry_run_returns_dry_run_status(mock_ctx):
    mock_ctx.scope.dry_run = True
    result = NetworkSharesTechnique().execute(mock_ctx)
    assert result.status == ResultStatus.DRY_RUN


def test_out_of_scope_cidr_skipped(mock_ctx):
    mock_ctx.scope.target_ranges = ["192.168.0.0/24"]
    mock_ctx.scope.dry_run = False
    with patch.object(NetworkSharesTechnique, "_enumerate_shares", return_value=[]):
        result = NetworkSharesTechnique().execute(mock_ctx)
    # No findings but no error — silently skipped out-of-scope target
    assert result.status in {ResultStatus.PARTIAL, ResultStatus.SUCCESS}


def test_findings_on_success(mock_ctx):
    mock_ctx.scope.dry_run = False
    fake_shares = [{"host": "10.0.0.5", "share": "SYSVOL"}]
    with patch.object(NetworkSharesTechnique, "_enumerate_shares", return_value=fake_shares):
        result = NetworkSharesTechnique().execute(mock_ctx)
    assert result.status == ResultStatus.SUCCESS
    assert len(result.findings) > 0
```

The `mock_ctx` fixture is provided by `tests/conftest.py` — it returns a `TechniqueContext` with a pre-configured `Scope` that includes `10.0.0.0/8` in scope.

Run the tests:

```bash
pytest tests/unit/techniques/test_network_shares.py -v
```

---

## 7 — Verify end-to-end in dry-run mode

The parametrized dry-run safety test in `tests/unit/techniques/test_dry_run.py` automatically picks up every technique in `TECHNIQUE_REGISTRY` and asserts it returns `DRY_RUN` status when `scope.dry_run = True`. Run it to confirm your technique is wired correctly:

```bash
pytest tests/unit/techniques/test_dry_run.py -v -k T1135
```

---

## Summary

| Step | File touched |
|------|-------------|
| Create technique module | `redgnat/techniques/<tactic>/<name>.py` |
| Register technique | `redgnat/techniques/registry.py` |
| Add TTP metadata | `redgnat/scenarios/ttp_mapper.py` |
| Add GNAT intel ask | `redgnat/feedback/gap_reporter.py` |
| Write unit tests | `tests/unit/techniques/test_<name>.py` |
