# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Cross-tool investigation context — shared STIX contract for the GNAT-o-sphere.

Every STIX object emitted by an investigation-scoped run is stamped with three
custom properties (four when a hypothesis is present):

    x_gnat_investigation_id        — the GNAT investigation being validated
    x_gnat_investigation_origin    — always "redgnat"
    x_gnat_investigation_link_type — "confirmed" for engagement-driven runs;
                                     "inferred" for post-hoc tagging (Phase 5)
    x_gnat_hypothesis_id           — (optional) the GNAT Hypothesis being tested

Canonical spec: docs/reference/investigation-context.md
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def apply_investigation_context(
    stix_obj: dict[str, Any],
    investigation_id: str,
    *,
    hypothesis_id: str | None = None,
    link_type: str = "confirmed",
) -> dict[str, Any]:
    """
    Stamp a STIX object with the shared investigation-context properties.

    Mutates ``stix_obj`` in-place and returns it for convenience.

    Parameters
    ----------
    stix_obj : dict
        Any STIX 2.1 object dict.
    investigation_id : str
        GNAT investigation ID (e.g. "IC-2026-0001").
    hypothesis_id : str | None
        GNAT Hypothesis ID when the run was scoped to a specific hypothesis.
    link_type : str
        "confirmed" for engagement-driven runs (default).
        "inferred" for post-hoc tagging.
    """
    stix_obj["x_gnat_investigation_id"] = investigation_id
    stix_obj["x_gnat_investigation_origin"] = "redgnat"
    stix_obj["x_gnat_investigation_link_type"] = link_type
    if hypothesis_id:
        stix_obj["x_gnat_hypothesis_id"] = hypothesis_id
    return stix_obj


def build_grouping(
    run_id: str,
    investigation_id: str,
    object_refs: list[str],
    *,
    hypothesis_id: str | None = None,
    created: datetime | None = None,
) -> dict[str, Any]:
    """
    Build a STIX 2.1 Grouping enveloping all objects from an investigation-scoped run.

    Parameters
    ----------
    run_id : str
        RedGNAT emulation run ID (used as the Grouping's deterministic UUID).
    investigation_id : str
        GNAT investigation ID.
    object_refs : list[str]
        STIX IDs of every object emitted by this run.
    hypothesis_id : str | None
        GNAT Hypothesis ID if the run was hypothesis-scoped.
    created : datetime | None
        Grouping creation timestamp; defaults to UTC now.
    """
    ts = (created or datetime.now(timezone.utc)).isoformat()
    grouping: dict[str, Any] = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": f"grouping--{run_id}",
        "created": ts,
        "modified": ts,
        "name": f"RedGNAT engagement {run_id}",
        "context": "suspicious-activity",
        "object_refs": object_refs,
        "x_gnat_investigation_id": investigation_id,
        "x_gnat_investigation_origin": "redgnat",
        "x_gnat_investigation_link_type": "confirmed",
    }
    if hypothesis_id:
        grouping["x_gnat_hypothesis_id"] = hypothesis_id
    return grouping


def validate_hypothesis(
    gnat_api_base_url: str,
    gnat_api_key: str,
    investigation_id: str,
    hypothesis_id: str,
    *,
    timeout: float = 3.0,
) -> tuple[bool | None, str | None]:
    """
    Validate that ``hypothesis_id`` belongs to ``investigation_id`` via GNAT's API.

    Parameters
    ----------
    gnat_api_base_url : str
        GNAT REST API base URL (e.g. "http://gnat-host:8000").
    gnat_api_key : str
        GNAT API key for authentication.
    investigation_id : str
        GNAT investigation ID.
    hypothesis_id : str
        Hypothesis ID to validate.
    timeout : float
        HTTP timeout in seconds (default 3 s — keeps engagement-creation latency low).

    Returns
    -------
    (True, None)
        Hypothesis exists and belongs to the investigation.
    (False, message)
        Hypothesis not found — caller should raise 400.
    (None, warning)
        GNAT unreachable — caller should accept with ``investigation_validation_pending=True``.
    """
    url = (
        f"{gnat_api_base_url.rstrip('/')}"
        f"/api/investigations/{investigation_id}/hypotheses"
    )
    req = urllib.request.Request(
        url,
        headers={"X-API-Key": gnat_api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            hypotheses: list[dict] = json.loads(resp.read())
        ids = {h.get("id") or h.get("hypothesis_id") for h in hypotheses}
        if hypothesis_id not in ids:
            return False, (
                f"Hypothesis {hypothesis_id!r} not found in investigation {investigation_id!r}"
            )
        return True, None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, f"Investigation {investigation_id!r} not found on GNAT (404)"
        logger.warning(
            "validate_hypothesis: GNAT returned HTTP %s for investigation %s — "
            "accepting run with validation_pending flag",
            exc.code,
            investigation_id,
        )
        return None, f"GNAT returned HTTP {exc.code}; hypothesis validation pending"
    except Exception as exc:
        logger.warning(
            "validate_hypothesis: GNAT unreachable (%s) — "
            "accepting run with validation_pending flag",
            exc,
        )
        return None, f"GNAT unreachable ({exc}); hypothesis validation pending"


def push_investigation_bundle(
    gnat_api_base_url: str,
    gnat_api_key: str,
    investigation_id: str,
    stix_bundle: dict[str, Any],
    *,
    reopen: bool = False,
    timeout: float = 15.0,
) -> tuple[bool, str | None]:
    """
    POST a STIX bundle to GNAT's investigation evidence endpoint.

    Parameters
    ----------
    gnat_api_base_url : str
        GNAT REST API base URL.
    gnat_api_key : str
        GNAT API key.
    investigation_id : str
        GNAT investigation to attach evidence to.
    stix_bundle : dict
        Full STIX 2.1 bundle dict.
    reopen : bool
        If True, add ``X-Reopen-Investigation: true`` header (for 409 recovery).
    timeout : float
        HTTP timeout in seconds.

    Returns
    -------
    (True, None)
        Push succeeded.
    (False, error_type)
        Push failed; ``error_type`` is one of "conflict", "not_found",
        "forbidden", "network_error".
    """
    url = (
        f"{gnat_api_base_url.rstrip('/')}"
        f"/api/investigations/{investigation_id}/evidence"
    )
    headers: dict[str, str] = {
        "X-API-Key": gnat_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if reopen:
        headers["X-Reopen-Investigation"] = "true"

    data = json.dumps(stix_bundle).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            _ = resp.read()
        return True, None
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            logger.warning(
                "push_investigation_bundle: investigation %s is closed (409) — "
                "bundle stored locally as pending_reopen",
                investigation_id,
            )
            return False, "conflict"
        if exc.code == 404:
            logger.warning(
                "push_investigation_bundle: investigation %s not found (404) — "
                "marking run as orphaned",
                investigation_id,
            )
            return False, "not_found"
        if exc.code == 403:
            logger.error(
                "push_investigation_bundle: tenant mismatch for investigation %s (403) — "
                "this is a configuration bug; check investigation_tenant_id",
                investigation_id,
            )
            return False, "forbidden"
        logger.error(
            "push_investigation_bundle: GNAT returned HTTP %s for investigation %s",
            exc.code,
            investigation_id,
        )
        return False, f"http_{exc.code}"
    except Exception as exc:
        logger.error(
            "push_investigation_bundle: network error pushing to investigation %s: %s",
            investigation_id,
            exc,
        )
        return False, "network_error"
