# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Core ORM models for RedGNAT."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from redgnat.orm.base import RedGNATBase, _utcnow, new_uuid


class IntelSource(str, Enum):
    """Origin system for an IntelFeed record."""

    GNAT = "gnat"
    SANDGNAT = "sandgnat"


class ScenarioStatus(str, Enum):
    """Lifecycle state of an EmulationScenario."""

    PENDING = "pending"
    ACTIVE = "active"
    ARCHIVED = "archived"


class RunStatus(str, Enum):
    """Execution state of an EmulationRun."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    KILLED = "killed"       # stopped by kill switch mid-run


class ResultStatus(str, Enum):
    """Outcome of a single technique execution within a run."""

    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"    # Scope check prevented execution
    DETECTED = "detected"  # Triggered defensive telemetry
    ERROR = "error"
    DRY_RUN = "dry_run"
    KILLED = "killed"      # Kill switch activated mid-run; technique did not start
    EXPIRED = "expired"    # Phase 2 engagement token expired; technique did not start


@dataclass
class IntelFeed(RedGNATBase):
    """
    Tracks one ingested intel record from GNAT or SandGNAT.

    Parameters
    ----------
    feed_id : str
        Unique ID (UUIDv4).
    source : IntelSource
        Origin system.
    source_ref_id : str
        STIX object ID or SandGNAT analysis_id from the source.
    stix_bundle : dict
        Full STIX bundle as received.
    campaign_name : str | None
        Human-readable campaign name if present.
    attack_pattern_ids : list[str]
        ATT&CK technique IDs extracted from the bundle (e.g. ["T1566.002"]).
    confidence : float
        Intel confidence score (0.0–1.0).
    ingested_at : datetime
        When this feed was ingested.
    """

    feed_id: str = field(default_factory=new_uuid)
    source: IntelSource = IntelSource.GNAT
    source_ref_id: str = ""
    stix_bundle: dict[str, Any] = field(default_factory=dict)
    campaign_name: str | None = None
    attack_pattern_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0
    ingested_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feed_id": self.feed_id,
            "source": self.source.value,
            "source_ref_id": self.source_ref_id,
            "stix_bundle": self.stix_bundle,
            "campaign_name": self.campaign_name,
            "attack_pattern_ids": self.attack_pattern_ids,
            "confidence": self.confidence,
            "ingested_at": self.ingested_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntelFeed":
        return cls(
            feed_id=data.get("feed_id", new_uuid()),
            source=IntelSource(data.get("source", "gnat")),
            source_ref_id=data.get("source_ref_id", ""),
            stix_bundle=data.get("stix_bundle", {}),
            campaign_name=data.get("campaign_name"),
            attack_pattern_ids=data.get("attack_pattern_ids", []),
            confidence=float(data.get("confidence", 0.0)),
            ingested_at=datetime.fromisoformat(data["ingested_at"])
            if "ingested_at" in data
            else _utcnow(),
        )


@dataclass
class EmulationScenario(RedGNATBase):
    """
    A named adversary emulation scenario built from threat intelligence.

    Parameters
    ----------
    scenario_id : str
        Unique ID (UUIDv4).
    name : str
        Human-readable scenario name.
    description : str
        What this scenario emulates and why.
    feed_id : str
        Source IntelFeed that triggered this scenario.
    technique_ids : list[str]
        Ordered list of ATT&CK technique IDs to execute.
    scope_overrides : dict
        Per-scenario scope overrides (merged with global scope at run time).
    status : ScenarioStatus
        Lifecycle state.
    created_at : datetime
    updated_at : datetime
    """

    scenario_id: str = field(default_factory=new_uuid)
    name: str = ""
    description: str = ""
    feed_id: str = ""
    technique_ids: list[str] = field(default_factory=list)
    scope_overrides: dict[str, Any] = field(default_factory=dict)
    status: ScenarioStatus = ScenarioStatus.PENDING
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "feed_id": self.feed_id,
            "technique_ids": self.technique_ids,
            "scope_overrides": self.scope_overrides,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmulationScenario":
        return cls(
            scenario_id=data.get("scenario_id", new_uuid()),
            name=data.get("name", ""),
            description=data.get("description", ""),
            feed_id=data.get("feed_id", ""),
            technique_ids=data.get("technique_ids", []),
            scope_overrides=data.get("scope_overrides", {}),
            status=ScenarioStatus(data.get("status", "pending")),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else _utcnow(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if "updated_at" in data
            else _utcnow(),
        )


@dataclass
class EmulationRun(RedGNATBase):
    """
    One execution instance of an EmulationScenario.

    Parameters
    ----------
    run_id : str
        Unique ID (UUIDv4).
    scenario_id : str
        Parent scenario.
    celery_task_id : str | None
        Celery async task ID for status tracking.
    status : RunStatus
    started_at : datetime | None
    completed_at : datetime | None
    triggered_by : str
        "scheduler" | "manual" | "intel_event"
    """

    run_id: str = field(default_factory=new_uuid)
    scenario_id: str = ""
    celery_task_id: str | None = None
    status: RunStatus = RunStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    triggered_by: str = "scheduler"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "celery_task_id": self.celery_task_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "triggered_by": self.triggered_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmulationRun":
        return cls(
            run_id=data.get("run_id", new_uuid()),
            scenario_id=data.get("scenario_id", ""),
            celery_task_id=data.get("celery_task_id"),
            status=RunStatus(data.get("status", "queued")),
            started_at=datetime.fromisoformat(data["started_at"])
            if data.get("started_at")
            else None,
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            triggered_by=data.get("triggered_by", "scheduler"),
        )


@dataclass
class TechniqueResult(RedGNATBase):
    """
    Outcome of executing one technique within an EmulationRun.

    Parameters
    ----------
    result_id : str
        Unique ID (UUIDv4).
    run_id : str
        Parent EmulationRun.
    scenario_id : str
        Parent EmulationScenario.
    feed_id : str
        Source IntelFeed (for traceability).
    technique_id : str
        ATT&CK technique ID.
    tactic : str
        ATT&CK tactic name.
    status : ResultStatus
    findings : list[dict]
        Structured findings (open ports, users found, clicks, etc.).
    evidence : list[dict]
        Raw evidence records (packet snippets, API responses, etc.).
    error : str | None
        Error message if status == ERROR.
    executed_at : datetime
    """

    result_id: str = field(default_factory=new_uuid)
    run_id: str = ""
    scenario_id: str = ""
    feed_id: str = ""
    technique_id: str = ""
    tactic: str = ""
    status: ResultStatus = ResultStatus.SUCCESS
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    executed_at: datetime = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "feed_id": self.feed_id,
            "technique_id": self.technique_id,
            "tactic": self.tactic,
            "status": self.status.value,
            "findings": self.findings,
            "evidence": self.evidence,
            "error": self.error,
            "executed_at": self.executed_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TechniqueResult":
        return cls(
            result_id=data.get("result_id", new_uuid()),
            run_id=data.get("run_id", ""),
            scenario_id=data.get("scenario_id", ""),
            feed_id=data.get("feed_id", ""),
            technique_id=data.get("technique_id", ""),
            tactic=data.get("tactic", ""),
            status=ResultStatus(data.get("status", "success")),
            findings=data.get("findings", []),
            evidence=data.get("evidence", []),
            error=data.get("error"),
            executed_at=datetime.fromisoformat(data["executed_at"])
            if "executed_at" in data
            else _utcnow(),
        )

    def to_stix_sighting(self) -> dict[str, Any]:
        """Export as a minimal STIX 2.1 Sighting object for push-back to GNAT."""
        return {
            "type": "sighting",
            "spec_version": "2.1",
            "id": f"sighting--{self.result_id}",
            "created": self.executed_at.isoformat(),
            "modified": self.executed_at.isoformat(),
            "sighting_of_ref": f"attack-pattern--{self.technique_id}",
            "count": len(self.findings),
            "x_redgnat_metadata": {
                "run_id": self.run_id,
                "scenario_id": self.scenario_id,
                "feed_id": self.feed_id,
                "status": self.status.value,
                "tactic": self.tactic,
            },
        }
