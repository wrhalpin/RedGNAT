"""
RedGNAT — Continuous Automated Red Teaming module for GNAT.

Quick start
-----------
>>> from redgnat import RedGNATClient
>>> client = RedGNATClient()
>>> client.ingest_latest()
>>> runs = [client.run_scenario(s.scenario_id) for s in client.list_scenarios()]
"""

from redgnat.client import RedGNATClient
from redgnat.orm.models import (
    EmulationRun,
    EmulationScenario,
    IntelFeed,
    ResultStatus,
    RunStatus,
    TechniqueResult,
)

__version__ = "0.1.0"

__all__ = [
    "RedGNATClient",
    "IntelFeed",
    "EmulationScenario",
    "EmulationRun",
    "TechniqueResult",
    "ResultStatus",
    "RunStatus",
]
