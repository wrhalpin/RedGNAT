# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RedGNAT base ORM class — dataclass-style models with STIX export."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid() -> str:
    """Return a new random UUIDv4 string."""
    return str(uuid.uuid4())


# Fixed namespace for deterministic (UUIDv5) IDs. Derived once from a constant
# string so the same logical entity always maps to the same ID across runs.
_REDGNAT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "redgnat")


def deterministic_id(*parts: str) -> str:
    """
    Return a stable UUIDv5 string derived from ``parts``.

    Used to give the same logical entity (e.g. a GNAT campaign, an ATT&CK
    technique) a repeatable ID so upserts dedupe and cross-object STIX
    references resolve, instead of minting a fresh random UUID each time.
    """
    key = "|".join(p or "" for p in parts)
    return str(uuid.uuid5(_REDGNAT_NAMESPACE, key))


class RedGNATBase:
    """
    Lightweight base for all RedGNAT ORM models.

    Follows GNAT's property-bag pattern: core fields are explicit attributes;
    serialization is via to_dict() / from_dict(). No SQLAlchemy or Pydantic.
    """

    def to_dict(self) -> dict[str, Any]:
        """Serialize the model to a JSON-compatible dict."""
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RedGNATBase:
        """Reconstruct a model instance from a serialized dict."""
        raise NotImplementedError

    def __repr__(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items() if v is not None)
        return f"{self.__class__.__name__}({fields})"
