# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""RedGNAT base ORM class — dataclass-style models with STIX export."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Return a new random UUIDv4 string."""
    return str(uuid.uuid4())


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
    def from_dict(cls, data: dict[str, Any]) -> "RedGNATBase":
        """Reconstruct a model instance from a serialized dict."""
        raise NotImplementedError

    def __repr__(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in self.to_dict().items() if v is not None)
        return f"{self.__class__.__name__}({fields})"
