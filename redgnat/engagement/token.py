"""
EngagementToken — time-bounded Phase 2 authorisation stored in Redis.

The token is the third factor of the Phase 2 impasse.  It must be created
explicitly by an operator via `redgnat engage` or POST /engage/authorize.
Once created it lives in Redis with a TTL; when it expires Phase 2 stops
at the next inter-technique checkpoint.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

_REDIS_KEY = "redgnat:engage:token"


@dataclass
class EngagementToken:
    """
    A short-lived Phase 2 authorisation record.

    Parameters
    ----------
    token_id : str
        Unique ID for this token (UUIDv4).
    operator : str
        Human-readable identity of who authorised this engagement.
    created_at : datetime
    expires_at : datetime
        When the token expires; techniques check this between steps.
    """

    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operator: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(cls, operator: str, duration_hours: float) -> "EngagementToken":
        """Create a new token valid for *duration_hours* from now."""
        now = datetime.now(timezone.utc)
        return cls(
            operator=operator,
            created_at=now,
            expires_at=now + timedelta(hours=duration_hours),
        )

    @property
    def is_valid(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at

    @property
    def remaining_seconds(self) -> float:
        delta = (self.expires_at - datetime.now(timezone.utc)).total_seconds()
        return max(delta, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "operator": self.operator,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EngagementToken":
        return cls(
            token_id=d["token_id"],
            operator=d.get("operator", ""),
            created_at=datetime.fromisoformat(d["created_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]),
        )

    # ------------------------------------------------------------------
    # Redis persistence
    # ------------------------------------------------------------------

    def store(self, redis_client: Any) -> None:
        """Persist to Redis with a TTL matching the token's remaining lifetime."""
        ttl = max(int(self.remaining_seconds) + 60, 1)  # small grace period
        redis_client.setex(_REDIS_KEY, ttl, json.dumps(self.to_dict()))

    @classmethod
    def load(cls, redis_client: Any) -> "EngagementToken | None":
        """Load from Redis, or return None if no token exists."""
        raw = redis_client.get(_REDIS_KEY)
        if not raw:
            return None
        try:
            return cls.from_dict(json.loads(raw))
        except Exception:
            return None

    @classmethod
    def revoke(cls, redis_client: Any) -> None:
        """Delete the token from Redis, immediately ending Phase 2 authorisation."""
        redis_client.delete(_REDIS_KEY)
