"""
RedGNAT → GNAT integration plugin.

Registers RedGNAT as a GNAT connector via the ConnectorMixin interface.
GNAT operators add this connector to pull emulation results (as STIX
Course-of-Action and Sighting objects) into their GNAT workspace.

Usage (in a GNAT config and workflow):

    from gnat import GNATClient
    from redgnat.plugins.gnat_plugin import RedGNATConnector

    client = GNATClient(config_path="gnat.ini")
    connector = RedGNATConnector(
        base_url="http://redgnat.internal:8000",
        api_key="REDGNAT_API_KEY",
    )
    # Pull all emulation results as STIX CoA objects
    results = connector.list_objects()

The connector is also auto-discoverable by GNAT via the entry point:
    [project.entry-points."gnat.connectors"]
    redgnat = "redgnat.plugins.gnat_plugin:RedGNATConnector"
"""
from __future__ import annotations

import json
import logging
import urllib.request
import ssl
from typing import Any

logger = logging.getLogger(__name__)


class RedGNATConnector:
    """
    Thin GNAT-compatible connector for pulling RedGNAT emulation results.

    Implements the minimal ConnectorMixin interface expected by GNATClient:
    authenticate(), health_check(), list_objects(), get_object().

    Results are returned as dicts matching GNAT's STIX ORM format
    (CourseOfAction and Sighting object types).

    Parameters
    ----------
    base_url : str
        RedGNAT API base URL.
    api_key : str
        RedGNAT API key (configured in redgnat.api).
    verify_ssl : bool
        Verify TLS certificate (default: True).
    """

    platform_name = "redgnat"
    description = "Continuous Automated Red Teaming (CART) emulation results"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._ssl_ctx = (
            ssl.create_default_context()
            if verify_ssl
            else self._no_verify_ctx()
        )

    @staticmethod
    def _no_verify_ctx() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def authenticate(self) -> bool:
        """Verify API key is accepted by RedGNAT."""
        return self.health_check()

    def health_check(self) -> bool:
        try:
            self._get("/api/v1/health")
            return True
        except Exception as exc:
            logger.warning("RedGNATConnector health check failed: %s", exc)
            return False

    def list_objects(
        self,
        object_type: str = "course-of-action",
        **kwargs: Any,
    ) -> list[dict]:
        """
        List emulation results as STIX objects.

        Parameters
        ----------
        object_type : str
            "course-of-action" (run summaries) or "sighting" (technique results).

        Returns
        -------
        list[dict]
            STIX-shaped dicts compatible with GNAT's ORM.
        """
        if object_type == "course-of-action":
            runs = self._get("/api/v1/stix/results")
            return runs if isinstance(runs, list) else []
        elif object_type == "sighting":
            sightings = self._get("/api/v1/stix/sightings")
            return sightings if isinstance(sightings, list) else []
        elif object_type == "note":
            notes = self._get("/api/v1/stix/gaps")
            return notes if isinstance(notes, list) else []
        else:
            logger.debug("RedGNATConnector: unsupported object_type %s", object_type)
            return []

    def get_object(self, object_id: str) -> dict | None:
        try:
            return self._get(f"/api/v1/stix/results/{object_id}")
        except Exception:
            return None

    def push_probe_request(self, probe_dict: dict) -> dict:
        """
        POST a ProbeRequest to RedGNAT's intake endpoint.

        GNAT AI agents call this after analysing gap notes to inject
        follow-on probe instructions into the RedGNAT emulation queue.

        Parameters
        ----------
        probe_dict : dict
            ProbeRequest.to_dict() payload.
        """
        return self._post("/api/v1/intel/probe-request", probe_dict)

    def upsert_object(self, obj: dict) -> dict:
        raise NotImplementedError("RedGNAT connector is read-only from GNAT's perspective")

    def delete_object(self, object_id: str) -> None:
        raise NotImplementedError("RedGNAT connector is read-only from GNAT's perspective")

    def to_stix(self, obj: dict) -> dict:
        return obj  # already STIX-shaped

    def from_stix(self, stix_obj: dict) -> dict:
        return stix_obj

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _get(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "X-API-Key": self._api_key,
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read())

    def _post(self, path: str, payload: dict) -> Any:
        url = f"{self._base_url}{path}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "X-API-Key": self._api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:  # noqa: S310
            return json.loads(resp.read())
