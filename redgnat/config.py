"""INI-based configuration management for RedGNAT."""
from __future__ import annotations

import configparser
import os
from pathlib import Path


class RedGNATConfig:
    """Loads and provides typed access to redgnat.ini configuration."""

    _SEARCH_ORDER = [
        lambda: os.environ.get("REDGNAT_CONFIG"),
        lambda: str(Path.home() / ".redgnat" / "config.ini"),
        lambda: "redgnat.ini",
    ]

    def __init__(self, path: str | None = None) -> None:
        self._cfg = configparser.ConfigParser()
        resolved = path or self._locate()
        if resolved and Path(resolved).exists():
            self._cfg.read(resolved)

    @classmethod
    def _locate(cls) -> str | None:
        for probe in cls._SEARCH_ORDER:
            candidate = probe()
            if candidate and Path(candidate).exists():
                return candidate
        return None

    # ------------------------------------------------------------------
    # [redgnat]
    # ------------------------------------------------------------------
    @property
    def db_url(self) -> str:
        return self._get("redgnat", "db_url", "postgresql://redgnat:redgnat@localhost:5432/redgnat")

    @property
    def redis_url(self) -> str:
        return self._get("redgnat", "redis_url", "redis://localhost:6379/0")

    @property
    def dry_run(self) -> bool:
        return self._cfg.getboolean("redgnat", "dry_run", fallback=False)

    @property
    def log_level(self) -> str:
        return self._get("redgnat", "log_level", "INFO").upper()

    # ------------------------------------------------------------------
    # [gnat]
    # ------------------------------------------------------------------
    @property
    def gnat_config_path(self) -> str | None:
        v = self._get("gnat", "config_path", "")
        return v or None

    @property
    def gnat_poll_interval(self) -> int:
        return int(self._get("gnat", "poll_interval_seconds", "300"))

    @property
    def gnat_min_confidence(self) -> float:
        return float(self._get("gnat", "min_confidence", "0.6"))

    # ------------------------------------------------------------------
    # [sandgnat]
    # ------------------------------------------------------------------
    @property
    def sandgnat_base_url(self) -> str:
        return self._get("sandgnat", "base_url", "http://localhost:5000")

    @property
    def sandgnat_api_key(self) -> str:
        return self._get("sandgnat", "api_key", "")

    @property
    def sandgnat_poll_interval(self) -> int:
        return int(self._get("sandgnat", "poll_interval_seconds", "120"))

    @property
    def sandgnat_min_severity(self) -> str:
        return self._get("sandgnat", "min_severity", "medium").lower()

    # ------------------------------------------------------------------
    # [gophish]
    # ------------------------------------------------------------------
    @property
    def gophish_base_url(self) -> str:
        return self._get("gophish", "base_url", "")

    @property
    def gophish_api_key(self) -> str:
        return self._get("gophish", "api_key", "")

    @property
    def gophish_sending_profile_id(self) -> int:
        return int(self._get("gophish", "sending_profile_id", "1"))

    @property
    def gophish_landing_page_base_url(self) -> str:
        return self._get("gophish", "landing_page_base_url", "")

    @property
    def gophish_default_campaign_hours(self) -> int:
        return int(self._get("gophish", "default_campaign_hours", "72"))

    # ------------------------------------------------------------------
    # [scope]
    # ------------------------------------------------------------------
    @property
    def scope_target_ranges(self) -> list[str]:
        return self._split("scope", "target_ranges")

    @property
    def scope_excluded_ranges(self) -> list[str]:
        return self._split("scope", "excluded_ranges")

    @property
    def scope_target_domains(self) -> list[str]:
        return self._split("scope", "target_domains")

    @property
    def scope_excluded_domains(self) -> list[str]:
        return self._split("scope", "excluded_domains")

    @property
    def scope_target_accounts(self) -> list[str]:
        return self._split("scope", "target_accounts")

    @property
    def scope_max_rate_per_minute(self) -> int:
        return int(self._get("scope", "max_rate_per_minute", "30"))

    # ------------------------------------------------------------------
    # [entra]
    # ------------------------------------------------------------------
    @property
    def entra_tenant_id(self) -> str:
        return self._get("entra", "tenant_id", "")

    @property
    def entra_client_id(self) -> str:
        return self._get("entra", "client_id", "")

    @property
    def entra_client_secret(self) -> str:
        return self._get("entra", "client_secret", "")

    @property
    def entra_authority(self) -> str:
        return self._get("entra", "authority", "https://login.microsoftonline.com")

    # ------------------------------------------------------------------
    # [okta]
    # ------------------------------------------------------------------
    @property
    def okta_base_url(self) -> str:
        return self._get("okta", "base_url", "")

    @property
    def okta_api_token(self) -> str:
        return self._get("okta", "api_token", "")

    # ------------------------------------------------------------------
    # [ldap]
    # ------------------------------------------------------------------
    @property
    def ldap_server(self) -> str:
        return self._get("ldap", "server", "")

    @property
    def ldap_bind_dn(self) -> str:
        return self._get("ldap", "bind_dn", "")

    @property
    def ldap_bind_password(self) -> str:
        return self._get("ldap", "bind_password", "")

    @property
    def ldap_base_dn(self) -> str:
        return self._get("ldap", "base_dn", "")

    @property
    def ldap_use_ssl(self) -> bool:
        return self._cfg.getboolean("ldap", "use_ssl", fallback=False)

    @property
    def ldap_port(self) -> int:
        return int(self._get("ldap", "port", "389"))

    # ------------------------------------------------------------------
    # [aws]
    # ------------------------------------------------------------------
    @property
    def aws_access_key_id(self) -> str:
        return self._get("aws", "aws_access_key_id", "")

    @property
    def aws_secret_access_key(self) -> str:
        return self._get("aws", "aws_secret_access_key", "")

    @property
    def aws_default_region(self) -> str:
        return self._get("aws", "aws_default_region", "us-east-1")

    @property
    def aws_assume_role_arn(self) -> str:
        return self._get("aws", "assume_role_arn", "")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get(self, section: str, key: str, default: str) -> str:
        return self._cfg.get(section, key, fallback=default).strip()

    def _split(self, section: str, key: str) -> list[str]:
        raw = self._get(section, key, "")
        return [v.strip() for v in raw.split(",") if v.strip()]
