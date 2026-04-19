"""Shared test fixtures for RedGNAT unit tests."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

from redgnat.techniques.base import Scope, TechniqueContext


@pytest.fixture
def minimal_config(tmp_path: Path) -> str:
    """Write a minimal redgnat.ini and return its path."""
    config_content = """
[redgnat]
db_url = postgresql://redgnat:test@localhost:5432/redgnat_test
redis_url = redis://localhost:6379/1
dry_run = false
log_level = DEBUG

[gnat]
poll_interval_seconds = 300
min_confidence = 0.6

[sandgnat]
base_url = http://localhost:5001
api_key = test-key
poll_interval_seconds = 120
min_severity = medium

[gophish]
base_url = https://localhost:3333
api_key = test-gophish-key
sending_profile_id = 1
landing_page_base_url = https://click.test.internal

[scope]
target_ranges = 192.168.100.0/24
excluded_ranges = 192.168.100.1/32
target_domains = test.example.com
excluded_domains =
target_accounts = test-user@test.example.com
max_rate_per_minute = 60

[entra]
tenant_id = test-tenant-id
client_id = test-client-id
client_secret = test-secret

[okta]
base_url = https://test.okta.com
api_token = test-okta-token

[ldap]
server = ldap://dc.test.example.com
bind_dn = CN=svc,DC=test,DC=example,DC=com
bind_password = test-pass
base_dn = DC=test,DC=example,DC=com
use_ssl = false
port = 389

[feedback]
enabled = true
push_to_gnat = false
probe_generation_enabled = true
probe_model = claude-3-5-sonnet-20241022
max_probes_per_report = 5
"""
    config_file = tmp_path / "redgnat.ini"
    config_file.write_text(config_content)
    return str(config_file)


@pytest.fixture
def mock_scope() -> Scope:
    """Return a permissive test scope."""
    return Scope(
        target_ranges=["192.168.100.0/24"],
        excluded_ranges=["192.168.100.1/32"],
        target_domains=["test.example.com"],
        excluded_domains=[],
        target_accounts=["test-user@test.example.com"],
        max_rate_per_minute=60,
        dry_run=False,
    )


@pytest.fixture
def dry_run_scope() -> Scope:
    """Return a dry-run scope that prevents all network activity."""
    return Scope(
        target_ranges=["192.168.100.0/24"],
        target_domains=["test.example.com"],
        target_accounts=["test-user@test.example.com"],
        max_rate_per_minute=60,
        dry_run=True,
    )


@pytest.fixture
def mock_ctx(mock_scope: Scope) -> TechniqueContext:
    """Return a TechniqueContext with the mock scope."""
    return TechniqueContext(
        run_id="run-test-001",
        scenario_id="scenario-test-001",
        feed_id="feed-test-001",
        scope=mock_scope,
        params={},
    )


@pytest.fixture
def dry_run_ctx(dry_run_scope: Scope) -> TechniqueContext:
    """Return a dry-run TechniqueContext."""
    return TechniqueContext(
        run_id="run-dry-001",
        scenario_id="scenario-dry-001",
        feed_id="feed-dry-001",
        scope=dry_run_scope,
        params={},
    )
