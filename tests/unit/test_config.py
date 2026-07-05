# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Exercise every RedGNATConfig property against a fully-populated INI."""

from __future__ import annotations

import textwrap

import pytest

from redgnat.config import RedGNATConfig

_FULL_INI = textwrap.dedent(
    """
    [redgnat]
    db_url = postgresql://u:p@db:5432/redgnat
    redis_url = redis://cache:6379/1
    dry_run = true
    phase2_enabled = true
    phase2_unlock_secret = s3cret
    log_level = debug

    [gnat]
    config_path = /etc/gnat.ini
    api_base_url = http://gnat:8000
    api_key = gk
    poll_interval_seconds = 120
    min_confidence = 0.8

    [sandgnat]
    base_url = http://sand:5000
    api_key = sk
    poll_interval_seconds = 90
    min_severity = high

    [gophish]
    base_url = https://gophish:3333
    api_key = gpk
    sending_profile_id = 2
    landing_page_base_url = https://redir
    default_campaign_hours = 48
    max_inline_poll_seconds = 30

    [scope]
    target_ranges = 10.0.0.0/8, 172.16.0.0/12
    excluded_ranges = 10.0.0.1/32
    target_domains = corp.example.com
    excluded_domains = prod.example.com
    target_accounts = test@example.com
    max_rate_per_minute = 15

    [entra]
    tenant_id = t-1
    client_id = c-1
    client_secret = sec
    authority = https://login.microsoftonline.com

    [okta]
    base_url = https://x.okta.com
    api_token = ot

    [ldap]
    server = ldap://dc.example.com
    bind_dn = CN=svc
    bind_password = pw
    base_dn = DC=example,DC=com
    use_ssl = true
    port = 636

    [aws]
    aws_access_key_id = AKIA
    aws_secret_access_key = secret
    aws_default_region = eu-west-1
    assume_role_arn = arn:aws:iam::1:role/x

    [feedback]
    enabled = false
    push_to_gnat = false
    probe_generation_enabled = false
    probe_model = claude-x
    max_probes_per_report = 5
    max_probe_depth = 2
    """
)


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "redgnat.ini"
    p.write_text(_FULL_INI)
    return RedGNATConfig(path=str(p))


def test_redgnat_section(cfg):
    assert cfg.db_url.endswith("/redgnat")
    assert cfg.redis_url.endswith("/1")
    assert cfg.dry_run is True
    assert cfg.phase2_enabled is True
    assert cfg.phase2_unlock_secret == "s3cret"
    assert cfg.log_level == "DEBUG"


def test_gnat_and_sandgnat(cfg):
    assert cfg.gnat_config_path == "/etc/gnat.ini"
    assert cfg.gnat_api_base_url == "http://gnat:8000"
    assert cfg.gnat_api_key == "gk"
    assert cfg.gnat_poll_interval == 120
    assert cfg.gnat_min_confidence == 0.8
    assert cfg.sandgnat_base_url == "http://sand:5000"
    assert cfg.sandgnat_api_key == "sk"
    assert cfg.sandgnat_poll_interval == 90
    assert cfg.sandgnat_min_severity == "high"


def test_gophish(cfg):
    assert cfg.gophish_base_url.endswith(":3333")
    assert cfg.gophish_api_key == "gpk"
    assert cfg.gophish_sending_profile_id == 2
    assert cfg.gophish_landing_page_base_url == "https://redir"
    assert cfg.gophish_default_campaign_hours == 48
    assert cfg.max_inline_poll_seconds == 30


def test_scope(cfg):
    assert cfg.scope_target_ranges == ["10.0.0.0/8", "172.16.0.0/12"]
    assert cfg.scope_excluded_ranges == ["10.0.0.1/32"]
    assert cfg.scope_target_domains == ["corp.example.com"]
    assert cfg.scope_excluded_domains == ["prod.example.com"]
    assert cfg.scope_target_accounts == ["test@example.com"]
    assert cfg.scope_max_rate_per_minute == 15


def test_idp_sections(cfg):
    assert cfg.entra_tenant_id == "t-1"
    assert cfg.entra_client_id == "c-1"
    assert cfg.entra_client_secret == "sec"
    assert cfg.entra_authority.startswith("https://login")
    assert cfg.okta_base_url.endswith(".okta.com")
    assert cfg.okta_api_token == "ot"
    assert cfg.ldap_server.startswith("ldap://")
    assert cfg.ldap_bind_dn == "CN=svc"
    assert cfg.ldap_bind_password == "pw"
    assert cfg.ldap_base_dn == "DC=example,DC=com"
    assert cfg.ldap_use_ssl is True
    assert cfg.ldap_port == 636


def test_aws_and_feedback(cfg):
    assert cfg.aws_access_key_id == "AKIA"
    assert cfg.aws_secret_access_key == "secret"
    assert cfg.aws_default_region == "eu-west-1"
    assert cfg.aws_assume_role_arn.startswith("arn:aws:iam")
    assert cfg.feedback_enabled is False
    assert cfg.feedback_push_to_gnat is False
    assert cfg.feedback_probe_generation_enabled is False
    assert cfg.feedback_probe_model == "claude-x"
    assert cfg.feedback_max_probes == 5
    assert cfg.feedback_max_probe_depth == 2


def test_defaults_when_file_absent(tmp_path):
    cfg = RedGNATConfig(path=str(tmp_path / "nope.ini"))
    assert cfg.db_url.startswith("postgresql://")
    assert cfg.dry_run is False
    assert cfg.gnat_poll_interval == 300
    assert cfg.scope_target_ranges == []
