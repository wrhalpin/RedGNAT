# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Success-path tests for GoPhish-backed techniques (client mocked)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Scope, TechniqueContext
from redgnat.techniques.identity.oauth_abuse import OAuthAbuseTechnique
from redgnat.techniques.phishing.mfa_phishing import MFAPhishingTechnique
from redgnat.techniques.phishing.spearphishing_attachment import (
    SpearphishingAttachmentTechnique,
)
from redgnat.techniques.phishing.spearphishing_link import SpearphishingLinkTechnique


def _cfg():
    cfg = MagicMock()
    cfg.gophish_base_url = "https://gophish.test"
    cfg.gophish_api_key = "key"
    cfg.gophish_landing_page_base_url = "https://redir.test"
    cfg.gophish_sending_profile_id = 1
    cfg.gophish_default_campaign_hours = 24
    cfg.max_inline_poll_seconds = 0
    return cfg


def _ctx():
    scope = Scope(
        target_domains=["test.example.com"],
        target_accounts=["victim@test.example.com"],
        max_rate_per_minute=60,
    )
    return TechniqueContext(
        run_id="run-1", scenario_id="s1", feed_id="f1", scope=scope,
        params={"targets": [{"email": "victim@test.example.com", "first_name": "V"}]},
    )


def _gophish_client():
    client = MagicMock()
    client.create_group.return_value = {"id": 1}
    client.create_template.return_value = {"id": 2}
    client.create_page.return_value = {"id": 3}
    client.list_smtp.return_value = [{"id": 1, "name": "smtp"}]
    client.create_campaign.return_value = {"id": 42}
    client.get_campaign_summary.return_value = {
        "stats": {"sent": 1, "opened": 1, "clicked": 1, "submitted_data": 0}
    }
    return client


@pytest.mark.parametrize(
    "module,cls",
    [
        ("redgnat.techniques.phishing.spearphishing_link", SpearphishingLinkTechnique),
        ("redgnat.techniques.phishing.spearphishing_attachment", SpearphishingAttachmentTechnique),
        ("redgnat.techniques.phishing.mfa_phishing", MFAPhishingTechnique),
        ("redgnat.techniques.identity.oauth_abuse", OAuthAbuseTechnique),
    ],
)
def test_success_path(module, cls):
    client = _gophish_client()
    with patch("redgnat.config.RedGNATConfig", return_value=_cfg()), \
         patch(f"{module}.GoPhishClient", return_value=client), \
         patch(f"{module}.time.sleep", lambda *_: None):
        result = cls().execute(_ctx())
    assert result.status == ResultStatus.SUCCESS
    client.create_campaign.assert_called_once()


@pytest.mark.parametrize(
    "module,cls",
    [
        ("redgnat.techniques.phishing.spearphishing_link", SpearphishingLinkTechnique),
        ("redgnat.techniques.phishing.spearphishing_attachment", SpearphishingAttachmentTechnique),
        ("redgnat.techniques.phishing.mfa_phishing", MFAPhishingTechnique),
        ("redgnat.techniques.identity.oauth_abuse", OAuthAbuseTechnique),
    ],
)
def test_teardown_on_error(module, cls):
    client = _gophish_client()
    client.create_campaign.side_effect = RuntimeError("gophish 500")
    with patch("redgnat.config.RedGNATConfig", return_value=_cfg()), \
         patch(f"{module}.GoPhishClient", return_value=client), \
         patch(f"{module}.time.sleep", lambda *_: None):
        result = cls().execute(_ctx())
    assert result.status == ResultStatus.ERROR
    # teardown deletes the created page/template/group after the failure
    client.delete_page.assert_called_once()
    client.delete_template.assert_called_once()
    client.delete_group.assert_called_once()


def test_not_configured_blocks():
    cfg = _cfg()
    cfg.gophish_base_url = ""
    with patch("redgnat.config.RedGNATConfig", return_value=cfg):
        result = SpearphishingLinkTechnique().execute(_ctx())
    assert result.status == ResultStatus.BLOCKED


def test_out_of_scope_target_blocks():
    with patch("redgnat.config.RedGNATConfig", return_value=_cfg()):
        scope = Scope(target_domains=["other.example.com"], max_rate_per_minute=60)
        ctx = TechniqueContext(
            run_id="r", scenario_id="s", feed_id="f", scope=scope,
            params={"targets": [{"email": "victim@test.example.com"}]},
        )
        result = SpearphishingLinkTechnique().execute(ctx)
    assert result.status == ResultStatus.BLOCKED
