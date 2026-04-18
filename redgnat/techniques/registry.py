"""
TECHNIQUE_REGISTRY — maps ATT&CK technique IDs to Technique classes.

To add a new technique:
1. Create the module in the appropriate tactic subdirectory
2. Subclass Technique with correct technique_id
3. Add an entry here: TECHNIQUE_REGISTRY["T1234.001"] = MyTechnique
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from redgnat.techniques.base import Technique

# ------------------------------------------------------------------
# Registry — populated at module import time
# ------------------------------------------------------------------
# Discovery
from redgnat.techniques.discovery.network_scan import NetworkScanTechnique
from redgnat.techniques.discovery.ad_enum import ADEnumTechnique
from redgnat.techniques.discovery.service_enum import ServiceEnumTechnique
from redgnat.techniques.discovery.cloud_enum import CloudEnumTechnique

# Phishing
from redgnat.techniques.phishing.spearphishing_link import SpearphishingLinkTechnique
from redgnat.techniques.phishing.spearphishing_attachment import SpearphishingAttachmentTechnique
from redgnat.techniques.phishing.mfa_phishing import MFAPhishingTechnique

# Identity
from redgnat.techniques.identity.password_spray import PasswordSprayTechnique
from redgnat.techniques.identity.credential_stuffing import CredentialStuffingTechnique
from redgnat.techniques.identity.mfa_fatigue import MFAFatigueTechnique
from redgnat.techniques.identity.oauth_abuse import OAuthAbuseTechnique
from redgnat.techniques.identity.token_theft import TokenTheftTechnique

TECHNIQUE_REGISTRY: dict[str, Type["Technique"]] = {
    # -----------------------------------------------------------------------
    # Discovery / Reconnaissance
    # -----------------------------------------------------------------------
    "T1046": NetworkScanTechnique,
    "T1595.001": NetworkScanTechnique,
    "T1087.002": ADEnumTechnique,
    "T1069.002": ADEnumTechnique,
    "T1482": ADEnumTechnique,
    "T1046.service": ServiceEnumTechnique,  # extended service banner variant
    "T1087.004": CloudEnumTechnique,
    "T1069.003": CloudEnumTechnique,
    "T1526": CloudEnumTechnique,
    # -----------------------------------------------------------------------
    # Initial Access — Phishing
    # -----------------------------------------------------------------------
    "T1566.002": SpearphishingLinkTechnique,
    "T1566.001": SpearphishingAttachmentTechnique,
    "T1566": MFAPhishingTechnique,  # AiTM phishing
    # -----------------------------------------------------------------------
    # Credential Access / Identity
    # -----------------------------------------------------------------------
    "T1110.003": PasswordSprayTechnique,
    "T1110.004": CredentialStuffingTechnique,
    "T1621": MFAFatigueTechnique,
    "T1528": OAuthAbuseTechnique,
    "T1539": TokenTheftTechnique,
}


def get_technique(technique_id: str) -> "Type[Technique] | None":
    """Return the Technique class for an ATT&CK ID, or None if not registered."""
    return TECHNIQUE_REGISTRY.get(technique_id)


def list_technique_ids() -> list[str]:
    """Return all registered ATT&CK technique IDs."""
    return sorted(TECHNIQUE_REGISTRY.keys())
