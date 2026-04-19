# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Phishing initial-access techniques (TA0001)."""
from redgnat.techniques.phishing.mfa_phishing import MFAPhishingTechnique
from redgnat.techniques.phishing.spearphishing_attachment import SpearphishingAttachmentTechnique
from redgnat.techniques.phishing.spearphishing_link import SpearphishingLinkTechnique

__all__ = [
    "SpearphishingLinkTechnique",
    "SpearphishingAttachmentTechnique",
    "MFAPhishingTechnique",
]
