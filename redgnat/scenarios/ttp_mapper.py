# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
TTP Mapper — maps ATT&CK technique IDs to tactics and metadata.

This is a static lookup table derived from MITRE ATT&CK Enterprise v15.
Techniques are limited to those implemented or planned in RedGNAT's technique
library. The full ATT&CK matrix is available via the GNAT mitre_attack connector.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueInfo:
    """Static metadata about an ATT&CK technique."""

    technique_id: str
    name: str
    tactic: str
    description: str


# Techniques implemented in RedGNAT's technique library
_TECHNIQUE_MAP: dict[str, TechniqueInfo] = {
    # -----------------------------------------------------------------------
    # Reconnaissance (TA0043)
    # -----------------------------------------------------------------------
    "T1595": TechniqueInfo(
        "T1595", "Active Scanning", "reconnaissance",
        "Adversaries scan victim infrastructure to gather information.",
    ),
    "T1595.001": TechniqueInfo(
        "T1595.001", "Scanning IP Blocks", "reconnaissance",
        "Adversaries scan IP blocks to identify hosts and open ports.",
    ),
    "T1595.002": TechniqueInfo(
        "T1595.002", "Vulnerability Scanning", "reconnaissance",
        "Adversaries scan for vulnerabilities in exposed services.",
    ),
    "T1592": TechniqueInfo(
        "T1592", "Gather Victim Host Information", "reconnaissance",
        "Adversaries gather information about victim hosts.",
    ),
    "T1590": TechniqueInfo(
        "T1590", "Gather Victim Network Information", "reconnaissance",
        "Adversaries gather information about the victim network.",
    ),
    # -----------------------------------------------------------------------
    # Initial Access (TA0001)
    # -----------------------------------------------------------------------
    "T1566": TechniqueInfo(
        "T1566", "Phishing", "initial-access",
        "Adversaries send phishing messages to gain access.",
    ),
    "T1566.001": TechniqueInfo(
        "T1566.001", "Spearphishing Attachment", "initial-access",
        "Adversaries send spearphishing emails with malicious attachments.",
    ),
    "T1566.002": TechniqueInfo(
        "T1566.002", "Spearphishing Link", "initial-access",
        "Adversaries send spearphishing emails with malicious links.",
    ),
    "T1566.004": TechniqueInfo(
        "T1566.004", "Spearphishing Voice", "initial-access",
        "Adversaries use voice calls (vishing) for social engineering.",
    ),
    "T1078": TechniqueInfo(
        "T1078", "Valid Accounts", "initial-access",
        "Adversaries use valid credentials to gain access.",
    ),
    "T1078.004": TechniqueInfo(
        "T1078.004", "Cloud Accounts", "initial-access",
        "Adversaries use valid cloud (Entra/Okta/AWS) credentials.",
    ),
    "T1190": TechniqueInfo(
        "T1190", "Exploit Public-Facing Application", "initial-access",
        "Adversaries exploit vulnerabilities in internet-facing applications.",
    ),
    # -----------------------------------------------------------------------
    # Credential Access (TA0006)
    # -----------------------------------------------------------------------
    "T1110": TechniqueInfo(
        "T1110", "Brute Force", "credential-access",
        "Adversaries attempt to gain access through brute force.",
    ),
    "T1110.003": TechniqueInfo(
        "T1110.003", "Password Spraying", "credential-access",
        "Adversaries use a single or small list of passwords against many accounts.",
    ),
    "T1110.004": TechniqueInfo(
        "T1110.004", "Credential Stuffing", "credential-access",
        "Adversaries use previously breached credential pairs.",
    ),
    "T1621": TechniqueInfo(
        "T1621", "Multi-Factor Authentication Request Generation", "credential-access",
        "Adversaries generate MFA requests to trick users into approving.",
    ),
    "T1528": TechniqueInfo(
        "T1528", "Steal Application Access Token", "credential-access",
        "Adversaries steal OAuth/OIDC tokens via consent phishing.",
    ),
    "T1539": TechniqueInfo(
        "T1539", "Steal Web Session Cookie", "credential-access",
        "Adversaries steal session cookies to bypass authentication.",
    ),
    # -----------------------------------------------------------------------
    # Discovery (TA0007)
    # -----------------------------------------------------------------------
    "T1046": TechniqueInfo(
        "T1046", "Network Service Discovery", "discovery",
        "Adversaries scan for open ports and running services.",
    ),
    "T1135": TechniqueInfo(
        "T1135", "Network Share Discovery", "discovery",
        "Adversaries look for network shares (SMB, NFS).",
    ),
    "T1018": TechniqueInfo(
        "T1018", "Remote System Discovery", "discovery",
        "Adversaries look for other hosts in the environment.",
    ),
    "T1069": TechniqueInfo(
        "T1069", "Permission Groups Discovery", "discovery",
        "Adversaries find group memberships to identify privilege escalation paths.",
    ),
    "T1069.002": TechniqueInfo(
        "T1069.002", "Domain Groups", "discovery",
        "Adversaries enumerate domain group memberships via LDAP.",
    ),
    "T1069.003": TechniqueInfo(
        "T1069.003", "Cloud Groups", "discovery",
        "Adversaries enumerate cloud identity groups (Entra/Okta/AWS IAM).",
    ),
    "T1087": TechniqueInfo(
        "T1087", "Account Discovery", "discovery",
        "Adversaries find valid accounts to target.",
    ),
    "T1087.002": TechniqueInfo(
        "T1087.002", "Domain Account", "discovery",
        "Adversaries enumerate domain accounts via LDAP/AD.",
    ),
    "T1087.004": TechniqueInfo(
        "T1087.004", "Cloud Account", "discovery",
        "Adversaries enumerate cloud accounts (Entra/Okta/AWS IAM).",
    ),
    "T1482": TechniqueInfo(
        "T1482", "Domain Trust Discovery", "discovery",
        "Adversaries enumerate domain trusts to find lateral movement paths.",
    ),
    "T1526": TechniqueInfo(
        "T1526", "Cloud Service Discovery", "discovery",
        "Adversaries enumerate cloud services and resources.",
    ),
}


class TTPMapper:
    """
    Resolves ATT&CK technique IDs to metadata and tactics.

    Techniques not in the static map return sensible defaults —
    this allows RedGNAT to accept any ATT&CK ID from intel feeds
    even if a technique module hasn't been implemented yet.
    """

    def get(self, technique_id: str) -> TechniqueInfo | None:
        """Return TechniqueInfo for a technique ID, or None if not in the static map."""
        return _TECHNIQUE_MAP.get(technique_id)

    def technique_tactic(self, technique_id: str) -> str:
        """Return the tactic name for a technique ID, or 'unknown'."""
        info = _TECHNIQUE_MAP.get(technique_id)
        if info:
            return info.tactic
        # Try parent technique for subtechniques
        parent = technique_id.split(".")[0]
        info = _TECHNIQUE_MAP.get(parent)
        return info.tactic if info else "unknown"

    def technique_name(self, technique_id: str) -> str:
        """Return the human-readable name for a technique ID, or the ID itself."""
        info = _TECHNIQUE_MAP.get(technique_id)
        return info.name if info else technique_id

    def all_technique_ids(self) -> list[str]:
        """Return all technique IDs in the static map."""
        return list(_TECHNIQUE_MAP.keys())
