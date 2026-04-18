"""
Network Service Discovery — T1046, T1595.001

Performs nmap-based network scanning against in-scope CIDR ranges.
Emulation only: discovers open ports and services but performs no exploitation.

External dependency: nmap must be installed on the host (apt install nmap).
Python binding: python-nmap (pip install python-nmap).
"""
from __future__ import annotations

import logging
import shutil
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import OutOfScopeError, Scope, Technique, TechniqueContext

logger = logging.getLogger(__name__)

# Default scan profile: SYN scan, service version detection, top 1000 ports
_DEFAULT_ARGS = "-sS -sV --top-ports 1000 -T3 --open"
# Faster profile for large ranges
_FAST_ARGS = "-sS --top-ports 100 -T4 --open"


class NetworkScanTechnique(Technique):
    """
    ATT&CK T1046 — Network Service Discovery.

    Scans the target ranges defined in scope for open ports and service banners.
    Results identify exposure surface for subsequent techniques.

    Parameters (ctx.params)
    -----------------------
    nmap_args : str
        Custom nmap argument string (default: _DEFAULT_ARGS).
    target_ranges : list[str]
        Override scope.target_ranges for this step only.
    """

    technique_id = "T1046"
    tactic = "discovery"
    name = "Network Service Discovery"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        if ctx.scope.dry_run:
            ranges = ctx.params.get("target_ranges", ctx.scope.target_ranges)
            return self._dry_run_result(
                ctx, f"Would scan {ranges} with nmap for open ports and services"
            )

        if not shutil.which("nmap"):
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[],
                error="nmap not found on PATH — install nmap and retry",
            )

        target_ranges = ctx.params.get("target_ranges", ctx.scope.target_ranges)
        if not target_ranges:
            return self._blocked_result(ctx, "No target_ranges configured in scope")

        # Validate all ranges are in scope before scanning
        for cidr in target_ranges:
            if not ctx.scope.allows_cidr(cidr):
                return self._blocked_result(ctx, f"Range {cidr} is not in configured scope")

        nmap_args = ctx.params.get("nmap_args", _DEFAULT_ARGS)
        findings: list[dict] = []
        evidence: list[dict] = []

        try:
            import nmap as nm  # type: ignore[import]
        except ImportError:
            return self._make_result(
                ctx,
                ResultStatus.ERROR,
                findings=[],
                error="python-nmap not installed — pip install python-nmap",
            )

        scanner = nm.PortScanner()

        for cidr in target_ranges:
            logger.info(
                "NetworkScan: scanning %s (args: %s) [run=%s]", cidr, nmap_args, ctx.run_id
            )
            try:
                scanner.scan(hosts=cidr, arguments=nmap_args)
            except nm.PortScannerError as exc:
                logger.warning("nmap scan of %s failed: %s", cidr, exc)
                continue

            for host in scanner.all_hosts():
                if scanner[host].state() != "up":
                    continue
                host_entry: dict[str, Any] = {
                    "host": host,
                    "hostname": scanner[host].hostname(),
                    "state": scanner[host].state(),
                    "open_ports": [],
                }
                for proto in scanner[host].all_protocols():
                    for port, port_info in scanner[host][proto].items():
                        if port_info["state"] == "open":
                            host_entry["open_ports"].append(
                                {
                                    "port": port,
                                    "protocol": proto,
                                    "service": port_info.get("name", ""),
                                    "product": port_info.get("product", ""),
                                    "version": port_info.get("version", ""),
                                    "extrainfo": port_info.get("extrainfo", ""),
                                }
                            )
                if host_entry["open_ports"]:
                    findings.append(host_entry)

                # Raw nmap XML for evidence (trimmed)
                evidence.append(
                    {"host": host, "nmap_data": dict(scanner[host])}
                )

        status = ResultStatus.SUCCESS if findings else ResultStatus.PARTIAL
        logger.info(
            "NetworkScan complete: %d hosts with open ports found across %d ranges",
            len(findings),
            len(target_ranges),
        )
        return self._make_result(ctx, status, findings, evidence)
