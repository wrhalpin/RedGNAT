"""
Service Enumeration / Banner Grabbing — T1046 (service fingerprinting variant)

Connects to discovered open ports and captures service banners.
Provides richer service identification than nmap version detection alone.

Emulation only: read-only banner capture, no exploitation.
"""
from __future__ import annotations

import logging
import socket
import ssl
from typing import Any

from redgnat.orm.models import ResultStatus
from redgnat.techniques.base import Technique, TechniqueContext

logger = logging.getLogger(__name__)

# Well-known probes per port
_PORT_PROBES: dict[int, bytes] = {
    21: b"",          # FTP — server sends banner on connect
    22: b"",          # SSH — server sends banner on connect
    23: b"",          # Telnet
    25: b"",          # SMTP
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",         # POP3
    143: b"",         # IMAP
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    445: b"",         # SMB — banner-level only
    3306: b"",        # MySQL
    3389: b"",        # RDP — version info from TLS handshake
    5432: b"",        # PostgreSQL
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}

_CONNECT_TIMEOUT = 3.0
_RECV_SIZE = 1024


class ServiceEnumTechnique(Technique):
    """
    ATT&CK T1046 — Service Banner Enumeration.

    Iterates over findings from a prior NetworkScanTechnique run (or a
    manually specified host:port list) and captures service banners.

    Parameters (ctx.params)
    -----------------------
    targets : list[dict]
        List of {"host": "x.x.x.x", "port": 22, "protocol": "tcp"} dicts.
        If not provided, technique returns PARTIAL with an explanation.
    connect_timeout : float
        Socket connect timeout in seconds (default 3.0).
    use_tls_ports : list[int]
        Ports that require TLS wrapping (default: [443, 8443, 3389]).
    """

    technique_id = "T1046"
    tactic = "discovery"
    name = "Service Banner Enumeration"
    emulation_only = True

    def execute(self, ctx: TechniqueContext) -> Any:
        targets: list[dict] = ctx.params.get("targets", [])
        timeout = float(ctx.params.get("connect_timeout", _CONNECT_TIMEOUT))
        tls_ports = set(ctx.params.get("use_tls_ports", [443, 8443, 3389]))

        if ctx.scope.dry_run:
            return self._dry_run_result(
                ctx,
                f"Would banner-grab {len(targets)} service endpoints",
            )

        if not targets:
            return self._make_result(
                ctx,
                ResultStatus.PARTIAL,
                findings=[{
                    "note": "No targets provided. Run NetworkScanTechnique first and "
                            "pass its findings as ctx.params['targets']."
                }],
            )

        findings: list[dict] = []
        for target in targets:
            host = target.get("host", "")
            port = int(target.get("port", 0))
            proto = target.get("protocol", "tcp")

            if not host or not port:
                continue

            try:
                self._check_scope_ip(ctx.scope, host)
            except Exception:
                logger.debug("ServiceEnum: %s:%s out of scope — skipping", host, port)
                continue

            banner = self._grab_banner(host, port, timeout, use_tls=(port in tls_ports))
            findings.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "banner": banner,
                    "banner_length": len(banner) if banner else 0,
                }
            )
            self._rate_sleep(ctx.scope)

        return self._make_result(ctx, ResultStatus.SUCCESS, findings)

    def _grab_banner(
        self, host: str, port: int, timeout: float, use_tls: bool
    ) -> str | None:
        probe = _PORT_PROBES.get(port, b"")
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx_ssl = ssl.create_default_context()
                ctx_ssl.check_hostname = False
                ctx_ssl.verify_mode = ssl.CERT_NONE
                sock = ctx_ssl.wrap_socket(sock, server_hostname=host)
            if probe:
                sock.sendall(probe)
            banner = sock.recv(_RECV_SIZE)
            sock.close()
            return banner.decode("utf-8", errors="replace").strip()
        except Exception as exc:
            logger.debug("Banner grab %s:%s failed: %s", host, port, exc)
            return None
