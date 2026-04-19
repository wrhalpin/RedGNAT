"""
RedGNAT command-line interface.

Usage
-----
    redgnat status
    redgnat engage --operator <name> --duration <hours>
    redgnat kill [--reason "..."] [--operator <name>]
    redgnat kill --reset [--operator <name>]
    redgnat scenarios
    redgnat runs [--scenario <id>]
"""
from __future__ import annotations

import argparse
import json
import sys


def _config():
    from redgnat.config import RedGNATConfig
    return RedGNATConfig()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    from redgnat.engagement.gate import EngagementGate

    status = EngagementGate(_config()).status()
    print(json.dumps(status, indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# engage
# ---------------------------------------------------------------------------


def cmd_engage(args: argparse.Namespace) -> int:
    from redgnat.engagement.gate import EngagementGate

    cfg = _config()
    gate = EngagementGate(cfg)

    if args.revoke:
        gate.revoke_token()
        print("Engagement token revoked.")
        return 0

    if not args.operator:
        print("ERROR: --operator is required", file=sys.stderr)
        return 1
    if not args.duration or args.duration <= 0:
        print("ERROR: --duration must be a positive number of hours", file=sys.stderr)
        return 1

    try:
        token = gate.authorize(operator=args.operator, duration_hours=args.duration)
    except PermissionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"Engagement authorized.\n"
        f"  token_id  : {token.token_id}\n"
        f"  operator  : {token.operator}\n"
        f"  expires_at: {token.expires_at.isoformat()}\n"
        f"  remaining : {token.remaining_seconds:.0f}s"
    )
    return 0


# ---------------------------------------------------------------------------
# kill
# ---------------------------------------------------------------------------


def cmd_kill(args: argparse.Namespace) -> int:
    from redgnat.engagement.kill_switch import KillSwitch

    ks = KillSwitch(_config())

    if args.reset:
        ks.reset(operator=args.operator or "")
        print("Kill switch reset. Workers may now accept new tasks.")
        return 0

    report = ks.activate(reason=args.reason or "", operator=args.operator or "")
    print(json.dumps(report, indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------


def cmd_scenarios(args: argparse.Namespace) -> int:
    from redgnat.client import RedGNATClient

    client = RedGNATClient()
    scenarios = client.list_scenarios()
    if not scenarios:
        print("No scenarios found.")
        return 0
    for s in scenarios:
        print(f"  {s.scenario_id}  {s.name!r}  status={s.status.value}  techniques={len(s.technique_ids)}")
    return 0


# ---------------------------------------------------------------------------
# runs
# ---------------------------------------------------------------------------


def cmd_runs(args: argparse.Namespace) -> int:
    from redgnat.client import RedGNATClient

    client = RedGNATClient()
    runs = client.list_runs(scenario_id=args.scenario or None)
    if not runs:
        print("No runs found.")
        return 0
    for r in runs:
        started = r.started_at.isoformat() if r.started_at else "-"
        print(f"  {r.run_id}  scenario={r.scenario_id}  status={r.status.value}  started={started}")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redgnat",
        description="RedGNAT — Continuous Automated Red Teaming platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="Show engagement gate and kill switch status")

    # engage
    p_engage = sub.add_parser("engage", help="Authorize or revoke a Phase 2 engagement window")
    p_engage.add_argument("--operator", help="Name of the authorizing operator")
    p_engage.add_argument("--duration", type=float, help="Token lifetime in hours")
    p_engage.add_argument("--revoke", action="store_true", help="Revoke the active token")

    # kill
    p_kill = sub.add_parser("kill", help="Activate or reset the global kill switch")
    p_kill.add_argument("--reason", help="Human-readable reason for kill")
    p_kill.add_argument("--operator", help="Operator identity")
    p_kill.add_argument("--reset", action="store_true", help="Clear the kill switch")

    # scenarios
    sub.add_parser("scenarios", help="List emulation scenarios")

    # runs
    p_runs = sub.add_parser("runs", help="List emulation runs")
    p_runs.add_argument("--scenario", help="Filter by scenario ID")

    args = parser.parse_args(argv)

    dispatch = {
        "status": cmd_status,
        "engage": cmd_engage,
        "kill": cmd_kill,
        "scenarios": cmd_scenarios,
        "runs": cmd_runs,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
