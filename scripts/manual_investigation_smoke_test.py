#!/usr/bin/env python3
"""Manually run the real Sherlock and Maigret collectors through UTI."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from uti.collectors import MaigretCollector, SherlockCollector  # noqa: E402
from uti.services import InvestigationResult, InvestigationService  # noqa: E402


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Sherlock and Maigret against one authorized research username "
            "and print the unified investigation results."
        )
    )
    parser.add_argument("username", help="authorized synthetic or research username to investigate")
    parser.add_argument("--sherlock-executable", default="sherlock", help="Sherlock executable or full path")
    parser.add_argument("--maigret-executable", default="maigret", help="Maigret executable or full path")
    parser.add_argument("--timeout-seconds", type=float, default=600.0, help="overall timeout per collector")
    parser.add_argument(
        "--sherlock-request-timeout-seconds",
        type=float,
        default=10.0,
        help="Sherlock per-site request timeout",
    )
    parser.add_argument(
        "--maigret-request-timeout-seconds",
        type=float,
        default=30.0,
        help="Maigret per-site request timeout",
    )
    parser.add_argument("--max-connections", type=int, default=20, help="Maigret maximum concurrent connections")
    return parser.parse_args()


def _print_investigation(result: InvestigationResult) -> None:
    print(f"Unified-UTI investigation: {result.username}")
    print("Ownership safeguard: every Finding must remain UNVERIFIED; identity_verified must remain False.")

    findings_by_tool = {
        "sherlock": [item for item in result.normalized_findings if item.source_tool.casefold() == "sherlock"],
        "maigret": [item for item in result.normalized_findings if item.source_tool.casefold() == "maigret"],
    }
    summaries = {item.collector_name: item for item in result.collector_summaries}
    print("\nCollector execution:")
    for collector_name in ("sherlock", "maigret"):
        summary = summaries.get(collector_name)
        if summary is None:
            print(f"- {collector_name}: no execution summary")
            continue
        if summary.timed_out:
            status = "TIMED OUT"
        elif summary.error:
            status = "FAILED"
        elif summary.returncode == 0:
            status = "COMPLETED"
        elif summary.returncode is not None:
            status = f"EXITED WITH STATUS {summary.returncode}"
        else:
            status = "FAILED BEFORE RETURNING AN EXIT STATUS"
        print(
            f"- {collector_name}: {status}; returncode={summary.returncode}; "
            f"findings={summary.findings_count}; timeout={summary.timed_out}"
        )
        if summary.error:
            print(f"  error: {summary.error}")
        if summary.stderr.strip():
            print(f"  stderr: {summary.stderr.strip()}")

    print("\nFindings per collector (before deduplication):")
    for collector_name in ("sherlock", "maigret"):
        tool_findings = findings_by_tool[collector_name]
        print(f"- {collector_name}: {len(tool_findings)}")
        for finding in tool_findings:
            print(f"  {finding.platform}: {finding.profile_url}")
            print(
                f"    profile_check={finding.profile_check_status.value}; "
                f"ownership={finding.ownership_status.value}; "
                f"identity_verified={finding.identity_verified}"
            )

    print(f"\nTotal normalized findings: {len(result.normalized_findings)}")
    print(f"Deduplicated findings: {len(result.deduplicated_findings)}")
    for finding in result.deduplicated_findings:
        print(
            f"- {finding.username} @ {finding.platform}: {finding.profile_url}; "
            f"sources={', '.join(finding.source_tools)}; "
            f"ownership={finding.ownership_status.value}; "
            f"identity_verified={finding.identity_verified}"
        )

    print(f"\nCorrelation results: {len(result.correlation_results)}")
    for index, group in enumerate(result.correlation_results, start=1):
        print(f"- group {index}: {group.interpretation}")
        print(f"  same_profile_candidate={group.same_profile_candidate}")
        for reason in group.reasons:
            print(f"  reason: {reason}")

    print("\nFinding assessments (no aggregate quality or identity score):")
    for assessment in result.assessments:
        finding = assessment.finding
        print(f"- {finding.platform}: {finding.profile_url}")
        for outcome in assessment.profile_check_outcomes:
            print(
                f"  profile check: {outcome.outcome.value}; collector={outcome.collector_name}; "
                f"reported_status={outcome.reported_status.value}; at={outcome.collected_at.isoformat()}"
            )
        print(f"  source independence: {assessment.source_independence.value}")
        for field in assessment.record_completeness.fields:
            print(f"  record field {field.name}: {field.state.value}")
        print(
            f"  ownership={assessment.ownership_status.value}; "
            f"identity_verified={assessment.identity_verified}"
        )

    print(f"\nWarnings: {len(result.warnings)}")
    for warning in result.warnings:
        print(f"- {warning}")

    print(f"\nErrors: {len(result.errors)}")
    for error in result.errors:
        print(f"- {error}")

    safeguards_hold = all(
        finding.ownership_status.value == "unverified" and finding.identity_verified is False
        for finding in (
            result.normalized_findings
            + result.deduplicated_findings
            + tuple(assessment.finding for assessment in result.assessments)
        )
    )
    print(f"\nOwnership safeguards verified for all returned findings: {safeguards_hold}")


def main() -> int:
    args = _arguments()
    try:
        sherlock = SherlockCollector(
            executable=args.sherlock_executable,
            timeout_seconds=args.timeout_seconds,
            request_timeout_seconds=args.sherlock_request_timeout_seconds,
        )
        maigret = MaigretCollector(
            executable=args.maigret_executable,
            timeout_seconds=args.timeout_seconds,
            request_timeout_seconds=args.maigret_request_timeout_seconds,
            max_connections=args.max_connections,
        )
    except (TypeError, ValueError, OSError) as exc:
        print(f"Invalid collector configuration: {exc}", file=sys.stderr)
        return 2

    service = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret)
    try:
        result = service.investigate(args.username)
    except (TypeError, ValueError) as exc:
        print(f"Could not start investigation: {exc}", file=sys.stderr)
        return 2

    _print_investigation(result)
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
