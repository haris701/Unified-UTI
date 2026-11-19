"""Synthetic tests for Maigret adapter; subprocess and network are mocked."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from uti.collectors import MaigretCollector, MaigretOutputError, parse_maigret_csv
from uti.models import OwnershipVerificationStatus, ValidationStatus


HEADER = "username,name,url_main,url_user,exists,http_status,error_reason\n"
USERNAME = "uti_demo_test_2026"
COLLECTED_AT = datetime(2026, 4, 5, tzinfo=timezone.utc)


def csv_row(
    status: str,
    *,
    platform: str = "SyntheticSite",
    url: str = "https://social.example/uti_demo_test_2026",
    http_status: str = "200",
    reason: str = "",
    username: str = USERNAME,
) -> str:
    return f"{username},{platform},https://social.example/,{url},{status},{http_status},{reason}\n"


class MaigretCsvParserTests(unittest.TestCase):
    def test_parser_retains_original_url_field_before_normalization(self) -> None:
        original_url = " https://Social.example/uti_demo_test_2026 "
        parsed = parse_maigret_csv(HEADER + csv_row("Claimed", url=original_url), queried_username=USERNAME)
        self.assertEqual(parsed[0].profile_url, original_url.strip())
        self.assertEqual(parsed.raw_records[0].as_mapping()["url_user"], original_url)

    def test_only_claimed_creates_candidate_and_preserves_provenance(self) -> None:
        content = HEADER + csv_row("Claimed")
        parsed = parse_maigret_csv(content, queried_username=USERNAME, collected_at=COLLECTED_AT)

        self.assertEqual(len(parsed), 1)
        finding = parsed[0]
        self.assertEqual(finding.username, USERNAME)
        self.assertEqual(finding.platform, "SyntheticSite")
        self.assertEqual(finding.profile_url, "https://social.example/uti_demo_test_2026")
        self.assertEqual(finding.profile_check_status, ValidationStatus.VALID)
        self.assertEqual(finding.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
        self.assertFalse(finding.identity_verified)
        self.assertEqual(finding.collected_at, COLLECTED_AT)
        self.assertEqual(finding.source_lineage[0].collector_name, "maigret")
        self.assertIsNone(finding.source_lineage[0].underlying_data_source)
        self.assertEqual(finding.evidence_provenance[0].evidence_type, "maigret_presence_report")
        self.assertEqual(finding.evidence_provenance[0].original_source_url, finding.profile_url)
        self.assertIn("http_status=200", finding.evidence[0])
        self.assertIn("error_reason=none", finding.evidence[0])

    def test_nonclaimed_statuses_are_diagnostics_not_findings(self) -> None:
        content = HEADER + "".join(
            csv_row(status, http_status=code, reason=reason)
            for status, code, reason in (
                ("Available", "404", "not found"),
                ("Unknown", "503", "service unavailable"),
                ("Illegal", "400", "invalid username"),
            )
        )
        parsed = parse_maigret_csv(content, queried_username=USERNAME)

        self.assertEqual(parsed, ())
        self.assertEqual([diagnostic.status for diagnostic in parsed.diagnostics], ["Available", "Unknown", "Illegal"])
        self.assertEqual([diagnostic.outcome for diagnostic in parsed.diagnostics], ["not_found", "inconclusive", "invalid_username"])
        self.assertEqual([diagnostic.http_status for diagnostic in parsed.diagnostics], ["404", "503", "400"])
        self.assertEqual([diagnostic.error_reason for diagnostic in parsed.diagnostics], ["not found", "service unavailable", "invalid username"])
        self.assertEqual([diagnostic.line_number for diagnostic in parsed.diagnostics], [2, 3, 4])

    def test_observed_statuses_do_not_require_profile_url_unless_claimed(self) -> None:
        content = HEADER
        content += csv_row("Illegal", url="", reason="invalid username")
        content += csv_row("Unknown", url="https://social.example/uti_demo_test_2026", reason="check inconclusive")
        content += csv_row("Available", url="https://social.example/uti_demo_test_2026", reason="not found")
        parsed = parse_maigret_csv(content, queried_username=USERNAME)

        self.assertEqual(parsed, ())
        self.assertEqual([item.outcome for item in parsed.diagnostics], ["invalid_username", "inconclusive", "not_found"])
        self.assertEqual(parsed.diagnostics[0].profile_url, "")
        self.assertEqual(parsed.warnings, ())

    def test_claimed_with_invalid_or_empty_profile_url_is_skipped(self) -> None:
        content = HEADER
        content += csv_row("Claimed", platform="InvalidUrl", url="javascript:alert(1)")
        content += csv_row("Claimed", platform="EmptyUrl", url="")
        parsed = parse_maigret_csv(content, queried_username=USERNAME)

        self.assertEqual(parsed, ())
        self.assertEqual(len(parsed.warnings), 2)
        self.assertTrue(all("invalid profile URL" in warning for warning in parsed.warnings))
        self.assertIn("line 2", parsed.warnings[0])
        self.assertIn("line 3", parsed.warnings[1])
        self.assertTrue(all(item.outcome == "invalid_profile_url" for item in parsed.diagnostics))

    def test_unknown_future_status_is_diagnostic_not_positive(self) -> None:
        parsed = parse_maigret_csv(HEADER + csv_row("Maybe"), queried_username=USERNAME)
        self.assertEqual(parsed, ())
        self.assertEqual(parsed.diagnostics[0].status, "Maybe")
        self.assertEqual(parsed.diagnostics[0].outcome, "unrecognized_status")

    def test_mixed_rows_retain_claimed_and_skip_invalid_url_and_bad_row(self) -> None:
        content = HEADER + csv_row("Claimed", platform="Before")
        content += csv_row("Claimed", platform="BadHost", url="https://uti_demo_test_2026.invalid_host.example/profile")
        content += csv_row("Claimed", platform="WrongUser", username="other_user")
        content += csv_row("Claimed", platform="After", url="https://social.example/after")
        parsed = parse_maigret_csv(content, queried_username=USERNAME)

        self.assertEqual([finding.platform for finding in parsed], ["Before", "After"])
        self.assertEqual(len(parsed.warnings), 2)
        self.assertIn("line 3", parsed.warnings[0])
        self.assertIn("invalid hostname", parsed.warnings[0])
        self.assertEqual(parsed.diagnostics[0].outcome, "invalid_profile_url")
        self.assertIn("line 4", parsed.warnings[1])
        self.assertIn("does not match", parsed.warnings[1])

    def test_structurally_malformed_row_is_skipped_with_warning(self) -> None:
        content = HEADER + csv_row("Claimed", platform="Before")
        content += f"{USERNAME},ShortRow,https://social.example/,https://social.example/short,Claimed,200\n"
        content += csv_row("Claimed", platform="After")
        parsed = parse_maigret_csv(content, queried_username=USERNAME)
        self.assertEqual([finding.platform for finding in parsed], ["Before", "After"])
        self.assertIn("line 3", parsed.warnings[0])
        self.assertIn("missing", parsed.warnings[0])

    def test_malformed_csv_syntax_is_rejected(self) -> None:
        content = HEADER + f'{USERNAME},"unterminated,https://social.example/,https://social.example/u,Claimed,200,\n'
        with self.assertRaisesRegex(MaigretOutputError, "could not parse Maigret CSV"):
            parse_maigret_csv(content, queried_username=USERNAME)

    def test_missing_and_extra_columns_are_rejected(self) -> None:
        with self.assertRaisesRegex(MaigretOutputError, "missing columns"):
            parse_maigret_csv("username,name\n", queried_username=USERNAME)
        with self.assertRaisesRegex(MaigretOutputError, "unexpected columns: extra"):
            parse_maigret_csv(HEADER.replace("error_reason\n", "error_reason,extra\n"), queried_username=USERNAME)

    def test_only_invalid_urls_yields_no_findings_and_warning(self) -> None:
        parsed = parse_maigret_csv(
            HEADER + csv_row("Claimed", url="javascript:alert(1)"),
            queried_username=USERNAME,
        )
        self.assertEqual(parsed, ())
        self.assertEqual(len(parsed.warnings), 1)
        self.assertIn("line 2", parsed.warnings[0])


class MaigretCollectorTests(unittest.TestCase):
    def test_invokes_with_safe_csv_json_and_control_flags(self) -> None:
        content = HEADER + csv_row("Claimed")

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / f"report_{USERNAME}.csv").write_text(content, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "synthetic stdout", "synthetic stderr")

        collector = MaigretCollector(executable="custom-maigret", timeout_seconds=77, request_timeout_seconds=12, max_connections=4)
        with patch("uti.collectors.maigret.subprocess.run", side_effect=fake_run) as run_mock:
            result = collector.collect(USERNAME)

        command = run_mock.call_args.args[0]
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(command[0], "custom-maigret")
        self.assertIn("--csv", command)
        self.assertEqual(command[command.index("--json") + 1], "simple")
        self.assertIn("--no-autoupdate", command)
        self.assertIn("--no-recursion", command)
        self.assertEqual(command[command.index("--timeout") + 1], "12")
        self.assertEqual(command[command.index("--max-connections") + 1], "4")
        self.assertEqual(command[-2:], ["--", USERNAME])
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["timeout"], 77)
        self.assertEqual(result.stdout, "synthetic stdout")
        self.assertEqual(result.stderr, "synthetic stderr")
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.raw_records), 1)

    def test_nonclaimed_rows_are_available_in_run_diagnostics(self) -> None:
        content = HEADER + csv_row("Available", reason="not found") + csv_row("Unknown", reason="blocked") + csv_row("Illegal", reason="invalid")

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            Path(command[command.index("--folderoutput") + 1], f"report_{USERNAME}.csv").write_text(content, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("uti.collectors.maigret.subprocess.run", side_effect=fake_run):
            result = MaigretCollector().collect(USERNAME)
        self.assertEqual(result.findings, ())
        self.assertEqual([item.status for item in result.diagnostics], ["Available", "Unknown", "Illegal"])

    def test_timeout_and_execution_errors_are_reported(self) -> None:
        timeout = subprocess.TimeoutExpired("maigret", 1, output=b"partial", stderr=b"working")
        with patch("uti.collectors.maigret.subprocess.run", side_effect=timeout):
            result = MaigretCollector(timeout_seconds=1).collect(USERNAME)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, "partial")
        self.assertEqual(result.stderr, "working")
        self.assertIn("timeout", result.error or "")

        with patch("uti.collectors.maigret.subprocess.run", side_effect=FileNotFoundError("not installed")):
            missing = MaigretCollector().collect(USERNAME)
        self.assertIn("could not execute Maigret", missing.error or "")

    def test_missing_malformed_output_and_nonzero_exit_are_reported(self) -> None:
        completed = subprocess.CompletedProcess(["maigret"], 0, "done", "")
        with patch("uti.collectors.maigret.subprocess.run", return_value=completed):
            missing = MaigretCollector().collect(USERNAME)
        self.assertIn("did not create", missing.error or "")

        malformed = HEADER + f'{USERNAME},"unterminated,https://social.example/,https://social.example/u,Claimed,200,\n'

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            Path(command[command.index("--folderoutput") + 1], f"report_{USERNAME}.csv").write_text(malformed, encoding="utf-8")
            return subprocess.CompletedProcess(command, 2, "partial", "failed")

        with patch("uti.collectors.maigret.subprocess.run", side_effect=fake_run):
            result = MaigretCollector().collect(USERNAME)
        self.assertIn("status 2", result.error or "")
        self.assertIn("could not parse Maigret CSV", result.error or "")
        self.assertEqual(result.findings, ())

    def test_invalid_configuration_and_unsafe_username_rejected(self) -> None:
        for kwargs in (
            {"timeout_seconds": 0},
            {"request_timeout_seconds": float("inf")},
            {"max_connections": 0},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                MaigretCollector(**kwargs)
        with patch("uti.collectors.maigret.subprocess.run") as run_mock:
            with self.assertRaises(ValueError):
                MaigretCollector().collect("../synthetic")
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
