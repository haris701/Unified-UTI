"""Synthetic tests for the Sherlock subprocess adapter; no searches are run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from uti.collectors.sherlock import SherlockCollector, SherlockOutputError, parse_sherlock_csv
from uti.models import ValidationStatus


SYNTHETIC_CSV = """username,name,url_main,url_user,exists,http_status,response_time_s
uti_test_account_42,ExampleSocial,https://social.example/,https://social.example/uti_test_account_42,Claimed,200,0.25
"""
CSV_HEADER = "username,name,url_main,url_user,exists,http_status,response_time_s\n"
COLLECTED_AT = datetime(2026, 1, 2, tzinfo=timezone.utc)


def eight_candidate_rows_csv() -> str:
    """Return eight fictional rows using the observed Sherlock 0.16.2 schema."""
    rows = [CSV_HEADER]
    for index in range(1, 9):
        rows.append(
            f"uti_demo_test_2026,ExampleSite{index},https://site{index}.example/,"
            f"https://site{index}.example/uti_demo_test_2026,Claimed,20{index},{index / 10:.1f}\n"
        )
    return "".join(rows)


def mixed_url_quality_csv() -> str:
    return CSV_HEADER + """uti_demo_test_2026,ValidOne,https://one.example/,https://one.example/uti_demo_test_2026,Claimed,200,0.1
uti_demo_test_2026,InvalidHost,https://omg.lol/,https://uti_demo_test_2026.omg.lol,Claimed,200,0.2
uti_demo_test_2026,ValidTwo,https://two.example/,https://two.example/uti_demo_test_2026,Claimed,200,0.3
"""


class SherlockCsvParserTests(unittest.TestCase):
    def test_header_only_csv_means_no_findings(self) -> None:
        header = "username,name,url_main,url_user,exists,http_status,response_time_s\n"
        self.assertEqual(
            parse_sherlock_csv(header, queried_username="uti_test_account_42", collected_at=COLLECTED_AT),
            (),
        )

    def test_parses_documented_csv_and_preserves_provenance(self) -> None:
        findings = parse_sherlock_csv(
            SYNTHETIC_CSV,
            queried_username="uti_test_account_42",
            collected_at=COLLECTED_AT,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.username, "uti_test_account_42")
        self.assertEqual(finding.platform, "ExampleSocial")
        self.assertEqual(finding.profile_url, "https://social.example/uti_test_account_42")
        self.assertEqual(finding.source_tool, "sherlock")
        self.assertEqual(finding.validation_status, ValidationStatus.VALID)
        self.assertEqual(finding.profile_check_status, ValidationStatus.VALID)
        self.assertEqual(finding.ownership_status.value, "unverified")
        self.assertFalse(finding.identity_verified)
        self.assertEqual(finding.collected_at, COLLECTED_AT)
        self.assertEqual(finding.source_lineage[0].collector_name, "sherlock")
        self.assertIsNone(finding.source_lineage[0].underlying_data_source)
        self.assertEqual(finding.evidence_provenance[0].evidence_type, "sherlock_presence_report")
        self.assertEqual(
            finding.evidence_provenance[0].original_source_url,
            "https://social.example/uti_test_account_42",
        )
        self.assertIn("http_status=200", finding.evidence[0])
        self.assertIn("response_time_s=0.25", finding.evidence[0])
        self.assertIn("ownership=unverified", finding.evidence[0])
        self.assertIn("status=Claimed", finding.evidence[0])

    def test_parser_retains_untrimmed_raw_csv_fields_separately(self) -> None:
        content = CSV_HEADER + (
            'uti_test_account_42,ExampleSocial,https://social.example/, '
            'https://Social.example/uti_test_account_42 ,Claimed,200,0.25\n'
        )
        parsed = parse_sherlock_csv(content, queried_username="uti_test_account_42", collected_at=COLLECTED_AT)
        self.assertEqual(parsed[0].profile_url, "https://Social.example/uti_test_account_42")
        self.assertEqual(parsed.raw_records[0].as_mapping()["url_user"], " https://Social.example/uti_test_account_42 ")

    def test_parses_eight_rows_from_the_reported_sherlock_schema(self) -> None:
        findings = parse_sherlock_csv(
            eight_candidate_rows_csv(),
            queried_username="uti_demo_test_2026",
            collected_at=COLLECTED_AT,
        )
        self.assertEqual(len(findings), 8)
        self.assertEqual(findings[0].platform, "ExampleSite1")
        self.assertEqual(findings[0].profile_url, "https://site1.example/uti_demo_test_2026")
        self.assertIn("http_status=201", findings[0].evidence[0])
        self.assertIn("response_time_s=0.1", findings[0].evidence[0])
        self.assertEqual(findings[0].source_lineage[0].collector_name, "sherlock")

    def test_maps_documented_status_values_without_claiming_identity(self) -> None:
        csv_text = """username,name,url_main,url_user,exists,http_status,response_time_s
uti_test_account_42,ExampleSocial,https://social.example/,https://social.example/a,Available,404,0.1
"""
        finding = parse_sherlock_csv(csv_text, queried_username="uti_test_account_42")[0]
        self.assertEqual(finding.validation_status, ValidationStatus.INVALID)
        self.assertNotIn("identity", finding.evidence[0].casefold())

    def test_rejects_incompatible_schema_and_wrong_username(self) -> None:
        with self.assertRaisesRegex(SherlockOutputError, "missing columns"):
            parse_sherlock_csv("username,name\n", queried_username="uti_test_account_42")
        mismatched = SYNTHETIC_CSV.replace("uti_test_account_42,ExampleSocial", "someone_else,ExampleSocial")
        with self.assertRaisesRegex(SherlockOutputError, "does not match"):
            parse_sherlock_csv(mismatched, queried_username="uti_test_account_42")

    def test_rejects_unexpected_csv_columns(self) -> None:
        unexpected = SYNTHETIC_CSV.replace("response_time_s\n", "response_time_s,extra_field\n")
        with self.assertRaisesRegex(SherlockOutputError, "unexpected columns: extra_field"):
            parse_sherlock_csv(unexpected, queried_username="uti_test_account_42")

    def test_rejects_structurally_incomplete_csv_row(self) -> None:
        incomplete = CSV_HEADER + "uti_test_account_42,ExampleSocial,https://social.example/,https://social.example/a,Claimed,200\n"
        with self.assertRaisesRegex(SherlockOutputError, "incomplete Sherlock CSV row"):
            parse_sherlock_csv(incomplete, queried_username="uti_test_account_42")

    def test_rejects_invalid_profile_urls_and_unknown_status(self) -> None:
        invalid_url = SYNTHETIC_CSV.replace(
            "https://social.example/uti_test_account_42,Claimed",
            "javascript:alert(1),Claimed",
        )
        parsed = parse_sherlock_csv(invalid_url, queried_username="uti_test_account_42")
        self.assertEqual(parsed, ())
        self.assertEqual(len(parsed.warnings), 1)
        self.assertIn("invalid profile URL", parsed.warnings[0])
        unknown_status = SYNTHETIC_CSV.replace(",Claimed,", ",Maybe,", 1)
        with self.assertRaisesRegex(SherlockOutputError, "unrecognized Sherlock status"):
            parse_sherlock_csv(unknown_status, queried_username="uti_test_account_42")

    def test_skips_one_invalid_hostname_and_keeps_valid_rows_before_and_after(self) -> None:
        parsed = parse_sherlock_csv(
            mixed_url_quality_csv(),
            queried_username="uti_demo_test_2026",
            collected_at=COLLECTED_AT,
        )
        self.assertEqual([finding.platform for finding in parsed], ["ValidOne", "ValidTwo"])
        self.assertEqual(len(parsed.warnings), 1)
        self.assertIn("CSV line 3", parsed.warnings[0])
        self.assertIn("invalid hostname", parsed.warnings[0])
        self.assertTrue(all(finding.ownership_status.value == "unverified" for finding in parsed))
        self.assertTrue(all(not finding.identity_verified for finding in parsed))

    def test_only_invalid_profile_urls_returns_no_findings_and_row_warning(self) -> None:
        only_invalid = CSV_HEADER + (
            "uti_demo_test_2026,InvalidHost,https://omg.lol/,"
            "https://uti_demo_test_2026.omg.lol,Claimed,200,0.2\n"
        )
        parsed = parse_sherlock_csv(only_invalid, queried_username="uti_demo_test_2026")
        self.assertEqual(parsed, ())
        self.assertEqual(len(parsed.warnings), 1)
        self.assertIn("CSV line 2", parsed.warnings[0])
        self.assertIn("invalid hostname", parsed.warnings[0])


class SherlockCollectorTests(unittest.TestCase):
    def test_runs_list_arguments_and_captures_process_output(self) -> None:
        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / "uti_test_account_42.csv").write_text(SYNTHETIC_CSV, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "synthetic stdout", "synthetic stderr")

        executable = str(Path.cwd() / "custom tools" / "sherlock")
        collector = SherlockCollector(executable=executable, timeout_seconds=42, request_timeout_seconds=10)
        with patch("uti.collectors.sherlock.subprocess.run", side_effect=fake_run) as run_mock:
            result = collector.collect("uti_test_account_42")

        command = run_mock.call_args.args[0]
        kwargs = run_mock.call_args.kwargs
        self.assertIsInstance(command, list)
        self.assertEqual(command[0], executable)
        self.assertEqual(command[-2:], ["--", "uti_test_account_42"])
        self.assertIn("--csv", command)
        self.assertIn("--folderoutput", command)
        self.assertEqual(command[command.index("--timeout") + 1], "10")
        self.assertEqual(Path(command[command.index("--folderoutput") + 1]), Path(kwargs["cwd"]))
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["timeout"], 42)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "synthetic stdout")
        self.assertEqual(result.stderr, "synthetic stderr")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.raw_records), 1)
        self.assertEqual(result.raw_records[0].as_mapping()["url_user"], "https://social.example/uti_test_account_42")

    def test_returns_nonzero_exit_code_and_keeps_parseable_partial_results(self) -> None:
        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / "uti_test_account_42.csv").write_text(SYNTHETIC_CSV, encoding="utf-8")
            return subprocess.CompletedProcess(command, 2, "partial output", "synthetic error")

        with patch("uti.collectors.sherlock.subprocess.run", side_effect=fake_run):
            result = SherlockCollector().collect("uti_test_account_42")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("status 2", result.error or "")
        self.assertEqual(result.stderr, "synthetic error")

    def test_missing_csv_file_is_reported(self) -> None:
        completed = subprocess.CompletedProcess(["sherlock"], 0, "done", "")
        with patch("uti.collectors.sherlock.subprocess.run", return_value=completed):
            result = SherlockCollector().collect("uti_test_account_42")
        self.assertEqual(result.findings, ())
        self.assertIn("did not create its expected CSV", result.error or "")

    def test_malformed_csv_file_is_reported(self) -> None:
        malformed_csv = CSV_HEADER + 'uti_test_account_42,"unterminated,https://social.example/,https://social.example/a,Claimed,200,0.2\n'

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / "uti_test_account_42.csv").write_text(malformed_csv, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("uti.collectors.sherlock.subprocess.run", side_effect=fake_run):
            result = SherlockCollector().collect("uti_test_account_42")
        self.assertEqual(result.findings, ())
        self.assertIn("could not parse Sherlock CSV", result.error or "")

    def test_skipped_row_warning_is_exposed_in_run_result(self) -> None:
        csv_text = mixed_url_quality_csv()

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            folder = Path(command[command.index("--folderoutput") + 1])
            (folder / "uti_demo_test_2026.csv").write_text(csv_text, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("uti.collectors.sherlock.subprocess.run", side_effect=fake_run):
            result = SherlockCollector().collect("uti_demo_test_2026")
        self.assertEqual([finding.platform for finding in result.findings], ["ValidOne", "ValidTwo"])
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("CSV line 3", result.warnings[0])
        self.assertIsNone(result.error)

    def test_timeout_is_reported_with_captured_partial_output(self) -> None:
        timeout = subprocess.TimeoutExpired("sherlock", 1, output=b"partial", stderr=b"still working")
        with patch("uti.collectors.sherlock.subprocess.run", side_effect=timeout):
            result = SherlockCollector(timeout_seconds=1).collect("uti_test_account_42")
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.returncode)
        self.assertEqual(result.stdout, "partial")
        self.assertEqual(result.stderr, "still working")
        self.assertIn("timeout", result.error or "")

    def test_missing_executable_is_reported_without_raising(self) -> None:
        with patch("uti.collectors.sherlock.subprocess.run", side_effect=FileNotFoundError("not installed")):
            result = SherlockCollector(executable="missing-sherlock").collect("uti_test_account_42")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.findings, ())
        self.assertIn("could not execute Sherlock", result.error or "")

    def test_output_filename_username_is_validated_before_execution(self) -> None:
        with patch("uti.collectors.sherlock.subprocess.run") as run_mock:
            with self.assertRaisesRegex(ValueError, "unsafe"):
                SherlockCollector().collect("../synthetic")
        run_mock.assert_not_called()

    def test_rejects_invalid_timeout_configuration(self) -> None:
        for timeout in (0, -1, float("inf"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                SherlockCollector(timeout_seconds=timeout)
            with self.subTest(request_timeout=timeout), self.assertRaises(ValueError):
                SherlockCollector(request_timeout_seconds=timeout)


if __name__ == "__main__":
    unittest.main()
