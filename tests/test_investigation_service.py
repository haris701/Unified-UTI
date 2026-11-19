"""Synthetic orchestration tests; collector execution is mocked."""

from __future__ import annotations

from datetime import datetime, timezone
import subprocess
import unittest
from unittest.mock import Mock

from uti.collectors import MaigretRunResult, SherlockRunResult
from uti.models import (
    EvidenceProvenance,
    Finding,
    OwnershipVerificationStatus,
    RawCollectorRecord,
    SourceLineage,
    ValidationStatus,
)
from uti.services import InvestigationService


USERNAME = "uti_demo_test_2026"
COLLECTED_AT = datetime(2026, 5, 1, tzinfo=timezone.utc)


def finding(
    tool: str,
    url: str,
    *,
    platform: str,
    evidence_text: str,
) -> Finding:
    lineage = SourceLineage(
        collector_name=tool,
        underlying_data_source=None,
        collection_method=f"synthetic {tool} test output",
    )
    evidence = EvidenceProvenance(
        value=evidence_text,
        evidence_type=f"{tool}_presence_report",
        source_lineage=lineage,
        original_source_url=url,
    )
    return Finding(
        username=USERNAME,
        platform=platform,
        profile_url=url,
        source_tool=tool,
        collected_at=COLLECTED_AT,
        evidence=(evidence_text,),
        validation_status=ValidationStatus.VALID,
        source_lineage=(lineage,),
        evidence_provenance=(evidence,),
        ownership_status=OwnershipVerificationStatus.UNVERIFIED,
    )


def sherlock_result(*findings: Finding, **overrides: object) -> SherlockRunResult:
    defaults: dict[str, object] = {
        "username": USERNAME,
        "findings": findings,
        "stdout": "sherlock stdout",
        "stderr": "",
        "returncode": 0,
    }
    defaults.update(overrides)
    return SherlockRunResult(**defaults)  # type: ignore[arg-type]


def maigret_result(*findings: Finding, **overrides: object) -> MaigretRunResult:
    defaults: dict[str, object] = {
        "username": USERNAME,
        "findings": findings,
        "stdout": "maigret stdout",
        "stderr": "",
        "returncode": 0,
    }
    defaults.update(overrides)
    return MaigretRunResult(**defaults)  # type: ignore[arg-type]


class InvestigationServiceTests(unittest.TestCase):
    def test_success_runs_both_and_processes_independent_profiles(self) -> None:
        first = finding("sherlock", "https://one.example/u", platform="One", evidence_text="sherlock saw One")
        second = finding("maigret", "https://two.example/u", platform="Two", evidence_text="maigret saw Two")
        sherlock = Mock(collect=Mock(return_value=sherlock_result(first)))
        maigret = Mock(collect=Mock(return_value=maigret_result(second)))

        result = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate(USERNAME)

        sherlock.collect.assert_called_once_with(USERNAME)
        maigret.collect.assert_called_once_with(USERNAME)
        self.assertEqual([item.collector_name for item in result.collector_summaries], ["sherlock", "maigret"])
        self.assertEqual(len(result.normalized_findings), 2)
        self.assertEqual(len(result.deduplicated_findings), 2)
        self.assertEqual(result.correlation_results, ())
        self.assertEqual(len(result.assessments), 2)
        self.assertTrue(all(item.finding.confidence is None for item in result.assessments))
        self.assertEqual(
            [item.profile_check_outcomes[0].outcome.value for item in result.assessments],
            ["positive", "positive"],
        )
        self.assertEqual(result.errors, ())

    def test_matching_username_alone_does_not_create_correlation(self) -> None:
        first = finding("sherlock", "https://one.example/u", platform="One", evidence_text="different evidence one")
        second = finding("maigret", "https://two.example/u", platform="Two", evidence_text="different evidence two")
        result = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=sherlock_result(first))),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result(second))),
        ).investigate(USERNAME)
        self.assertEqual(result.correlation_results, ())

    def test_partial_failure_does_not_discard_successful_collector_findings(self) -> None:
        survivor = finding("maigret", "https://survivor.example/u", platform="Survivor", evidence_text="Maigret result")
        sherlock = Mock(collect=Mock(side_effect=RuntimeError("synthetic process failure")))
        maigret = Mock(collect=Mock(return_value=maigret_result(survivor, warnings=("one row skipped",))))

        result = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate(USERNAME)

        maigret.collect.assert_called_once_with(USERNAME)
        self.assertEqual([item.platform for item in result.deduplicated_findings], ["Survivor"])
        self.assertTrue(any("sherlock collector failed" in error for error in result.errors))
        self.assertEqual(result.warnings, ("maigret: one row skipped",))
        self.assertIn("synthetic process failure", result.collector_summaries[0].error or "")

    def test_timed_out_collector_result_keeps_other_results(self) -> None:
        survivor = finding("maigret", "https://survivor.example/u", platform="Survivor", evidence_text="Maigret result")
        sherlock = sherlock_result(returncode=None, timed_out=True, error="Sherlock timeout")
        service = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=sherlock)),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result(survivor))),
        )

        result = service.investigate(USERNAME)
        self.assertTrue(result.collector_summaries[0].timed_out)
        self.assertEqual([item.platform for item in result.deduplicated_findings], ["Survivor"])
        self.assertIn("Sherlock timeout", " ".join(result.errors))

    def test_duplicate_profile_across_collectors_merges_provenance_then_assesses(self) -> None:
        url = "https://shared.example/uti_demo_test_2026"
        first = finding("sherlock", url, platform="Shared", evidence_text="Sherlock observation")
        second = finding("maigret", url, platform="Shared", evidence_text="Maigret observation")
        result = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=sherlock_result(first))),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result(second))),
        ).investigate(USERNAME)

        self.assertEqual(len(result.normalized_findings), 2)
        self.assertEqual(len(result.deduplicated_findings), 1)
        merged = result.deduplicated_findings[0]
        self.assertEqual(set(merged.source_tools), {"sherlock", "maigret"})
        self.assertEqual({item.source_lineage.collector_name for item in merged.evidence_provenance}, {"sherlock", "maigret"})
        self.assertEqual(len(result.assessments), 1)
        self.assertEqual(result.assessments[0].source_independence.value, "unknown")
        self.assertEqual(
            {item.collector_name for item in result.assessments[0].profile_check_outcomes},
            {"sherlock", "maigret"},
        )

    def test_empty_findings_returns_empty_processing_outputs(self) -> None:
        result = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=sherlock_result())),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result())),
        ).investigate(USERNAME)
        self.assertEqual(result.normalized_findings, ())
        self.assertEqual(result.deduplicated_findings, ())
        self.assertEqual(result.correlation_results, ())
        self.assertEqual(result.assessments, ())

    def test_raw_collector_rows_are_exposed_on_execution_summary(self) -> None:
        record = RawCollectorRecord(
            "sherlock", 2, ("username", "url_user"), (USERNAME, " https://site.example/u ")
        )
        execution = sherlock_result(raw_records=(record,))
        result = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=execution)),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result())),
        ).investigate(USERNAME)
        self.assertEqual(result.collector_summaries[0].raw_records, (record,))
        self.assertEqual(result.collector_summaries[0].raw_records[0].as_mapping()["url_user"], " https://site.example/u ")

    def test_ownership_and_identity_safeguards_survive_all_stages(self) -> None:
        first = finding("sherlock", "https://same.example/u", platform="Same", evidence_text="same evidence")
        second = finding("maigret", "https://same.example/u", platform="Same", evidence_text="same evidence")
        result = InvestigationService(
            sherlock_collector=Mock(collect=Mock(return_value=sherlock_result(first))),
            maigret_collector=Mock(collect=Mock(return_value=maigret_result(second))),
        ).investigate(USERNAME)

        for finding_stage in (
            result.normalized_findings
            + result.deduplicated_findings
            + tuple(item.finding for item in result.assessments)
        ):
            self.assertEqual(finding_stage.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
            self.assertFalse(finding_stage.identity_verified)
        for assessment in result.assessments:
            self.assertEqual(assessment.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
            self.assertFalse(assessment.identity_verified)
        for group in result.correlation_results:
            self.assertIn("identity is not verified", group.interpretation)

    def test_timeout_exception_is_recorded_and_other_collector_runs(self) -> None:
        survivor = finding("maigret", "https://survivor.example/u", platform="Survivor", evidence_text="Maigret result")
        sherlock = Mock(collect=Mock(side_effect=subprocess.TimeoutExpired("sherlock", 3)))
        maigret = Mock(collect=Mock(return_value=maigret_result(survivor)))
        result = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate(USERNAME)
        self.assertTrue(result.collector_summaries[0].timed_out)
        maigret.collect.assert_called_once_with(USERNAME)
        self.assertEqual(len(result.assessments), 1)

    def test_rejects_empty_username_before_running_collectors(self) -> None:
        sherlock = Mock()
        maigret = Mock()
        with self.assertRaisesRegex(ValueError, "username"):
            InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate(" ")
        sherlock.collect.assert_not_called()
        maigret.collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
