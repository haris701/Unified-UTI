"""Tests for non-numeric profile and record assessments."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from uti.models import (
    EvidenceIndependence,
    EvidenceProvenance,
    Finding,
    OwnershipVerificationStatus,
    SourceLineage,
    ValidationStatus,
)
from uti.scoring import (
    CompletenessState,
    ProfileCheckOutcomeKind,
    assess_finding,
    assess_profile_check,
    assess_record_completeness,
)


COLLECTED_AT = datetime(2026, 7, 14, 9, 30, tzinfo=timezone.utc)


def make_finding(
    status: ValidationStatus,
    *,
    evidence: tuple[str, ...] = ("synthetic observation",),
    provenance: tuple[EvidenceProvenance, ...] | None = None,
) -> Finding:
    lineage = SourceLineage("synthetic_collector")
    if provenance is None and evidence:
        provenance = tuple(
            EvidenceProvenance(value, "synthetic_record", lineage, "https://evidence.example/item")
            for value in evidence
        )
    return Finding(
        username="uti_synthetic_user",
        platform="SyntheticPlatform",
        profile_url="https://social.example/uti_synthetic_user",
        source_tool="synthetic_collector",
        collected_at=COLLECTED_AT,
        evidence=evidence,
        validation_status=status,
        source_lineage=(lineage,),
        evidence_provenance=provenance or (),
        ownership_status=OwnershipVerificationStatus.UNVERIFIED,
    )


class ProfileCheckAssessmentTests(unittest.TestCase):
    def test_distinguishes_positive_negative_inconclusive_and_error(self) -> None:
        cases = (
            (ValidationStatus.VALID, ProfileCheckOutcomeKind.POSITIVE),
            (ValidationStatus.INVALID, ProfileCheckOutcomeKind.NEGATIVE),
            (ValidationStatus.UNVERIFIED, ProfileCheckOutcomeKind.INCONCLUSIVE),
            (ValidationStatus.ERROR, ProfileCheckOutcomeKind.ERROR),
        )
        for reported_status, expected in cases:
            with self.subTest(status=reported_status):
                outcome = assess_profile_check(make_finding(reported_status))
                self.assertEqual(outcome.outcome, expected)
                self.assertEqual(outcome.reported_status, reported_status)
                self.assertEqual(outcome.collector_name, "synthetic_collector")
                self.assertEqual(outcome.collected_at, COLLECTED_AT)

    def test_http_200_does_not_override_inconclusive_collector_status(self) -> None:
        finding = make_finding(
            ValidationStatus.UNVERIFIED,
            evidence=("Maigret status=Unknown; http_status=200",),
        )
        outcome = assess_profile_check(finding)
        self.assertEqual(outcome.outcome, ProfileCheckOutcomeKind.INCONCLUSIVE)
        self.assertEqual(outcome.reported_status, ValidationStatus.UNVERIFIED)


class RecordCompletenessAssessmentTests(unittest.TestCase):
    def test_missing_evidence_is_distinct_from_unknown_metadata(self) -> None:
        assessment = assess_record_completeness(make_finding(ValidationStatus.VALID, evidence=()))
        self.assertEqual(assessment.state_for("evidence"), CompletenessState.MISSING)
        self.assertEqual(assessment.state_for("evidence_type"), CompletenessState.MISSING)
        self.assertEqual(assessment.state_for("original_source_url"), CompletenessState.MISSING)
        self.assertEqual(assessment.state_for("collection_timestamp"), CompletenessState.AVAILABLE)
        self.assertEqual(assessment.state_for("source_lineage"), CompletenessState.AVAILABLE)
        self.assertIn("evidence", assessment.missing_fields)
        self.assertNotIn("evidence", assessment.unknown_fields)

    def test_unknown_evidence_type_and_source_url_remain_unknown(self) -> None:
        lineage = SourceLineage("synthetic_collector")
        finding = make_finding(
            ValidationStatus.VALID,
            evidence=("synthetic value",),
            provenance=(EvidenceProvenance("synthetic value", "unknown", lineage),),
        )
        assessment = assess_record_completeness(finding)
        self.assertEqual(assessment.state_for("evidence"), CompletenessState.AVAILABLE)
        self.assertEqual(assessment.state_for("evidence_type"), CompletenessState.UNKNOWN)
        self.assertEqual(assessment.state_for("original_source_url"), CompletenessState.UNKNOWN)
        self.assertIn("evidence_type", assessment.unknown_fields)
        self.assertNotIn("evidence_type", assessment.missing_fields)

    def test_independence_uses_only_declared_lineage(self) -> None:
        unknown_lineage = SourceLineage("source_a", underlying_data_source=None)
        unknown_repeated = make_finding(
            ValidationStatus.VALID,
            evidence=("first", "second"),
            provenance=(
                EvidenceProvenance("first", "fixture", unknown_lineage),
                EvidenceProvenance("second", "fixture", unknown_lineage),
            ),
        )
        self.assertEqual(assess_finding(unknown_repeated).source_independence, EvidenceIndependence.UNKNOWN)

        shared_source = SourceLineage("source_a", underlying_data_source="catalog-a")
        dependent = make_finding(
            ValidationStatus.VALID,
            evidence=("first", "second"),
            provenance=(
                EvidenceProvenance("first", "fixture", shared_source),
                EvidenceProvenance("second", "fixture", shared_source),
            ),
        )
        self.assertEqual(assess_finding(dependent).source_independence, EvidenceIndependence.DEPENDENT)

        independent = make_finding(
            ValidationStatus.VALID,
            evidence=("first", "second"),
            provenance=(
                EvidenceProvenance("first", "fixture", SourceLineage("source_a", "catalog-a")),
                EvidenceProvenance("second", "fixture", SourceLineage("source_b", "catalog-b")),
            ),
        )
        self.assertEqual(assess_finding(independent).source_independence, EvidenceIndependence.INDEPENDENT)

    def test_assessment_keeps_ownership_unverified_and_identity_false(self) -> None:
        assessment = assess_finding(make_finding(ValidationStatus.VALID))
        self.assertEqual(assessment.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
        self.assertFalse(assessment.identity_verified)


if __name__ == "__main__":
    unittest.main()
