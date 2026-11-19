"""Synthetic unit tests for UTI's initial processing layer."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import unittest

from uti.correlation import correlate_findings
from uti.deduplication import deduplicate_findings
from uti.models import (
    EvidenceIndependence,
    Finding,
    OwnershipVerificationStatus,
    ProfileCheckStatus,
    ValidationStatus,
)
from uti.normalizers import normalize_finding
from uti.scoring import score_finding


def synthetic_finding(
    *,
    username: str = "alice_test_42",
    platform: str = "ExampleSocial",
    profile_url: str = "https://social.example/users/alice_test_42",
    source_tool: str = "synthetic_fixture",
    evidence: tuple[str, ...] = ("synthetic profile page returned",),
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED,
) -> Finding:
    """Create a fictional finding without network access."""
    return Finding(
        username=username,
        platform=platform,
        profile_url=profile_url,
        source_tool=source_tool,
        evidence=evidence,
        collected_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        validation_status=validation_status,
    )


def lineaged_finding(
    *,
    collector: str,
    dataset: str | None,
    profile_url: str,
    evidence: str | None = "synthetic blue comet marker",
) -> Finding:
    """Create a synthetic finding with explicit or unknown source lineage."""
    raw = {
        "username": "alice_test_42",
        "platform": "ExampleSocial",
        "profile_url": profile_url,
        "source_tool": collector,
        "collection_method": "synthetic fixture import",
        "evidence": [
            {
                "value": evidence,
                "evidence_type": "synthetic_bio_marker",
                "original_source_url": "https://evidence.example/fixture/42",
            }
        ] if evidence is not None else [],
        "validation_status": "valid",
        "collected_at": "2026-01-02T00:00:00Z",
    }
    if dataset is not None:
        raw["underlying_data_source"] = dataset
    return normalize_finding(raw)


class NormalizeFindingTests(unittest.TestCase):
    def test_normalizes_common_aliases_and_timestamp(self) -> None:
        finding = normalize_finding(
            {
                "queried_username": "alice_test_42",
                "site": "ExampleSocial",
                "url": "https://social.example/u/alice_test_42",
                "source": "synthetic_fixture",
                "evidence": ["synthetic result", "  synthetic result  "],
                "status": "found",
                "collected_at": "2026-01-02T03:04:05+03:00",
            }
        )
        self.assertEqual(finding.username, "alice_test_42")
        self.assertEqual(finding.platform, "ExampleSocial")
        self.assertEqual(finding.evidence, ("synthetic result",))
        self.assertEqual(finding.validation_status, ValidationStatus.VALID)
        self.assertEqual(finding.collected_at, datetime(2026, 1, 2, 0, 4, 5, tzinfo=timezone.utc))

    def test_requires_source_and_valid_profile_url(self) -> None:
        with self.assertRaisesRegex(ValueError, "source_tool"):
            normalize_finding({"username": "alice_test_42", "platform": "ExampleSocial", "url": "https://social.example/a"})
        with self.assertRaisesRegex(ValueError, "invalid profile_url"):
            synthetic_finding(profile_url="javascript:alert(1)")

    def test_rejects_unsafe_or_malformed_urls(self) -> None:
        for url in (
            "https://social.example:bad/alice",
            "https://user:secret@social.example/alice",
            "https://social .example/alice",
            "https://bad_host.example/alice",
            "https://[broken/alice",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                synthetic_finding(profile_url=url)

    def test_requires_explicit_timezone_aware_collection_timestamp(self) -> None:
        raw = {
            "username": "alice_test_42",
            "platform": "ExampleSocial",
            "profile_url": "https://social.example/alice",
            "source_tool": "synthetic_fixture",
        }
        with self.assertRaisesRegex(ValueError, "collected_at"):
            normalize_finding(raw)
        with self.assertRaisesRegex(ValueError, "timezone"):
            normalize_finding({**raw, "collected_at": "2026-01-02T03:04:05"})
        fallback = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(normalize_finding(raw, collected_at=fallback).collected_at, fallback)

    def test_rejects_malformed_evidence_instead_of_stringifying_objects(self) -> None:
        raw = {
            "username": "alice_test_42",
            "platform": "ExampleSocial",
            "profile_url": "https://social.example/alice",
            "source_tool": "synthetic_fixture",
            "collected_at": "2026-01-02T00:00:00Z",
        }
        for evidence in (
            [{"nested": "value"}],
            {"details": {"nested": "value"}},
            {"score": float("nan")},
            {"": "missing key"},
            b"opaque",
        ):
            with self.subTest(evidence=evidence), self.assertRaisesRegex(ValueError, "evidence"):
                normalize_finding({**raw, "evidence": evidence})

    def test_confidence_must_be_finite_and_in_range(self) -> None:
        for value in (float("nan"), float("inf"), -0.01, 1.01, "high"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Finding(
                    username="alice_test_42",
                    platform="ExampleSocial",
                    profile_url="https://social.example/alice",
                    source_tool="synthetic_fixture",
                    collected_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                    confidence=value,
                )

    def test_normalizes_source_lineage_and_evidence_provenance(self) -> None:
        finding = lineaged_finding(
            collector="fixture_collector",
            dataset="synthetic_catalog_v1",
            profile_url="https://social.example/alice_test_42",
        )
        lineage = finding.source_lineage[0]
        self.assertEqual(lineage.collector_name, "fixture_collector")
        self.assertEqual(lineage.underlying_data_source, "synthetic_catalog_v1")
        self.assertEqual(lineage.collection_method, "synthetic fixture import")
        evidence = finding.evidence_provenance[0]
        self.assertEqual(evidence.evidence_type, "synthetic_bio_marker")
        self.assertEqual(evidence.original_source_url, "https://evidence.example/fixture/42")

    def test_partial_lineage_mapping_uses_other_declared_lineage_fields(self) -> None:
        finding = normalize_finding(
            {
                "username": "alice_test_42",
                "platform": "ExampleSocial",
                "profile_url": "https://social.example/alice_test_42",
                "source_tool": "fixture_collector",
                "underlying_data_source": "synthetic_catalog_v1",
                "collection_method": "synthetic fixture import",
                "source_lineage": {"collector_name": "explicit_fixture_adapter"},
                "evidence": "synthetic marker",
                "collected_at": "2026-01-02T00:00:00Z",
            }
        )
        self.assertEqual(finding.source_lineage[0].collector_name, "explicit_fixture_adapter")
        self.assertEqual(finding.source_lineage[0].underlying_data_source, "synthetic_catalog_v1")

    def test_repeated_evidence_observations_retain_each_provenance_record(self) -> None:
        raw = {
            "username": "alice_test_42",
            "platform": "ExampleSocial",
            "profile_url": "https://social.example/alice_test_42",
            "source_tool": "fixture_collector",
            "underlying_data_source": "synthetic_catalog_v1",
            "evidence": ["synthetic repeated marker", "synthetic repeated marker"],
            "collected_at": "2026-01-02T00:00:00Z",
        }
        finding = normalize_finding(raw)
        self.assertEqual(finding.evidence, ("synthetic repeated marker",))
        self.assertEqual(len(finding.evidence_provenance), 2)

    def test_rejects_malformed_source_lineage(self) -> None:
        raw = {
            "username": "alice_test_42",
            "platform": "ExampleSocial",
            "profile_url": "https://social.example/alice_test_42",
            "source_tool": "fixture_collector",
            "source_lineage": {"collector_name": None, "underlying_data_source": ["catalog"]},
            "collected_at": "2026-01-02T00:00:00Z",
        }
        with self.assertRaisesRegex(ValueError, "source_lineage"):
            normalize_finding(raw)

    def test_any_supplied_confidence_requires_explanation(self) -> None:
        with self.assertRaisesRegex(ValueError, "confidence_reasons"):
            Finding(
                username="alice_test_42",
                platform="ExampleSocial",
                profile_url="https://social.example/alice",
                source_tool="synthetic_fixture",
                collected_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                confidence=0.5,
            )

    def test_valid_is_a_profile_check_not_verified_ownership(self) -> None:
        finding = synthetic_finding(validation_status=ValidationStatus.VALID)
        self.assertEqual(finding.profile_check_status, ProfileCheckStatus.VALID)
        self.assertEqual(finding.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
        self.assertFalse(finding.identity_verified)
        scored = score_finding(finding)
        self.assertIn("positive profile check", scored.confidence_reasons[0])
        self.assertNotIn("ownership", scored.confidence_reasons[0])

    def test_normalizer_does_not_trust_an_input_ownership_claim(self) -> None:
        finding = normalize_finding(
            {
                "username": "alice_test_42",
                "platform": "ExampleSocial",
                "profile_url": "https://social.example/alice",
                "source_tool": "synthetic_fixture",
                "collected_at": "2026-01-02T00:00:00Z",
                "validation_status": "valid",
                "ownership_status": "verified",
            }
        )
        self.assertEqual(finding.profile_check_status, ProfileCheckStatus.VALID)
        self.assertEqual(finding.ownership_status, OwnershipVerificationStatus.UNVERIFIED)
        self.assertFalse(finding.identity_verified)

    def test_model_cannot_represent_verified_ownership(self) -> None:
        with self.assertRaisesRegex(ValueError, "ownership_status must remain unverified"):
            Finding(
                username="alice_test_42",
                platform="ExampleSocial",
                profile_url="https://social.example/alice",
                source_tool="synthetic_fixture",
                collected_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                ownership_status="verified",  # type: ignore[arg-type]
            )


class DeduplicationTests(unittest.TestCase):
    def test_merges_safe_host_variants_and_preserves_provenance(self) -> None:
        first = synthetic_finding(source_tool="fixture_a", evidence=("synthetic bio marker",))
        second = synthetic_finding(
            profile_url="HTTPS://SOCIAL.EXAMPLE:443/users/alice_test_42",
            source_tool="fixture_b",
            evidence=("synthetic avatar marker",),
            validation_status=ValidationStatus.VALID,
        )
        result = deduplicate_findings([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0].source_tools), {"fixture_a", "fixture_b"})
        self.assertEqual(set(result[0].evidence), {"synthetic bio marker", "synthetic avatar marker"})
        self.assertEqual(result[0].validation_status, ValidationStatus.VALID)

    def test_merged_findings_clear_stale_scores_for_recalculation(self) -> None:
        first = score_finding(synthetic_finding(source_tool="fixture_a"))
        second = score_finding(synthetic_finding(source_tool="fixture_b", evidence=("another synthetic marker",)))
        merged = deduplicate_findings([first, second])[0]
        self.assertIsNone(merged.confidence)
        self.assertEqual(merged.confidence_reasons, ())
        self.assertIsNotNone(score_finding(merged).confidence)

    def test_legacy_confidence_does_not_choose_deduplication_winner(self) -> None:
        first = replace(
            synthetic_finding(platform="FirstPlatform"),
            confidence=0.1,
            confidence_reasons=("legacy low value",),
        )
        second = replace(
            synthetic_finding(platform="SecondPlatform", source_tool="fixture_b"),
            confidence=0.9,
            confidence_reasons=("legacy high value",),
        )
        merged = deduplicate_findings([first, second])[0]
        self.assertEqual(merged.platform, "FirstPlatform")
        self.assertIsNone(merged.confidence)

    def test_keeps_distinct_urls(self) -> None:
        first = synthetic_finding()
        second = synthetic_finding(profile_url="https://other.example/alice_test_42")
        self.assertEqual(len(deduplicate_findings([first, second])), 2)

    def test_preserves_case_trailing_slash_and_fragment_differences(self) -> None:
        urls = (
            "https://social.example/User42",
            "https://social.example/user42",
            "https://social.example/user42/",
            "https://social.example/user42#profile",
        )
        findings = [synthetic_finding(profile_url=url) for url in urls]
        self.assertEqual(len(deduplicate_findings(findings)), len(urls))

    def test_preserves_query_parameter_and_hash_route_differences(self) -> None:
        base = "https://social.example/alice_test_42"
        urls = (base, base + "?view=compact", base + "#profile")
        findings = [synthetic_finding(profile_url=url) for url in urls]
        self.assertEqual(len(deduplicate_findings(findings)), len(urls))

    def test_preserves_username_case_when_deduplicating(self) -> None:
        upper = synthetic_finding(username="Alice_test_42")
        lower = synthetic_finding(username="alice_test_42")
        self.assertEqual(len(deduplicate_findings([upper, lower])), 2)


class CorrelationTests(unittest.TestCase):
    def test_correlates_shared_evidence(self) -> None:
        first = synthetic_finding(evidence=("synthetic bio marker: blue comet",))
        second = synthetic_finding(
            platform="AnotherExample",
            profile_url="https://another.example/alice_test_42",
            source_tool="fixture_b",
            evidence=(" Synthetic Bio Marker:   Blue Comet ",),
        )
        groups = correlate_findings([first, second])
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].findings), 2)
        self.assertTrue(any("shared evidence" in reason for reason in groups[0].reasons))

    def test_username_match_alone_does_not_correlate(self) -> None:
        first = synthetic_finding(evidence=("synthetic evidence one",))
        second = synthetic_finding(
            platform="AnotherExample",
            profile_url="https://another.example/alice_test_42",
            evidence=("synthetic evidence two",),
        )
        self.assertEqual(correlate_findings([first, second]), [])

    def test_username_case_variant_does_not_create_correlation(self) -> None:
        first = synthetic_finding(username="Alice_test_42", evidence=("synthetic shared marker",))
        second = synthetic_finding(
            username="alice_test_42",
            platform="AnotherExample",
            profile_url="https://another.example/alice_test_42",
            evidence=("synthetic shared marker",),
        )
        self.assertEqual(correlate_findings([first, second]), [])

    def test_overlapping_collectors_are_classified_as_dependent_repeats(self) -> None:
        first = lineaged_finding(
            collector="fixture_a",
            dataset="shared_synthetic_catalog",
            profile_url="https://social.example/alice_test_42",
        )
        second = lineaged_finding(
            collector="fixture_b",
            dataset="shared_synthetic_catalog",
            profile_url="https://another.example/alice_test_42",
        )
        group = correlate_findings([first, second])[0]
        self.assertFalse(group.same_profile_candidate)
        self.assertEqual(len(group.shared_evidence), 1)
        self.assertEqual(group.shared_evidence[0].independence, EvidenceIndependence.DEPENDENT)
        self.assertEqual(len(group.repeated_evidence), 1)
        self.assertEqual(group.independently_corroborated_evidence, ())
        self.assertIn("identity is not verified", group.interpretation)

    def test_different_declared_datasets_are_independent_candidate_support(self) -> None:
        first = lineaged_finding(
            collector="fixture_a",
            dataset="synthetic_catalog_a",
            profile_url="https://social.example/alice_test_42",
        )
        second = lineaged_finding(
            collector="fixture_b",
            dataset="synthetic_catalog_b",
            profile_url="https://another.example/alice_test_42",
        )
        group = correlate_findings([first, second])[0]
        self.assertEqual(group.shared_evidence[0].independence, EvidenceIndependence.INDEPENDENT)
        self.assertEqual(len(group.independently_corroborated_evidence), 1)
        self.assertFalse(group.same_profile_candidate)

    def test_unknown_lineage_stays_unknown(self) -> None:
        first = lineaged_finding(
            collector="fixture_a",
            dataset=None,
            profile_url="https://social.example/alice_test_42",
        )
        second = lineaged_finding(
            collector="fixture_b",
            dataset=None,
            profile_url="https://another.example/alice_test_42",
        )
        group = correlate_findings([first, second])[0]
        self.assertEqual(group.shared_evidence[0].independence, EvidenceIndependence.UNKNOWN)
        self.assertEqual(group.independently_corroborated_evidence, ())

    def test_unknown_contributor_prevents_independence_classification(self) -> None:
        first = lineaged_finding(
            collector="fixture_a",
            dataset="catalog_a",
            profile_url="https://social.example/alice_test_42",
        )
        second = lineaged_finding(
            collector="fixture_b",
            dataset="catalog_b",
            profile_url="https://another.example/alice_test_42",
        )
        third = lineaged_finding(
            collector="fixture_c",
            dataset=None,
            profile_url="https://third.example/alice_test_42",
        )
        group = correlate_findings([first, second, third])[0]
        self.assertEqual(group.shared_evidence[0].independence, EvidenceIndependence.UNKNOWN)
        self.assertEqual(group.independently_corroborated_evidence, ())

    def test_same_profile_is_a_candidate_not_identity_verification(self) -> None:
        first = lineaged_finding(
            collector="fixture_a",
            dataset=None,
            profile_url="https://social.example/alice_test_42",
            evidence="synthetic first marker",
        )
        second = lineaged_finding(
            collector="fixture_b",
            dataset=None,
            profile_url="https://social.example/alice_test_42",
            evidence="synthetic second marker",
        )
        group = correlate_findings([first, second])[0]
        self.assertTrue(group.same_profile_candidate)
        self.assertEqual(group.shared_evidence, ())
        self.assertIn("not verified", group.interpretation)


class ScoringTests(unittest.TestCase):
    def test_score_is_explainable_and_not_mutating_input(self) -> None:
        finding = synthetic_finding(
            evidence=("synthetic bio marker",),
            validation_status=ValidationStatus.VALID,
        )
        scored = score_finding(finding)
        self.assertEqual(scored.confidence, 0.8)
        self.assertEqual(finding.confidence, None)
        self.assertIn("not a probability", score_finding.__doc__)
        self.assertTrue(scored.confidence_reasons)

    def test_multiple_tools_do_not_inflate_score_without_independence_metadata(self) -> None:
        merged = deduplicate_findings(
            [
                synthetic_finding(source_tool="fixture_a", validation_status=ValidationStatus.VALID),
                synthetic_finding(source_tool="fixture_b", validation_status=ValidationStatus.VALID),
            ]
        )[0]
        scored = score_finding(merged)
        self.assertEqual(scored.confidence, 0.8)
        self.assertFalse(any("multiple collectors" in item for item in scored.confidence_reasons))

    def test_additional_evidence_strings_do_not_inflate_score(self) -> None:
        one_item = synthetic_finding(
            evidence=("one",),
            validation_status=ValidationStatus.VALID,
        )
        many_items = synthetic_finding(
            evidence=("one", "two", "three", "four", "five"),
            validation_status=ValidationStatus.VALID,
        )
        scored_one, scored_many = score_finding(one_item), score_finding(many_items)
        self.assertEqual(scored_one.confidence, 0.8)
        self.assertEqual(scored_many.confidence, scored_one.confidence)
        self.assertLessEqual(scored_many.confidence, 1.0)

    def test_independence_bonus_requires_distinct_known_datasets(self) -> None:
        independent = deduplicate_findings(
            [
                lineaged_finding(collector="fixture_a", dataset="catalog_a", profile_url="https://social.example/alice_test_42"),
                lineaged_finding(collector="fixture_b", dataset="catalog_b", profile_url="https://social.example/alice_test_42"),
            ]
        )[0]
        dependent = deduplicate_findings(
            [
                lineaged_finding(collector="fixture_a", dataset="shared_catalog", profile_url="https://social.example/alice_test_42"),
                lineaged_finding(collector="fixture_b", dataset="shared_catalog", profile_url="https://social.example/alice_test_42"),
            ]
        )[0]
        unknown = deduplicate_findings(
            [
                lineaged_finding(collector="fixture_a", dataset=None, profile_url="https://social.example/alice_test_42"),
                lineaged_finding(collector="fixture_b", dataset=None, profile_url="https://social.example/alice_test_42"),
            ]
        )[0]
        mixed = deduplicate_findings(
            [
                lineaged_finding(collector="fixture_a", dataset="catalog_a", profile_url="https://social.example/alice_test_42"),
                lineaged_finding(collector="fixture_b", dataset="catalog_b", profile_url="https://social.example/alice_test_42"),
                lineaged_finding(collector="fixture_c", dataset=None, profile_url="https://social.example/alice_test_42"),
            ]
        )[0]
        no_evidence = deduplicate_findings(
            [
                lineaged_finding(collector="fixture_a", dataset="catalog_a", profile_url="https://social.example/alice_test_42", evidence=None),
                lineaged_finding(collector="fixture_b", dataset="catalog_b", profile_url="https://social.example/alice_test_42", evidence=None),
            ]
        )[0]

        independent_score = score_finding(independent)
        dependent_score = score_finding(dependent)
        unknown_score = score_finding(unknown)
        mixed_score = score_finding(mixed)
        no_evidence_score = score_finding(no_evidence)
        self.assertEqual(independent_score.confidence, 0.9)
        self.assertEqual(dependent_score.confidence, 0.8)
        self.assertEqual(unknown_score.confidence, 0.8)
        self.assertEqual(mixed_score.confidence, 0.8)
        self.assertEqual(no_evidence_score.confidence, 0.7)
        self.assertTrue(any("explicitly distinct" in reason for reason in independent_score.confidence_reasons))
        self.assertTrue(any("no independence bonus" in reason for reason in unknown_score.confidence_reasons))


if __name__ == "__main__":
    unittest.main()
