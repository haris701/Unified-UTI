"""Synthetic tests for dashboard presentation adapters."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest

from uti.dashboard.viewmodels import attack_surface_category_rows, url_verification_rows
from uti.identity.url_verification import URLVerificationResult, URLVerificationStatus
from uti.models import SourceLineage
from uti.identity.attack_surface import AttackSurfaceAssessment


class DashboardViewModelTests(unittest.TestCase):
    def test_url_verification_table_preserves_outcome_and_original_final_urls(self):
        record = URLVerificationResult(
            "uti_synthetic", "SyntheticSite", "https://source.example/old", "https://source.example/profile",
            ("sherlock",), URLVerificationStatus.REDIRECTED, 200, "Synthetic profile",
            (("og:type", "profile"),), True, datetime(2026, 1, 1, tzinfo=timezone.utc),
            (SourceLineage("url_verification", None, "synthetic fetch"),), "synthetic redirect result",
        )
        row = url_verification_rows((record,))[0]
        self.assertEqual(row["Original URL"], "https://source.example/old")
        self.assertEqual(row["Final URL"], "https://source.example/profile")
        self.assertEqual(row["Status"], "REDIRECTED")
        self.assertTrue(row["Profile-specific evidence"])
        self.assertIn("og:type=profile", row["Page metadata"])
        self.assertIn("synthetic redirect", row["Reason"])

    def test_attack_surface_categories_render_as_distinct_evidence_counts(self):
        assessment = AttackSurfaceAssessment(
            discovered_profile_urls=1, unique_eligible_profile_urls=1,
            verified_accessible_profiles=1, inconclusive_urls=0, failed_or_skipped_urls=0,
            identity_attributes_found=1, public_contact_indicators=1,
            developer_technology_indicators=0, professional_information_indicators=0,
            public_websites_and_domains=0, supported_correlations=0,
            generated_threat_indicators=1, category_summaries=(("contact_exposure", 1),),
            overall_status="informational", overall_assessment="Synthetic evidence.",
            recommended_actions=(), evidence_limitations=(),
        )
        rows = attack_surface_category_rows(assessment)
        self.assertEqual(rows, [{"Category": "Contact Exposure", "Distinct evidence values": 1}])


if __name__ == "__main__":
    unittest.main()
