"""Synthetic tests for investigation and findings workbook exports."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import replace
from io import BytesIO
import unittest
from unittest.mock import Mock

from openpyxl import load_workbook

from uti.collectors import MaigretRunResult, SherlockRunResult
from uti.models import (
    EvidenceProvenance,
    Finding,
    OwnershipVerificationStatus,
    RawCollectorRecord,
    SourceLineage,
    ValidationStatus,
)
from uti.reporting import export_findings_workbook, export_identity_workbook, export_investigation_workbook
from uti.services import InvestigationService
from uti.identity.analysis import analyze_threats
from uti.identity.attack_surface import assess_attack_surface
from uti.identity.correlation import correlate_identity_attributes
from uti.identity.deduplication import deduplicate_identity_attributes
from uti.identity.models import ProfileURLCollectionAudit, ProfileURLCollectionStatus
from uti.identity.url_verification import URLVerificationResult, URLVerificationStatus
from uti.identity.normalization import normalize_identity_attribute


USERNAME = "uti_excel_synthetic_42"
STAMP = datetime(2026, 6, 1, tzinfo=timezone.utc)


def make_finding(tool: str, url: str, platform: str, *, evidence_text: str = "synthetic marker") -> Finding:
    lineage = SourceLineage(tool, f"{tool}_fixture", "synthetic CSV fixture")
    provenance = EvidenceProvenance(evidence_text, "synthetic_marker", lineage, url)
    return Finding(
        username=USERNAME,
        platform=platform,
        profile_url=url,
        source_tool=tool,
        collected_at=STAMP,
        evidence=(evidence_text,),
        validation_status=ValidationStatus.VALID,
        source_lineage=(lineage,),
        evidence_provenance=(provenance,),
        ownership_status=OwnershipVerificationStatus.UNVERIFIED,
    )


def raw_record(tool: str, platform: str, url: str, status: str = "Claimed") -> RawCollectorRecord:
    headers = ("username", "name", "url_main", "url_user", "exists", "http_status", "evidence")
    values = (USERNAME, platform, "https://site.example/", url, status, "200", "synthetic CSV row")
    return RawCollectorRecord(tool, 2, headers, values)


def make_result(sherlock_findings=(), maigret_findings=(), *, sherlock_raw=(), maigret_raw=()):
    sherlock = Mock(collect=Mock(return_value=SherlockRunResult(
        USERNAME, tuple(sherlock_findings), "", "", 0, raw_records=tuple(sherlock_raw)
    )))
    maigret = Mock(collect=Mock(return_value=MaigretRunResult(
        USERNAME, tuple(maigret_findings), "", "", 0, raw_records=tuple(maigret_raw)
    )))
    result = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate(USERNAME)
    return result, sherlock, maigret


class ExcelExportTests(unittest.TestCase):
    def test_workbooks_preserve_raw_and_normalized_urls_without_recollection(self) -> None:
        original_url = " https://social.example/uti_excel_synthetic_42 "
        normalized_url = original_url.strip()
        finding = make_finding("sherlock", normalized_url, "ExampleSocial")
        result, sherlock, maigret = make_result(
            [finding], (),
            sherlock_raw=[raw_record("sherlock", "ExampleSocial", original_url)],
        )

        full = load_workbook(BytesIO(export_investigation_workbook(result)), data_only=False)
        findings = load_workbook(BytesIO(export_findings_workbook(result)), data_only=False)
        row = list(findings["All Findings"].iter_rows(min_row=2, values_only=True))[0]
        self.assertEqual(row[2], normalized_url)
        self.assertEqual(row[3], original_url)
        self.assertEqual(row[4], "https://social.example/uti_excel_synthetic_42")
        self.assertEqual(full.sheetnames, [
            "Summary", "Raw Sherlock", "Raw Maigret", "Normalized Findings",
            "Deduplicated Findings", "Correlations", "Diagnostics", "Profile Intelligence",
            "Identity Attributes", "Dedup Identity Attributes", "Profile URL Collection Audit",
            "Identity Correlations", "Threat Indicators", "Identity Diagnostics",
            "URL Verification", "Attack Surface Assessment",
        ])
        self.assertEqual(findings.sheetnames, ["All Findings", "Deduplicated Findings", "Finding Diagnostics"])
        self.assertEqual(full["Raw Sherlock"].cell(2, 5).value, original_url)
        self.assertEqual(full["Normalized Findings"].cell(2, 3).value, original_url)
        self.assertEqual(row[13], "unverified")
        self.assertFalse(row[14])
        self.assertEqual(full["Raw Sherlock"].freeze_panes, "A2")
        self.assertTrue(full["Raw Sherlock"].auto_filter.ref)
        sherlock.collect.assert_called_once_with(USERNAME)
        maigret.collect.assert_called_once_with(USERNAME)

    def test_deduplication_correlation_and_provenance_are_exported(self) -> None:
        shared_url = "https://same.example/uti_excel_synthetic_42"
        first = make_finding("sherlock", shared_url, "SharedPlatform")
        second = make_finding("maigret", shared_url, "SharedPlatform")
        third = make_finding("maigret", "https://other.example/uti_excel_synthetic_42", "OtherPlatform")
        result, _, _ = make_result(
            [first], [second, third],
            sherlock_raw=[raw_record("sherlock", "SharedPlatform", shared_url)],
            maigret_raw=[raw_record("maigret", "SharedPlatform", shared_url), raw_record("maigret", "OtherPlatform", third.profile_url)],
        )
        self.assertEqual(len(result.deduplicated_findings), 2)
        self.assertEqual(len(result.correlation_results), 1)
        workbook = load_workbook(BytesIO(export_investigation_workbook(result)), data_only=False)
        dedup_rows = list(workbook["Deduplicated Findings"].iter_rows(min_row=2, values_only=True))
        self.assertEqual(len(dedup_rows), 2)
        shared_row = next(row for row in dedup_rows if row[1] == "SharedPlatform")
        self.assertIn("sherlock", shared_row[5])
        self.assertIn("maigret", shared_row[5])
        self.assertIn("sherlock", shared_row[12])
        self.assertIn("maigret", shared_row[12])
        self.assertEqual(workbook["Correlations"].max_row, 2)
        self.assertIn("independent", str(workbook["Correlations"].cell(2, 7).value))

    def test_empty_findings_make_valid_header_only_sheets(self) -> None:
        result, _, _ = make_result()
        complete = load_workbook(BytesIO(export_investigation_workbook(result)))
        findings = load_workbook(BytesIO(export_findings_workbook(result)))
        self.assertEqual(complete["Normalized Findings"].max_row, 1)
        self.assertEqual(complete["Deduplicated Findings"].max_row, 1)
        self.assertEqual(findings["All Findings"].max_row, 1)
        self.assertEqual(findings["Deduplicated Findings"].max_row, 1)
        self.assertEqual(findings["Finding Diagnostics"].freeze_panes, "A2")
        identity = load_workbook(BytesIO(export_identity_workbook(result)))
        self.assertEqual(identity.sheetnames, [
            "Profile Intelligence", "All Identity Attributes", "Dedup Identity Attributes",
            "Profile URL Collection Audit", "Identity Correlations", "Threat Indicators", "Identity Diagnostics",
            "URL Verification", "Attack Surface Assessment",
        ])
        self.assertEqual(identity["All Identity Attributes"].max_row, 1)
        self.assertEqual(identity["Profile Intelligence"].max_row, 1)
        self.assertEqual(identity["Profile URL Collection Audit"].max_row, 1)
        self.assertEqual(identity["Identity Diagnostics"].freeze_panes, "A2")
        self.assertEqual(identity["URL Verification"].max_row, 1)
        self.assertGreater(identity["Attack Surface Assessment"].max_row, 1)
        self.assertEqual(identity["Attack Surface Assessment"].cell(2, 2).value, "inconclusive")
        assessment_values = [str(cell.value) for row in identity["Attack Surface Assessment"].iter_rows() for cell in row]
        self.assertTrue(any("Not implemented" in value for value in assessment_values))

    def test_untrusted_formula_like_evidence_is_written_as_text(self) -> None:
        formula_like = "=HYPERLINK(\"https://example.invalid\",\"open\")"
        finding = make_finding("sherlock", "https://safe.example/user", "ExampleSocial", evidence_text=formula_like)
        result, _, _ = make_result([finding])
        workbook = load_workbook(BytesIO(export_findings_workbook(result)), data_only=False)
        cell = workbook["All Findings"].cell(2, 7)
        self.assertEqual(cell.value, "'" + formula_like)
        self.assertNotEqual(cell.data_type, "f")

    def test_populated_identity_workbook_preserves_profile_mapping_audit_and_threat_evidence(self) -> None:
        url_one = "https://one.example/uti_excel_synthetic_42"
        url_two = "https://two.example/uti_excel_synthetic_42"
        first = make_finding("sherlock", url_one, "OneProfile")
        second = make_finding("maigret", url_two, "TwoProfile")
        result, _, _ = make_result([first], [second])
        identity_attributes = tuple(normalize_identity_attribute({
            "attribute_type": "email", "value": "alex@example.org", "source_tool": tool,
            "source_url": url, "collected_at": STAMP, "evidence": f"Email published on {url}",
            "evidence_type": "synthetic_profile_email",
        }) for tool, url in (("public_page", url_one), ("public_page", url_two)))
        deduplicated = deduplicate_identity_attributes(identity_attributes)
        correlations = correlate_identity_attributes(deduplicated)
        audits = tuple(ProfileURLCollectionAudit(
            USERNAME, finding.platform, finding.profile_url, finding.source_tools, True,
            ProfileURLCollectionStatus.FETCHED, STAMP, 1, finding.profile_url, 200,
        ) for finding in (first, second))
        verification = tuple(URLVerificationResult(
            USERNAME, finding.platform, finding.profile_url, finding.profile_url,
            finding.source_tools, URLVerificationStatus.VERIFIED_ACCESSIBLE, 200,
            "Synthetic profile", (("og:type", "profile"),), True, STAMP,
            finding.source_lineage, "explicit synthetic profile metadata",
        ) for finding in (first, second))
        threat_indicators = analyze_threats(identity_attributes, (first, second))
        result = replace(
            result,
            identity_collection_enabled=True,
            identity_attributes=identity_attributes,
            deduplicated_identity_attributes=deduplicated,
            identity_correlations=correlations,
            threat_indicators=threat_indicators,
            profile_url_audits=audits,
            url_verification_results=verification,
        )
        result = replace(result, attack_surface=assess_attack_surface(
            (first, second), verification, identity_attributes, correlations, threat_indicators,
        ))
        workbook = load_workbook(BytesIO(export_identity_workbook(result)), data_only=True)
        profiles = list(workbook["Profile Intelligence"].iter_rows(min_row=2, values_only=True))
        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0][5], "alex@example.org")
        self.assertEqual(profiles[0][7], "-")
        all_attrs = list(workbook["All Identity Attributes"].iter_rows(min_row=2, values_only=True))
        self.assertEqual(len(all_attrs), 2)
        self.assertIn(url_one, all_attrs[0][9])
        self.assertEqual(workbook["Identity Correlations"].max_row, 2)
        self.assertIn("unknown", str(workbook["Identity Correlations"].cell(2, 5).value))
        self.assertEqual(workbook["Profile URL Collection Audit"].max_row, 3)
        self.assertEqual(workbook["Threat Indicators"].max_row, 2)
        self.assertEqual(workbook["URL Verification"].max_row, 3)
        self.assertEqual(workbook["URL Verification"].cell(2, 6).value, "verified_accessible")
        self.assertEqual(workbook["Attack Surface Assessment"].cell(2, 2).value, "informational")


if __name__ == "__main__":
    unittest.main()
