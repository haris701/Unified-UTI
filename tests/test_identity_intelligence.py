"""Synthetic tests for identity normalization, collection, correlation and reports."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from uti.identity.analysis import ThreatIndicatorType, analyze_threats
from uti.identity.attack_surface import assess_attack_surface
from uti.identity.collectors.base import IdentityCollectionRequest, IdentityCollectorService, IdentityCollectionResult
from uti.identity.collectors.local_file import LocalEvidenceIdentityCollector
from uti.identity.collectors.public_page import (
    HTTPResponseData, PublicPage, PublicPageFetcher, PublicPageFetchError,
    PublicPageIdentityCollector, _extract_attributes,
)
from uti.identity.correlation import correlate_identity_attributes
from uti.identity.deduplication import deduplicate_identity_attributes
from uti.identity.models import IdentityAttributeType, VerificationStatus
from uti.identity.normalization import normalize_identity_attribute
from uti.identity.presentation import build_profile_intelligence
from uti.identity.service import IdentityIntelligenceService
from uti.identity.url_verification import URLVerificationService, URLVerificationStatus
from uti.reporting import export_identity_workbook
from uti.services import InvestigationService
from uti.models import Finding, RawCollectorRecord, ValidationStatus


STAMP = datetime(2026, 2, 3, tzinfo=timezone.utc)


def attr(kind: str, value: str, tool: str = "fixture", url: str = "https://source.example/page", **extra):
    return normalize_identity_attribute({
        "attribute_type": kind, "value": value, "source_tool": tool,
        "source_url": url, "collected_at": STAMP, "evidence": "synthetic source record",
        "evidence_type": "synthetic", **extra,
    })


class IdentityNormalizationTests(unittest.TestCase):
    def test_all_declared_attribute_types_accept_synthetic_values(self):
        values = {
            "display_name": "Synthetic Person", "publicly_stated_name": "Synthetic Person",
            "email": "Person@Example.ORG", "phone": "+1 202 555 0123",
            "website": "https://www.example.org/about", "domain": "example.org",
            "social_profile": "https://social.example/synthetic", "bio": "Synthetic bio",
            "alias": "synthetic_alias", "organization": "Synthetic University",
            "secondary_username": "linked_alias", "job_title": "Researcher",
            "professional_affiliation": "Example Lab", "technology": "Python", "skill": "Analysis",
            "coarse_location": "Synthetic City", "profile_image_url": "https://example.org/image.png",
            "other": "Synthetic value",
        }
        for kind in IdentityAttributeType:
            with self.subTest(kind=kind):
                result = attr(kind.value, values[kind.value])
                self.assertEqual(result.attribute_type, kind)
                self.assertTrue(result.source_lineage)
                self.assertTrue(result.evidence_provenance)

    def test_email_phone_name_alias_and_urls_normalize_conservatively(self):
        email = attr("email", " Person@EXAMPLE.ORG ")
        self.assertEqual(email.normalized_value, "Person@example.org")
        self.assertEqual(email.verification_status, VerificationStatus.FORMAT_VALID)
        self.assertEqual(attr("phone", "(202) 555-0100").normalized_value, "(202) 555-0100")
        self.assertEqual(attr("phone", "202 555 0100", country_context="+1").normalized_value, "+12025550100")
        self.assertEqual(attr("display_name", "  Synthetic   Person ").normalized_value, "Synthetic Person")
        self.assertEqual(attr("alias", "Mixed_CASE  Name").normalized_value, "Mixed_CASE Name")
        self.assertEqual(attr("website", "https://EXAMPLE.org/a").normalized_value, "https://example.org/a")
        with self.assertRaises(ValueError):
            attr("email", "not-an-email")

    def test_duplicate_attributes_preserve_observations_and_unknown_independence(self):
        first = attr("email", "person@example.org", "collector-a", "https://a.example/page")
        second = attr("email", "person@example.org", "collector-b", "https://b.example/page")
        dedup = deduplicate_identity_attributes((first, second))
        self.assertEqual(len(dedup), 1)
        self.assertEqual(len(dedup[0].observations), 2)
        correlations = correlate_identity_attributes(dedup)
        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0].source_independence.value, "unknown")
        self.assertIn("not verified", correlations[0].interpretation)

    def test_same_source_page_is_dependent_and_username_is_not_identity_evidence(self):
        first = attr("alias", "same-handle", "sherlock", "https://same.example/profile")
        second = attr("alias", "same-handle", "maigret", "https://same.example/profile")
        corr = correlate_identity_attributes(deduplicate_identity_attributes((first, second)))[0]
        self.assertEqual(corr.source_independence.value, "dependent")
        self.assertFalse(any(item.indicator_type is ThreatIndicatorType.POTENTIAL_IMPERSONATION_INDICATOR for item in analyze_threats((first, second))))

    def test_insufficient_evidence_indicators_are_informational(self):
        indicators = analyze_threats((attr("organization", "Synthetic University"),))
        self.assertTrue(indicators)
        self.assertTrue(all(item.severity.value == "informational" for item in indicators))
        self.assertFalse(any(item.indicator_type is ThreatIndicatorType.POTENTIAL_IMPERSONATION_INDICATOR for item in indicators))

    def test_biography_and_contact_evidence_generate_explainable_indicators(self):
        biography = attr("bio", "Synthetic biography")
        email = attr("email", "contact@example.org")
        indicators = analyze_threats((biography, email))
        kinds = {item.indicator_type for item in indicators}
        self.assertIn(ThreatIndicatorType.PUBLIC_IDENTITY_EXPOSURE, kinds)
        self.assertIn(ThreatIndicatorType.PUBLIC_CONTACT_EXPOSURE, kinds)
        self.assertTrue(all(item.supporting_evidence and item.severity.value == "informational" for item in indicators))

    def test_technology_and_professional_attributes_generate_low_claim_indicators(self):
        technology = attr("technology", "Python", url="https://dev.example/profile", evidence="JSON-LD knowsAbout: Python")
        title = attr("job_title", "Research Engineer", url="https://work.example/profile")
        indicators = analyze_threats((technology, title))
        kinds = {item.indicator_type for item in indicators}
        self.assertIn(ThreatIndicatorType.DEVELOPER_INFORMATION_EXPOSURE, kinds)
        self.assertIn(ThreatIndicatorType.PUBLIC_TECHNOLOGY_DISCLOSURE, kinds)
        self.assertIn(ThreatIndicatorType.PROFESSIONAL_INFORMATION_EXPOSURE, kinds)
        self.assertTrue(all(item.severity.value == "informational" for item in indicators))
        self.assertTrue(all(item.source_references for item in indicators))

    def test_unfetched_profile_candidates_alone_do_not_create_exposure_indicators(self):
        candidate = Finding(
            "uti_synthetic", "CandidateSite", "https://candidate.example/profile",
            "sherlock", STAMP, evidence=("synthetic positive profile check",),
            validation_status=ValidationStatus.VALID,
        )
        self.assertEqual(analyze_threats((), (candidate,)), ())

    def test_attack_surface_deduplicates_values_and_returns_explainable_no_score_summary(self):
        finding = Finding("uti_synthetic", "Synthetic", "https://source.example/profile", "sherlock", STAMP, validation_status=ValidationStatus.VALID)
        first = attr("email", "public@example.org", "public_page", finding.profile_url)
        second = attr("email", "public@example.org", "public_page", finding.profile_url)
        verified = URLVerificationService().evaluate(
            finding.username, finding.platform, finding.profile_url, finding.source_tools,
            finding.source_lineage,
            page=PublicPage(finding.profile_url, "text/html", b'<meta property="og:type" content="profile">', 200),
        )
        indicators = analyze_threats((first, second), (finding,))
        assessment = assess_attack_surface((finding,), (verified,), (first, second), (), indicators)
        self.assertEqual(assessment.public_contact_indicators, 1)
        self.assertEqual(assessment.verified_accessible_profiles, 1)
        self.assertEqual(assessment.overall_status, "informational")
        self.assertIn("No account ownership", assessment.overall_assessment)
        self.assertFalse(hasattr(assessment, "score"))


class IdentityCollectorTests(unittest.TestCase):
    def _finding(self, *, source_tool="sherlock", url="https://social.example/uti_synthetic", status=ValidationStatus.VALID):
        return Finding(
            "uti_synthetic", "SyntheticSocial", url, source_tool, STAMP,
            evidence=("synthetic collector result",), validation_status=status,
        )

    def test_authorized_local_json_and_malformed_rows_produce_diagnostics(self):
        request = IdentityCollectionRequest("synthetic-user", local_evidence_content=json.dumps([
            {"attribute_type": "display_name", "value": "Synthetic Person"},
            {"attribute_type": "email", "value": "bad"},
            {"attribute_type": "other", "value": "ignored", "unexpected": True},
        ]).encode(), local_evidence_filename="synthetic.json")
        result = LocalEvidenceIdentityCollector().collect(request)
        self.assertEqual(len(result.attributes), 1)
        self.assertEqual(len(result.diagnostics), 2)
        self.assertIn("sha256=", result.attributes[0].source_lineage[0].collection_method)

    def test_identity_collectors_are_failure_isolated(self):
        class Broken:
            name = "broken"
            def collect(self, _request):
                raise RuntimeError("synthetic failure")
        class Good:
            name = "good"
            def collect(self, _request):
                return IdentityCollectionResult("good", (attr("alias", "synthetic"),))
        result = IdentityCollectorService((Broken(), Good())).collect(IdentityCollectionRequest("synthetic-user"))
        self.assertEqual(len(result.attributes), 1)
        self.assertEqual(result.diagnostics[0].level.value, "error")

    def test_public_html_extracts_only_explicitly_published_fields(self):
        html = b'<meta property="og:type" content="profile"><meta property="og:title" content="synthetic-user - Overview"><meta name="description" content="Public bio https://portfolio.example/path."><meta name="profile:alias" content="synthetic_alias"><meta name="profile:organization" content="Synthetic Institute"><span class="p-name vcard-fullname" itemprop="name">  Alex   Morgan </span><a href="mailto:public@example.org">mail</a><a rel="me" href="https://person.example/">site</a>'
        attrs = _extract_attributes(PublicPage("https://source.example/profile", "text/html", html, 200), "synthetic-user")
        kinds = {item.attribute_type.value for item in attrs}
        self.assertTrue({"display_name", "bio", "email", "website", "domain", "alias", "organization"}.issubset(kinds))
        self.assertIn("https://portfolio.example/path", {item.normalized_value for item in attrs if item.attribute_type.value == "website"})
        display_name = next(item for item in attrs if item.attribute_type.value == "display_name")
        self.assertEqual(display_name.original_value, "Alex Morgan")
        self.assertNotIn("Overview", display_name.original_value)
        self.assertTrue(all(item.associated_username == "synthetic-user" for item in attrs))
        self.assertTrue(all(item.source_url == "https://source.example/profile" and item.collected_at.tzinfo for item in attrs))
        self.assertTrue(all(item.evidence and item.evidence_type and item.source_lineage and item.evidence_provenance for item in attrs))

    def test_jsonld_extracts_professional_technology_and_linked_profile_evidence(self):
        document = {
            "@context": "https://schema.org", "@type": "Person", "name": "Alex Morgan",
            "alternateName": "alex_morgan", "email": "alex@example.com",
            "url": "https://alex.example/", "sameAs": ["https://code.example/alex"],
            "jobTitle": "Research Engineer", "worksFor": {"@type": "Organization", "name": "Example Research"},
            "knowsAbout": ["Python", "Docker"], "address": {"addressLocality": "Example City"},
        }
        html = ('<script type="application/ld+json">' + json.dumps(document) + '</script>').encode()
        source_url = "https://profile.example/alex"
        attrs = _extract_attributes(PublicPage(source_url, "text/html", html, 200), "uti_synthetic")
        values = {(item.attribute_type.value, item.normalized_value) for item in attrs}
        self.assertIn(("publicly_stated_name", "Alex Morgan"), values)
        self.assertIn(("secondary_username", "alex_morgan"), values)
        self.assertIn(("email", "alex@example.com"), values)
        self.assertIn(("job_title", "Research Engineer"), values)
        self.assertIn(("professional_affiliation", "Example Research"), values)
        self.assertIn(("technology", "Python"), values)
        self.assertIn(("technology", "Docker"), values)
        self.assertIn(("social_profile", "https://code.example/alex"), values)
        self.assertIn(("coarse_location", "Example City"), values)
        self.assertTrue(all(item.source_url == source_url and item.evidence and item.evidence_provenance for item in attrs))

    def test_generic_200_profile_candidate_is_inconclusive_and_not_enriched(self):
        finding = self._finding()
        generic = b'<html><title>Welcome</title><body><span itemprop="name">Generic Site Title</span> Home page</body></html>'
        class FakeFetcher:
            max_urls = 5
            def fetch(self, url):
                return PublicPage(url, "text/html", generic, 200)
        result = PublicPageIdentityCollector(fetcher=FakeFetcher()).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(finding,)),
        )
        self.assertEqual(result.url_verification_results[0].status, URLVerificationStatus.INCONCLUSIVE)
        self.assertFalse(result.url_verification_results[0].profile_specific)
        self.assertEqual(result.attributes, ())

    def test_redirected_page_keeps_candidate_url_and_records_final_evidence_source(self):
        finding = self._finding(url="https://old.example/user")
        final_url = "https://new.example/profile/user"
        html = b'<meta property="og:type" content="profile"><meta property="og:title" content="Synthetic Name">'
        class FakeFetcher:
            max_urls = 5
            def fetch(self, _url):
                return PublicPage(finding.profile_url, "text/html", html, 200, final_url, 1)
        result = PublicPageIdentityCollector(fetcher=FakeFetcher()).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(finding,)),
        )
        self.assertEqual(result.url_verification_results[0].status, URLVerificationStatus.REDIRECTED)
        self.assertTrue(all(item.source_url == finding.profile_url for item in result.attributes))
        self.assertTrue(all(item.evidence_provenance[0].original_source_url == final_url for item in result.attributes))

    def test_discovered_profile_flows_through_collection_with_audit_and_exact_profile_mapping(self):
        finding = self._finding()
        html = b'<meta property="og:type" content="profile"><meta property="og:title" content="Synthetic Name"><a href="mailto:synthetic@example.org">email</a>'

        class FakeFetcher:
            max_urls = 10
            def fetch(self, url):
                self.requested_url = url
                return PublicPage(url, "text/html", html, 200)

        fetcher = FakeFetcher()
        request = IdentityCollectionRequest("uti_synthetic", profile_findings=(finding,))
        progress = []
        collection = PublicPageIdentityCollector(fetcher=fetcher).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(finding,), progress_callback=lambda stage, detail: progress.append((stage, detail))),
        )
        self.assertEqual(fetcher.requested_url, finding.profile_url)
        self.assertEqual(len(collection.attributes), 2)
        self.assertTrue(all(item.source_url == finding.profile_url for item in collection.attributes))
        audit = collection.profile_url_audits[0]
        self.assertEqual(audit.fetch_status.value, "fetched")
        self.assertTrue(audit.identity_collection_attempted)
        self.assertEqual(audit.http_status, 200)
        self.assertEqual(audit.extracted_attribute_count, 2)
        profile_rows = build_profile_intelligence((finding,), collection.attributes, collection.profile_url_audits)
        self.assertEqual(len(profile_rows), 1)
        self.assertEqual(len(profile_rows[0].attributes), 2)
        self.assertEqual(profile_rows[0].collection_audit.fetch_status.value, "fetched")
        self.assertEqual(collection.url_verification_results[0].status, URLVerificationStatus.VERIFIED_ACCESSIBLE)
        self.assertTrue(any(stage == "URL verification" for stage, _ in progress))
        self.assertTrue(any(stage == "OSINT enrichment" for stage, _ in progress))

    def test_profile_url_cap_counts_eligible_fetches_not_invalid_or_duplicate_rows(self):
        first = self._finding(url="https://social.example/first")
        second = self._finding(url="https://social.example/second")
        html = b'<meta property="og:type" content="profile"><meta property="og:title" content="Synthetic Name">'

        class FakeFetcher:
            max_urls = 1
            def __init__(self):
                self.calls = []
            def fetch(self, url):
                self.calls.append(url)
                return PublicPage(url, "text/html", html, 200)

        fetcher = FakeFetcher()
        result = PublicPageIdentityCollector(fetcher=fetcher).collect(IdentityCollectionRequest(
            "uti_synthetic",
            public_urls=("file:///synthetic/unsafe", first.profile_url),
            profile_findings=(first, second),
        ))
        # The repeated URL and unsafe URL do not waste the single eligible page slot.
        self.assertEqual(fetcher.calls, [first.profile_url])
        self.assertEqual(
            [audit.fetch_status.value for audit in result.profile_url_audits],
            ["skipped", "fetched", "skipped", "skipped"],
        )
        self.assertIn("maximum eligible URL count", result.profile_url_audits[-1].reason_skipped)
        self.assertTrue(any("URL limit reached" in diagnostic.message for diagnostic in result.diagnostics))

    def test_public_page_fetcher_default_limit_covers_more_than_ten_profiles(self):
        self.assertEqual(PublicPageFetcher().max_urls, 50)

    def test_attributes_from_two_profiles_are_not_combined(self):
        first = self._finding(url="https://one.example/profile")
        second = self._finding(url="https://two.example/profile")
        first_attribute = attr("display_name", "Synthetic One", url=first.profile_url)
        second_attribute = attr("email", "two@example.org", url=second.profile_url)
        rows = build_profile_intelligence((first, second), (first_attribute, second_attribute), ())
        self.assertEqual(len(rows), 2)
        self.assertEqual(tuple(item.attribute_type.value for item in rows[0].attributes), ("display_name",))
        self.assertEqual(tuple(item.attribute_type.value for item in rows[1].attributes), ("email",))

    def test_unsupported_discovery_source_is_audited_without_fetching(self):
        finding = self._finding(source_tool="unknown_collector")
        fetcher = Mock(max_urls=10)
        result = PublicPageIdentityCollector(fetcher=fetcher).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(finding,)),
        )
        fetcher.fetch.assert_not_called()
        self.assertEqual(result.profile_url_audits[0].fetch_status.value, "unsupported")
        self.assertFalse(result.profile_url_audits[0].identity_collection_attempted)

    def test_invalid_urls_and_unsupported_content_are_audited_honestly(self):
        invalid = PublicPageIdentityCollector(fetcher=Mock(max_urls=10)).collect(
            IdentityCollectionRequest("uti_synthetic", public_urls=("file:///synthetic/path",)),
        )
        self.assertEqual(invalid.profile_url_audits[0].fetch_status.value, "skipped")
        self.assertFalse(invalid.profile_url_audits[0].identity_collection_attempted)

        fetcher = Mock(max_urls=10)
        fetcher.fetch.side_effect = PublicPageFetchError("unsupported page content type: application/pdf", status_code=200)
        unsupported = PublicPageIdentityCollector(fetcher=fetcher).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(self._finding(),)),
        )
        audit = unsupported.profile_url_audits[0]
        self.assertEqual(audit.fetch_status.value, "unsupported")
        self.assertEqual(audit.http_status, 200)
        self.assertTrue(audit.identity_collection_attempted)

    def test_failed_fetch_and_duplicate_attributes_remain_source_attributed(self):
        first = self._finding(source_tool="sherlock")
        same_url = self._finding(source_tool="maigret")
        fetcher = Mock(max_urls=10)
        fetcher.fetch.side_effect = TimeoutError("synthetic timeout")
        # The collector records failure and does not manufacture attributes.
        failed = PublicPageIdentityCollector(fetcher=fetcher).collect(
            IdentityCollectionRequest("uti_synthetic", profile_findings=(first,)),
        )
        self.assertEqual(failed.profile_url_audits[0].fetch_status.value, "failed")
        self.assertIn("synthetic timeout", failed.profile_url_audits[0].error_or_warning)

        observations = (
            attr("email", "same@example.org", "source-a", "https://a.example/profile"),
            attr("email", "same@example.org", "source-b", "https://b.example/profile"),
        )
        deduplicated = deduplicate_identity_attributes(observations)
        self.assertEqual(len(deduplicated[0].observations), 2)
        self.assertEqual({item.source_tool for item in deduplicated[0].observations}, {"source-a", "source-b"})
        self.assertFalse(first.identity_verified or same_url.identity_verified)

    def test_public_fetcher_blocks_private_dns_and_redirects_and_enforces_content(self):
        private_resolver = lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        fetcher = PublicPageFetcher(resolver=private_resolver, requester=lambda *_: self.fail("must not request private host"))
        with self.assertRaises(PublicPageFetchError):
            fetcher.fetch("https://public.example/")

        resolver = lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        calls = []
        def redirect(_target, url, *_args):
            calls.append(url)
            return HTTPResponseData(404, {"content-type": "text/plain"}, b"") if url.endswith("robots.txt") else HTTPResponseData(302, {"location": "http://127.0.0.1/"}, b"")
        fetcher = PublicPageFetcher(resolver=resolver, requester=redirect, min_interval_seconds=0)
        with self.assertRaisesRegex(PublicPageFetchError, "non-public IP"):
            fetcher.fetch("https://public.example/")
        self.assertEqual(len(calls), 2)

    def test_url_verification_distinguishes_profile_generic_login_and_not_found(self):
        service = URLVerificationService()
        finding = self._finding()
        profile = PublicPage(finding.profile_url, "text/html", b'<meta property="og:type" content="profile"><title>Profile</title>', 200)
        generic = PublicPage(finding.profile_url, "text/html", b"<title>Generic home</title><p>Welcome</p>", 200)
        login = PublicPage(finding.profile_url, "text/html", b"<title>Sign in</title><form><input type=\"password\"></form>", 200)
        missing = PublicPage(finding.profile_url, "text/html", b"<title>Not found</title>", 404)
        self.assertEqual(service.evaluate("u", "p", finding.profile_url, ("sherlock",), finding.source_lineage, page=profile).status, URLVerificationStatus.VERIFIED_ACCESSIBLE)
        self.assertEqual(service.evaluate("u", "p", finding.profile_url, ("sherlock",), finding.source_lineage, page=generic).status, URLVerificationStatus.INCONCLUSIVE)
        self.assertEqual(service.evaluate("u", "p", finding.profile_url, ("sherlock",), finding.source_lineage, page=login).status, URLVerificationStatus.ACCESS_RESTRICTED)
        self.assertEqual(service.evaluate("u", "p", finding.profile_url, ("sherlock",), finding.source_lineage, page=missing).status, URLVerificationStatus.NOT_FOUND)
        self.assertEqual(service.evaluate("u", "p", finding.profile_url, ("sherlock",), finding.source_lineage, error=TimeoutError("synthetic timeout")).status, URLVerificationStatus.TIMEOUT)

    def test_url_verification_service_deduplicates_and_respects_page_cap(self):
        first = self._finding(url="https://one.example/profile")
        second = self._finding(url="https://two.example/profile")
        class FakeFetcher:
            max_urls = 1
            def __init__(self):
                self.calls = []
            def fetch(self, url, *, allow_http_errors=False):
                self.calls.append(url)
                return PublicPage(url, "text/html", b'<meta property="og:type" content="profile">', 200)
        fetcher = FakeFetcher()
        results = URLVerificationService(fetcher).verify((first, first, second))
        self.assertEqual(len(results), 2)
        self.assertEqual(fetcher.calls, [first.profile_url])
        self.assertEqual(results[0].status, URLVerificationStatus.VERIFIED_ACCESSIBLE)
        self.assertEqual(results[1].status, URLVerificationStatus.SKIPPED)

    def test_public_fetcher_follows_only_revalidated_redirects_and_records_final_url(self):
        resolver = lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        calls = []
        def requester(_target, url, *_args):
            calls.append(url)
            if url.endswith("robots.txt"):
                return HTTPResponseData(404, {"content-type": "text/plain"}, b"")
            if url == "https://one.example/start":
                return HTTPResponseData(302, {"location": "https://two.example/profile"}, b"")
            return HTTPResponseData(200, {"content-type": "text/html"}, b'<meta property="og:type" content="profile">')
        fetcher = PublicPageFetcher(resolver=resolver, requester=requester, min_interval_seconds=0)
        page = fetcher.fetch("https://one.example/start")
        self.assertEqual(page.url, "https://one.example/start")
        self.assertEqual(page.final_url, "https://two.example/profile")
        self.assertEqual(page.redirect_count, 1)
        self.assertEqual(calls, [
            "https://one.example/robots.txt", "https://one.example/start",
            "https://two.example/robots.txt", "https://two.example/profile",
        ])
        verified = URLVerificationService(fetcher).evaluate(
            "uti_synthetic", "Synthetic", page.url, ("sherlock",), (), page=page,
        )
        self.assertEqual(verified.status, URLVerificationStatus.REDIRECTED)
        self.assertTrue(verified.profile_specific)

    def test_public_fetcher_rejects_redirect_loop_and_mixed_public_private_dns(self):
        resolver = lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        def loop_request(_target, url, *_args):
            if url.endswith("robots.txt"):
                return HTTPResponseData(404, {"content-type": "text/plain"}, b"")
            return HTTPResponseData(302, {"location": url}, b"")
        with self.assertRaisesRegex(PublicPageFetchError, "redirect loop"):
            PublicPageFetcher(resolver=resolver, requester=loop_request, min_interval_seconds=0).fetch("https://one.example/profile")

        mixed_resolver = lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443)),
        ]
        fetcher = PublicPageFetcher(resolver=mixed_resolver, requester=lambda *_: self.fail("mixed DNS must be blocked"))
        with self.assertRaisesRegex(PublicPageFetchError, "non-public address"):
            fetcher.fetch("https://one.example/profile")

    def test_dns_resolution_timeout_is_bounded_and_reported(self):
        def slow_resolver(*_args, **_kwargs):
            time.sleep(0.05)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        finding = self._finding()
        fetcher = PublicPageFetcher(timeout_seconds=0.01, resolver=slow_resolver, requester=lambda *_: self.fail("DNS timeout must prevent HTTP"), min_interval_seconds=0)
        outcome = URLVerificationService(fetcher).verify((finding,))[0]
        self.assertEqual(outcome.status, URLVerificationStatus.TIMEOUT)

    def test_public_fetcher_rejects_unsupported_and_oversized_responses(self):
        resolver = lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        for page_response in (
            HTTPResponseData(200, {"content-type": "application/pdf"}, b"pdf"),
            HTTPResponseData(200, {"content-type": "text/html"}, b"123456789"),
        ):
            responses = [HTTPResponseData(404, {"content-type": "text/plain"}, b""), page_response]
            fetcher = PublicPageFetcher(
                resolver=resolver, requester=lambda *_args: responses.pop(0),
                min_interval_seconds=0, max_response_bytes=8,
            )
            with self.assertRaises(PublicPageFetchError):
                fetcher.fetch("https://public.example/")

    def test_identity_service_can_be_configured_with_no_sources_and_opt_in_is_explicit(self):
        empty_identity = IdentityIntelligenceService(collectors=[])
        identity_result = empty_identity.investigate(IdentityCollectionRequest("synthetic-user"), ())
        self.assertEqual(identity_result.attributes, ())

        untouched_identity_service = Mock()
        no_collectors = Mock(collect=Mock(return_value=SimpleNamespace(findings=(), warnings=(), diagnostics=(), error=None, timed_out=False, returncode=0, stdout="", stderr="", raw_records=())))
        result = InvestigationService(
            sherlock_collector=no_collectors, maigret_collector=no_collectors,
            identity_service=untouched_identity_service,
        ).investigate("synthetic-user")
        untouched_identity_service.investigate.assert_not_called()
        self.assertFalse(result.identity_collection_enabled)
        self.assertFalse(result.identity_attributes)

    def test_investigation_service_automatically_passes_discovered_profiles_when_enabled(self):
        finding = self._finding()
        html = b'<meta property="og:type" content="profile"><meta property="og:title" content="Synthetic Name">'

        class FakeFetcher:
            max_urls = 10
            def fetch(self, url):
                return PublicPage(url, "text/html", html, 200)

        execution = SimpleNamespace(
            findings=(finding,), warnings=(), diagnostics=(), error=None, timed_out=False,
            returncode=0, stdout="", stderr="", raw_records=(),
        )
        first_collector = Mock(collect=Mock(return_value=execution))
        second_collector = Mock(collect=Mock(return_value=SimpleNamespace(
            findings=(), warnings=(), diagnostics=(), error=None, timed_out=False,
            returncode=0, stdout="", stderr="", raw_records=(),
        )))
        identity_service = IdentityIntelligenceService([PublicPageIdentityCollector(fetcher=FakeFetcher())])
        result = InvestigationService(
            sherlock_collector=first_collector,
            maigret_collector=second_collector,
            identity_service=identity_service,
        ).investigate("uti_synthetic", enable_identity_collection=True)
        self.assertTrue(result.identity_collection_enabled)
        self.assertEqual(len(result.identity_attributes), 1)
        self.assertEqual(result.identity_attributes[0].source_url, finding.profile_url)
        self.assertEqual(len(result.profile_url_audits), 1)
        self.assertEqual(result.profile_url_audits[0].fetch_status.value, "fetched")
        self.assertEqual(result.url_verification_results[0].status, URLVerificationStatus.VERIFIED_ACCESSIBLE)
        self.assertEqual(result.attack_surface.verified_accessible_profiles, 1)
        self.assertFalse(result.identity_attributes[0].verification_status.value == "independently_corroborated")

    def test_disabled_identity_still_audits_discovery_and_preserves_raw_collector_url(self):
        finding = self._finding()
        raw_url = f" {finding.profile_url} "
        raw = RawCollectorRecord(
            "sherlock", 2,
            ("username", "name", "url_user"),
            (finding.username, finding.platform, raw_url),
        )
        sherlock = Mock(collect=Mock(return_value=SimpleNamespace(
            findings=(finding,), warnings=(), diagnostics=(), error=None, timed_out=False,
            returncode=0, stdout="", stderr="", raw_records=(raw,),
        )))
        maigret = Mock(collect=Mock(return_value=SimpleNamespace(
            findings=(), warnings=(), diagnostics=(), error=None, timed_out=False,
            returncode=0, stdout="", stderr="", raw_records=(),
        )))
        result = InvestigationService(sherlock_collector=sherlock, maigret_collector=maigret).investigate("uti_synthetic")
        audit = result.profile_url_audits[0]
        self.assertEqual(audit.fetch_status.value, "discovered")
        self.assertFalse(audit.identity_collection_attempted)
        self.assertEqual(audit.canonical_profile_url, "https://social.example/uti_synthetic")
        self.assertEqual(audit.original_profile_urls, (raw_url,))


if __name__ == "__main__":
    unittest.main()
