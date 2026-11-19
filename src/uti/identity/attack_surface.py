"""Investigation-level public exposure summary with no composite risk score."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from uti.identity.analysis import ThreatIndicator
from uti.identity.correlation import IdentityCorrelation
from uti.identity.models import IdentityAttribute, IdentityAttributeType
from uti.identity.url_verification import URLVerificationResult, URLVerificationStatus
from uti.models import Finding
from uti.utils.urls import canonical_profile_url


@dataclass(frozen=True, slots=True)
class AttackSurfaceAssessment:
    """Counts and evidence-backed narrative for one investigation."""

    discovered_profile_urls: int
    unique_eligible_profile_urls: int
    verified_accessible_profiles: int
    inconclusive_urls: int
    failed_or_skipped_urls: int
    identity_attributes_found: int
    public_contact_indicators: int
    developer_technology_indicators: int
    professional_information_indicators: int
    public_websites_and_domains: int
    supported_correlations: int
    generated_threat_indicators: int
    category_summaries: tuple[tuple[str, int], ...]
    overall_status: str
    overall_assessment: str
    recommended_actions: tuple[str, ...]
    evidence_limitations: tuple[str, ...]


def assess_attack_surface(
    findings: Iterable[Finding],
    verification: Iterable[URLVerificationResult],
    attributes: Iterable[IdentityAttribute],
    correlations: Iterable[IdentityCorrelation],
    indicators: Iterable[ThreatIndicator],
) -> AttackSurfaceAssessment:
    """Summarize observed public evidence; never infer compromise or identity."""
    profiles = tuple(findings)
    urls = tuple(verification)
    attrs = tuple(attributes)
    links = tuple(correlations)
    threats = tuple(indicators)
    unique_attrs = {(item.attribute_type, item.normalized_value) for item in attrs}
    counts = {kind: sum(1 for attr_type, _ in unique_attrs if attr_type is kind) for kind in IdentityAttributeType}
    accessible = sum(
        item.status is URLVerificationStatus.VERIFIED_ACCESSIBLE
        or (item.status is URLVerificationStatus.REDIRECTED and item.profile_specific)
        for item in urls
    )
    inconclusive = sum(item.status is URLVerificationStatus.INCONCLUSIVE for item in urls)
    failed = sum(item.status in {
        URLVerificationStatus.NOT_FOUND, URLVerificationStatus.ACCESS_RESTRICTED,
        URLVerificationStatus.TIMEOUT, URLVerificationStatus.ERROR, URLVerificationStatus.SKIPPED,
    } or (item.status is URLVerificationStatus.REDIRECTED and not item.profile_specific) for item in urls)
    contacts = counts[IdentityAttributeType.EMAIL] + counts[IdentityAttributeType.PHONE]
    developer = counts[IdentityAttributeType.TECHNOLOGY] + counts[IdentityAttributeType.SKILL]
    professional = counts[IdentityAttributeType.JOB_TITLE] + counts[IdentityAttributeType.PROFESSIONAL_AFFILIATION]
    web_domains = counts[IdentityAttributeType.WEBSITE] + counts[IdentityAttributeType.DOMAIN]
    categories = (
        ("identity_exposure", counts[IdentityAttributeType.DISPLAY_NAME] + counts[IdentityAttributeType.PUBLICLY_STATED_NAME] + counts[IdentityAttributeType.ALIAS] + counts[IdentityAttributeType.SECONDARY_USERNAME]),
        ("contact_exposure", contacts),
        ("developer_footprint", developer),
        ("professional_footprint", professional),
        ("digital_footprint", counts[IdentityAttributeType.BIO] + counts[IdentityAttributeType.SOCIAL_PROFILE] + counts[IdentityAttributeType.PROFILE_IMAGE_URL]),
        ("website_domain_associations", web_domains),
        ("organization_associations", counts[IdentityAttributeType.ORGANIZATION] + counts[IdentityAttributeType.PROFESSIONAL_AFFILIATION]),
        ("profile_inconsistencies", 0),
        ("evidence_quality_issues", sum(item.indicator_type.value == "evidence_quality_issue" for item in threats)),
    )
    if attrs and (accessible or any(item.source_url for item in attrs)):
        overall_status = "informational"
        descriptors = []
        if developer:
            descriptors.append("developer or technology details")
        if professional:
            descriptors.append("professional details")
        if contacts:
            descriptors.append("public contact values")
        if web_domains:
            descriptors.append("websites or domains")
        if not descriptors:
            descriptors.append("public identity or profile details")
        overall = f"The collected evidence includes {'; '.join(descriptors)} in source-attributed records. These details may support reconnaissance. No account ownership, compromise, or malicious activity was established."
    else:
        overall_status = "inconclusive"
        overall = "Available evidence is insufficient to characterize the public exposure surface. Candidate profile results and page reachability alone do not establish identity or compromise."
    actions = tuple(dict.fromkeys(
        item.recommended_action for item in threats if item.recommended_action.strip()
    ))
    limitations = [
        "Profile detection and page accessibility do not verify account ownership or common identity.",
        "Generic, login, bot-protection, and error pages are not treated as verified profiles.",
        "Only pages returned by enabled Sherlock/Maigret discovery and allowed by URL, robots, content, time, and response limits were assessed.",
        "No breach database, private source, credential check, or platform-specific identity API is included.",
    ]
    if any(item.status is URLVerificationStatus.INCONCLUSIVE for item in urls):
        limitations.append("Some reachable pages did not expose reliable profile-specific indicators.")
    if any(item.status is URLVerificationStatus.SKIPPED for item in urls):
        limitations.append("Some candidate URLs were skipped by collection eligibility, safety, or configured limits.")
    eligible_urls = set()
    for item in urls:
        if item.status is URLVerificationStatus.SKIPPED:
            continue
        try:
            eligible_urls.add(canonical_profile_url(item.original_url.strip()))
        except ValueError:
            eligible_urls.add(item.original_url)
    return AttackSurfaceAssessment(
        (len(urls) if urls else len(profiles)), len(eligible_urls),
        accessible, inconclusive, failed, len(unique_attrs), contacts, developer, professional,
        web_domains, len(links), len(threats), categories, overall_status, overall,
        actions, tuple(limitations),
    )


__all__ = ["AttackSurfaceAssessment", "assess_attack_surface"]
