"""Explainable, conservative threat-intelligence indicators."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from collections.abc import Iterable

from uti.identity.models import IdentityAttribute, IdentityAttributeType
from uti.models import Finding
from uti.utils.urls import canonical_profile_url


class ThreatIndicatorType(str, Enum):
    PUBLIC_IDENTITY_EXPOSURE = "public_identity_exposure"
    PUBLIC_CONTACT_EXPOSURE = "public_contact_exposure"
    DIGITAL_FOOTPRINT_EXPOSURE = "digital_footprint_exposure"
    POTENTIAL_IMPERSONATION_INDICATOR = "potential_impersonation_indicator"
    PUBLIC_PROFILE_INCONSISTENCY = "public_profile_inconsistency"
    POTENTIAL_PROFILE_INCONSISTENCY = "potential_profile_inconsistency"
    ORGANIZATION_ASSOCIATION = "organization_association"
    DOMAIN_ASSOCIATION = "domain_association"
    DEVELOPER_INFORMATION_EXPOSURE = "developer_information_exposure"
    PROFESSIONAL_INFORMATION_EXPOSURE = "professional_information_exposure"
    PUBLIC_TECHNOLOGY_DISCLOSURE = "public_technology_disclosure"
    EVIDENCE_QUALITY_ISSUE = "evidence_quality_issue"
    SOURCE_RELIABILITY_ISSUE = "source_reliability_issue"


class ThreatSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ThreatIndicator:
    """Rule explanation backed by cited findings and identity observations."""

    indicator_type: ThreatIndicatorType
    description: str
    supporting_evidence: tuple[str, ...]
    source_references: tuple[str, ...]
    affected_attributes: tuple[str, ...]
    severity: ThreatSeverity
    severity_reason: str
    recommended_action: str
    limitations: tuple[str, ...]
    source_profile_urls: tuple[str, ...] = ()
    related_identity_attributes: tuple[IdentityAttribute, ...] = ()
    related_username_findings: tuple[Finding, ...] = ()


_IDENTITY_TYPES = {
    IdentityAttributeType.DISPLAY_NAME,
    IdentityAttributeType.PUBLICLY_STATED_NAME,
    IdentityAttributeType.ALIAS,
    IdentityAttributeType.ORGANIZATION,
    IdentityAttributeType.COARSE_LOCATION,
    IdentityAttributeType.BIO,
}
_FOOTPRINT_TYPES = {
    IdentityAttributeType.WEBSITE,
    IdentityAttributeType.DOMAIN,
    IdentityAttributeType.SOCIAL_PROFILE,
    IdentityAttributeType.BIO,
    IdentityAttributeType.PROFILE_IMAGE_URL,
}


def analyze_threats(
    attributes: Iterable[IdentityAttribute],
    findings: Iterable[Finding] = (),
    *,
    diagnostics: Iterable[object] = (),
) -> tuple[ThreatIndicator, ...]:
    """Generate descriptive exposure indicators; never infer malicious intent."""
    attrs = tuple(attributes)
    profile_findings = tuple(findings)
    outputs: list[ThreatIndicator] = []
    identity = tuple(item for item in attrs if item.attribute_type in _IDENTITY_TYPES)
    contact = tuple(item for item in attrs if item.attribute_type in {IdentityAttributeType.EMAIL, IdentityAttributeType.PHONE})
    footprint = tuple(item for item in attrs if item.attribute_type in _FOOTPRINT_TYPES)
    developer = tuple(item for item in attrs if item.attribute_type in {IdentityAttributeType.TECHNOLOGY, IdentityAttributeType.SKILL})
    professional = tuple(item for item in attrs if item.attribute_type in {IdentityAttributeType.JOB_TITLE, IdentityAttributeType.PROFESSIONAL_AFFILIATION})
    if identity:
        outputs.append(_indicator(
            ThreatIndicatorType.PUBLIC_IDENTITY_EXPOSURE,
            "Public identity-related values were explicitly reported by collected sources.", identity,
            "Review whether these values should remain publicly visible and remove or restrict them where appropriate.",
            findings=profile_findings,
        ))
    if contact:
        outputs.append(_indicator(
            ThreatIndicatorType.PUBLIC_CONTACT_EXPOSURE,
            "Publicly published contact values were observed in the supplied evidence.", contact,
            "Review the source page's visibility and remove or replace contact details that are not intended for public use.",
            findings=profile_findings,
        ))
    if footprint:
        refs = tuple(dict.fromkeys(
            item.source_url for item in footprint if item.source_url
        ))
        evidence = tuple(item.evidence for item in footprint)
        affected = tuple(item.attribute_type.value for item in footprint)
        outputs.append(ThreatIndicator(
            ThreatIndicatorType.DIGITAL_FOOTPRINT_EXPOSURE,
            "A public biography, website, domain, profile link, or profile image was retrieved from a source page.",
            tuple(dict.fromkeys(evidence)), refs, tuple(dict.fromkeys(affected)),
            ThreatSeverity.INFORMATIONAL,
            "Public presence by itself is not a threat; no elevated severity rule is justified by this evidence.",
            "Review profile visibility, recovery settings, and reuse of public contact details.",
            ("A collector-reported profile URL alone is not treated as retrieved public exposure.",
             "Retrieved page content does not verify account ownership or identify the account operator."),
            source_profile_urls=tuple(dict.fromkeys(item.source_url for item in footprint if item.source_url)),
            related_identity_attributes=footprint,
            related_username_findings=_related_findings(footprint, profile_findings),
        ))
    organizations = tuple(item for item in attrs if item.attribute_type is IdentityAttributeType.ORGANIZATION)
    if organizations:
        outputs.append(_indicator(
            ThreatIndicatorType.ORGANIZATION_ASSOCIATION,
            "An organization value was reported by a public source; the relationship is not independently verified.", organizations,
            "Confirm the affiliation through an authorized official source before relying on it.",
            findings=profile_findings,
        ))
    domains = tuple(item for item in attrs if item.attribute_type in {IdentityAttributeType.DOMAIN, IdentityAttributeType.WEBSITE})
    if domains:
        outputs.append(_indicator(
            ThreatIndicatorType.DOMAIN_ASSOCIATION,
            "A website or domain was explicitly present in the collected evidence.", domains,
            "Review DNS, website ownership, and account-security configuration only within authorized scope.",
            findings=profile_findings,
        ))
    if developer:
        outputs.append(_indicator(
            ThreatIndicatorType.DEVELOPER_INFORMATION_EXPOSURE,
            "A public profile explicitly disclosed technology terms or skills. This can provide reconnaissance context but does not show a vulnerability or compromise.",
            developer,
            "Review public repositories, profile descriptions, and linked technical material for accidental secrets or infrastructure details.",
            findings=profile_findings,
        ))
        outputs.append(_indicator(
            ThreatIndicatorType.PUBLIC_TECHNOLOGY_DISCLOSURE,
            "Technology or skill terms were explicitly present in public profile evidence.",
            developer,
            "Keep only technical details that are appropriate for public disclosure; do not infer vulnerability from technology names alone.",
            findings=profile_findings,
        ))
    if professional:
        outputs.append(_indicator(
            ThreatIndicatorType.PROFESSIONAL_INFORMATION_EXPOSURE,
            "A public source explicitly stated a job title or professional affiliation.",
            professional,
            "Review whether professional affiliation and role details should remain public and current.",
            findings=profile_findings,
        ))
    diagnostic_items = tuple(diagnostics)
    if diagnostic_items:
        outputs.append(ThreatIndicator(
            ThreatIndicatorType.EVIDENCE_QUALITY_ISSUE,
            "One or more identity collection limitations or validation diagnostics were recorded.",
            tuple(str(getattr(item, "message", item)) for item in diagnostic_items),
            tuple(dict.fromkeys(str(getattr(item, "source_url", "") or "") for item in diagnostic_items if getattr(item, "source_url", None))),
            (), ThreatSeverity.INFORMATIONAL,
            "Diagnostics reduce completeness; they do not establish a security incident.",
            "Resolve collection warnings and review the original sources before using the evidence.",
            ("A warning may reflect access restrictions, unavailable pages, or unsupported content rather than missing identity data.",),
        ))
    return tuple(outputs)


def _indicator(
    kind: ThreatIndicatorType,
    description: str,
    attributes: tuple[IdentityAttribute, ...],
    recommended_action: str,
    *,
    findings: tuple[Finding, ...] = (),
) -> ThreatIndicator:
    source_urls = tuple(dict.fromkeys(item.source_url for item in attributes if item.source_url))
    source_keys = set()
    for source_url in source_urls:
        try:
            source_keys.add(canonical_profile_url(source_url))
        except ValueError:
            continue
    related_findings = _related_findings(attributes, findings, source_keys=source_keys)
    return ThreatIndicator(
        indicator_type=kind,
        description=description,
        supporting_evidence=tuple(dict.fromkeys(item.evidence for item in attributes)),
        source_references=tuple(dict.fromkeys(item.source_url for item in attributes if item.source_url)),
        affected_attributes=tuple(dict.fromkeys(item.attribute_type.value for item in attributes)),
        severity=ThreatSeverity.INFORMATIONAL,
        severity_reason="No validated risk model or independently established harm supports a higher severity.",
        recommended_action=recommended_action,
        limitations=(
            "Source-reported public data does not verify account ownership or common identity.",
            "This indicator describes exposure for defensive review; it is not an allegation of malicious activity.",
        ),
        source_profile_urls=source_urls,
        related_identity_attributes=attributes,
        related_username_findings=related_findings,
    )


def _related_findings(
    attributes: tuple[IdentityAttribute, ...],
    findings: tuple[Finding, ...],
    *,
    source_keys: set[str] | None = None,
) -> tuple[Finding, ...]:
    keys = source_keys if source_keys is not None else set()
    if source_keys is None:
        for attribute in attributes:
            if attribute.source_url:
                try:
                    keys.add(canonical_profile_url(attribute.source_url))
                except ValueError:
                    continue
    return tuple(
        finding for finding in findings
        if canonical_profile_url(finding.profile_url) in keys
    )

