"""Identity collection, exact-value grouping, correlation, and threat analysis."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence

from uti.identity.analysis import ThreatIndicator, analyze_threats
from uti.identity.collectors.base import (
    IdentityCollectionRequest,
    IdentityCollectionResult,
    IdentityCollector,
    IdentityCollectorService,
)
from uti.identity.collectors.local_file import LocalEvidenceIdentityCollector
from uti.identity.collectors.public_page import PublicPageIdentityCollector
from uti.identity.correlation import IdentityCorrelation, correlate_identity_attributes
from uti.identity.deduplication import DeduplicatedIdentityAttribute, deduplicate_identity_attributes
from uti.identity.models import IdentityAttribute, IdentityDiagnostic
from uti.identity.models import ProfileURLCollectionAudit
from uti.identity.url_verification import URLVerificationResult
from uti.models import Finding


@dataclass(frozen=True, slots=True)
class IdentityIntelligenceResult:
    attributes: tuple[IdentityAttribute, ...]
    deduplicated_attributes: tuple[DeduplicatedIdentityAttribute, ...]
    correlations: tuple[IdentityCorrelation, ...]
    threat_indicators: tuple[ThreatIndicator, ...]
    diagnostics: tuple[IdentityDiagnostic, ...]
    profile_url_audits: tuple[ProfileURLCollectionAudit, ...] = ()
    url_verification_results: tuple[URLVerificationResult, ...] = ()


class IdentityIntelligenceService:
    """Run configured identity adapters and assess their resulting evidence."""

    def __init__(self, collectors: Sequence[IdentityCollector] | None = None) -> None:
        configured = collectors if collectors is not None else (
            PublicPageIdentityCollector(),
            LocalEvidenceIdentityCollector(),
        )
        self.collector_service = IdentityCollectorService(configured)

    def investigate(
        self,
        request: IdentityCollectionRequest,
        findings: Sequence[Finding],
    ) -> IdentityIntelligenceResult:
        collection: IdentityCollectionResult = self.collector_service.collect(request)
        if request.progress_callback is not None:
            request.progress_callback("Identity correlation", "grouping matching source-reported attributes")
        deduplicated = deduplicate_identity_attributes(collection.attributes)
        correlations = correlate_identity_attributes(deduplicated)
        if request.progress_callback is not None:
            request.progress_callback("Threat analysis", "evaluating evidence-backed exposure rules")
        indicators = analyze_threats(collection.attributes, findings, diagnostics=collection.diagnostics)
        return IdentityIntelligenceResult(
            attributes=collection.attributes,
            deduplicated_attributes=deduplicated,
            correlations=correlations,
            threat_indicators=indicators,
            diagnostics=collection.diagnostics,
            profile_url_audits=collection.profile_url_audits,
            url_verification_results=collection.url_verification_results,
        )

