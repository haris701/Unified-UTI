"""Identity collector interface and failure-isolated orchestration."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, TYPE_CHECKING, Callable

from uti.identity.models import (
    IdentityAttribute, IdentityDiagnostic, DiagnosticLevel, ProfileURLCollectionAudit,
)
from uti.models import Finding

if TYPE_CHECKING:
    from uti.identity.url_verification import URLVerificationResult


@dataclass(frozen=True, slots=True)
class IdentityCollectionRequest:
    username: str
    public_urls: tuple[str, ...] = ()
    original_profile_urls: tuple[tuple[str, str], ...] = ()
    profile_findings: tuple[Finding, ...] = ()
    include_profile_findings: bool = True
    local_evidence_content: bytes | None = None
    local_evidence_filename: str | None = None
    progress_callback: Callable[[str, str], None] | None = None


@dataclass(frozen=True, slots=True)
class IdentityCollectionResult:
    collector_name: str
    attributes: tuple[IdentityAttribute, ...] = ()
    diagnostics: tuple[IdentityDiagnostic, ...] = ()
    profile_url_audits: tuple[ProfileURLCollectionAudit, ...] = ()
    url_verification_results: tuple[URLVerificationResult, ...] = ()


class IdentityCollector(Protocol):
    """Adapter for one explicitly configured public or authorized identity source."""

    name: str

    def collect(self, request: IdentityCollectionRequest) -> IdentityCollectionResult: ...


class IdentityCollectorService:
    """Run configured identity adapters independently and retain diagnostics."""

    def __init__(self, collectors: Sequence[IdentityCollector]) -> None:
        self.collectors = tuple(collectors)

    def collect(self, request: IdentityCollectionRequest) -> IdentityCollectionResult:
        attributes: list[IdentityAttribute] = []
        diagnostics: list[IdentityDiagnostic] = []
        audits: list[ProfileURLCollectionAudit] = []
        url_verification: list[URLVerificationResult] = []
        for collector in self.collectors:
            collector_name = getattr(collector, "name", type(collector).__name__)
            if request.progress_callback is not None:
                request.progress_callback("Identity collection", f"Running {collector_name}")
            try:
                result = collector.collect(request)
            except Exception as exc:  # A failing source must not discard other source results.
                diagnostics.append(IdentityDiagnostic(
                    collector_name=collector_name,
                    message=f"identity collector failed: {exc}",
                    level=DiagnosticLevel.ERROR,
                ))
                continue
            if not isinstance(result, IdentityCollectionResult):
                diagnostics.append(IdentityDiagnostic(
                    collector_name=collector_name,
                    message="collector returned an unsupported result type",
                    level=DiagnosticLevel.ERROR,
                ))
                continue
            attributes.extend(result.attributes)
            diagnostics.extend(result.diagnostics)
            audits.extend(result.profile_url_audits)
            url_verification.extend(result.url_verification_results)
            if request.progress_callback is not None:
                request.progress_callback("Identity collection", f"{collector_name} completed")
        return IdentityCollectionResult("identity_service", tuple(attributes), tuple(diagnostics), tuple(audits), tuple(url_verification))


class FindingProfileAttributeCollector:
    """Represent existing Findings as reported profile URL attributes, without fetching them."""

    name = "finding_profile_attributes"

    def collect(self, request: IdentityCollectionRequest) -> IdentityCollectionResult:
        if not request.include_profile_findings:
            return IdentityCollectionResult(self.name)
        from uti.identity.normalization import normalize_identity_attribute

        attributes = []
        for finding in request.profile_findings:
            evidence = " | ".join(finding.evidence) or f"{finding.source_tool} reported this candidate profile URL"
            attributes.append(normalize_identity_attribute({
                "attribute_type": "social_profile",
                "value": finding.profile_url,
                "source_tool": finding.source_tool,
                "source_url": finding.profile_url,
                "collected_at": finding.collected_at,
                "evidence": evidence,
                "evidence_type": "collector_reported_profile_url",
                "source_lineage": finding.source_lineage,
                "evidence_provenance": finding.evidence_provenance,
                "verification_status": "source_reported",
                "association_status": "potential_association",
                "sensitivity": "public",
                "associated_username": finding.username,
            }))
        return IdentityCollectionResult(self.name, tuple(attributes))

