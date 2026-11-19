"""Orchestrate collectors and existing finding-processing components."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Protocol, Sequence, Callable

from uti.collectors.maigret import MaigretCollector, MaigretRunResult
from uti.collectors.sherlock import SherlockCollector, SherlockRunResult
from uti.correlation import CorrelationGroup, correlate_findings
from uti.deduplication import deduplicate_findings
from uti.models import Finding, RawCollectorRecord
from uti.identity.analysis import ThreatIndicator, analyze_threats
from uti.identity.attack_surface import AttackSurfaceAssessment, assess_attack_surface
from uti.identity.collectors.base import IdentityCollectionRequest
from uti.identity.models import (
    IdentityAttribute, IdentityDiagnostic, DiagnosticLevel,
    ProfileURLCollectionAudit, ProfileURLCollectionStatus,
)
from uti.identity.service import IdentityIntelligenceResult, IdentityIntelligenceService
from uti.identity.url_verification import URLVerificationResult, URLVerificationStatus
from uti.identity.deduplication import DeduplicatedIdentityAttribute
from uti.identity.correlation import IdentityCorrelation
from uti.scoring import FindingAssessment, assess_finding, assess_profile_check
from uti.utils.urls import canonical_profile_url


class _Collector(Protocol):
    """Minimal collector interface required by the investigation service."""

    def collect(self, username: str) -> SherlockRunResult | MaigretRunResult: ...


@dataclass(frozen=True, slots=True)
class CollectorExecutionSummary:
    """Captured execution details for one collector invocation."""

    collector_name: str
    findings_count: int
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str | None = None
    timed_out: bool = False
    warnings: tuple[str, ...] = ()
    diagnostics: tuple[object, ...] = ()
    raw_records: tuple[RawCollectorRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    """All collection and processing outputs for one username investigation."""

    username: str
    collector_summaries: tuple[CollectorExecutionSummary, ...]
    normalized_findings: tuple[Finding, ...]
    deduplicated_findings: tuple[Finding, ...]
    correlation_results: tuple[CorrelationGroup, ...]
    assessments: tuple[FindingAssessment, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    investigated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    identity_collection_enabled: bool = False
    identity_attributes: tuple[IdentityAttribute, ...] = ()
    deduplicated_identity_attributes: tuple[DeduplicatedIdentityAttribute, ...] = ()
    identity_correlations: tuple[IdentityCorrelation, ...] = ()
    threat_indicators: tuple[ThreatIndicator, ...] = ()
    identity_diagnostics: tuple[IdentityDiagnostic, ...] = ()
    profile_url_audits: tuple[ProfileURLCollectionAudit, ...] = ()
    url_verification_results: tuple[URLVerificationResult, ...] = ()
    attack_surface: AttackSurfaceAssessment | None = None
    identity_limitations: tuple[str, ...] = (
        "Collector-reported profile presence and public attributes do not verify account ownership or real-world identity.",
        "Attribute matches are candidate relationships; shared values alone do not prove common identity.",
        "Source independence remains unknown unless provenance declares the underlying data source.",
    )


class InvestigationService:
    """Run Sherlock and Maigret independently, then process their findings.

    Collector instances may be injected for configuration, reuse, or tests.
    A failure from one collector is recorded and never stops the other from
    running. Assessments describe collector outcomes and record completeness;
    no composite or identity score is generated.
    """

    def __init__(
        self,
        *,
        sherlock_collector: _Collector | None = None,
        maigret_collector: _Collector | None = None,
        identity_service: IdentityIntelligenceService | None = None,
    ) -> None:
        self.sherlock_collector = SherlockCollector() if sherlock_collector is None else sherlock_collector
        self.maigret_collector = MaigretCollector() if maigret_collector is None else maigret_collector
        self.identity_service = IdentityIntelligenceService() if identity_service is None else identity_service

    def investigate(
        self,
        username: str,
        *,
        enable_identity_collection: bool = False,
        public_urls: Sequence[str] = (),
        include_profile_findings: bool = True,
        identity_evidence_content: bytes | None = None,
        identity_evidence_filename: str | None = None,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> InvestigationResult:
        """Collect profile and optional identity evidence for one username.

        Identity collection is disabled by default. Public-page retrieval only
        occurs after explicit opt-in and only for supplied URLs or findings the
        caller specifically opts to enrich.
        """
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username must be a non-empty string")
        if not isinstance(enable_identity_collection, bool) or not isinstance(include_profile_findings, bool):
            raise ValueError("identity collection options must be booleans")
        if not isinstance(public_urls, Sequence) or isinstance(public_urls, (str, bytes)) or any(
            not isinstance(url, str) for url in public_urls
        ):
            raise ValueError("public_urls must be a sequence of strings")
        if identity_evidence_content is not None and not isinstance(identity_evidence_content, bytes):
            raise ValueError("identity_evidence_content must be bytes or None")
        investigated_at = datetime.now(timezone.utc)

        summaries: list[CollectorExecutionSummary] = []
        normalized: list[Finding] = []
        warnings: list[str] = []
        errors: list[str] = []

        collectors = (
            ("sherlock", self.sherlock_collector),
            ("maigret", self.maigret_collector),
        )
        for collector_name, _ in collectors:
            if progress_callback is not None:
                progress_callback(collector_name.title(), "running")
        # The collectors are independent subprocesses. Running them together
        # reduces wall-clock time while preserving separate results/errors.
        with ThreadPoolExecutor(max_workers=len(collectors), thread_name_prefix="uti-collector") as executor:
            executions = {
                collector_name: executor.submit(collector.collect, username)
                for collector_name, collector in collectors
            }

        for collector_name, _ in collectors:
            try:
                execution = executions[collector_name].result()
            except Exception as exc:  # Keep independent collector work moving.
                message = f"{collector_name} collector failed: {exc}"
                errors.append(message)
                summaries.append(
                    CollectorExecutionSummary(
                        collector_name=collector_name,
                        findings_count=0,
                        error=message,
                        timed_out=_is_timeout_exception(exc),
                    )
                )
                if progress_callback is not None:
                    progress_callback(collector_name.title(), "failed; continuing with the other collector")
                continue

            collector_findings: list[Finding] = []
            for index, finding in enumerate(getattr(execution, "findings", ())):
                if not isinstance(finding, Finding):
                    message = f"{collector_name} returned a non-Finding result at index {index}"
                    errors.append(message)
                    continue
                if finding.username != username:
                    message = f"{collector_name} returned a finding for a different username at index {index}"
                    errors.append(message)
                    continue
                try:
                    # Reconstructing validates the existing normalized model
                    # while retaining all evidence and source lineage fields.
                    normalized_finding = replace(finding)
                except (TypeError, ValueError) as exc:
                    message = f"{collector_name} returned an invalid finding at index {index}: {exc}"
                    errors.append(message)
                    continue
                collector_findings.append(normalized_finding)
                normalized.append(normalized_finding)

            raw_warnings = tuple(getattr(execution, "warnings", ()) or ())
            raw_diagnostics = tuple(getattr(execution, "diagnostics", ()) or ())
            for warning in raw_warnings:
                warnings.append(f"{collector_name}: {warning}")

            collector_error = getattr(execution, "error", None)
            if collector_error:
                errors.append(f"{collector_name}: {collector_error}")
            timed_out = bool(getattr(execution, "timed_out", False))
            if timed_out and not collector_error:
                errors.append(f"{collector_name} collector timed out")

            summaries.append(
                CollectorExecutionSummary(
                    collector_name=collector_name,
                    findings_count=len(collector_findings),
                    stdout=_text_or_empty(getattr(execution, "stdout", "")),
                    stderr=_text_or_empty(getattr(execution, "stderr", "")),
                    returncode=getattr(execution, "returncode", None),
                    error=str(collector_error) if collector_error else None,
                    timed_out=timed_out,
                    warnings=raw_warnings,
                    diagnostics=raw_diagnostics,
                    raw_records=tuple(
                        item for item in (getattr(execution, "raw_records", ()) or ())
                        if isinstance(item, RawCollectorRecord)
                    ),
                )
            )
            if progress_callback is not None:
                progress_callback(collector_name.title(), "completed")

        if progress_callback is not None:
            progress_callback("Normalization and deduplication", "processing collected findings")
        deduplicated = deduplicate_findings(normalized)
        correlations = correlate_findings(deduplicated)
        assessments: list[FindingAssessment] = []
        for finding in deduplicated:
            key = (finding.username, canonical_profile_url(finding.profile_url))
            observations = tuple(
                assess_profile_check(source_finding)
                for source_finding in normalized
                if (source_finding.username, canonical_profile_url(source_finding.profile_url)) == key
            )
            base_assessment = assess_finding(finding)
            assessments.append(replace(base_assessment, profile_check_outcomes=observations))
        if progress_callback is not None:
            progress_callback("Correlation and assessment", "completed")

        identity_attributes: tuple[IdentityAttribute, ...] = ()
        deduplicated_identity_attributes: tuple[DeduplicatedIdentityAttribute, ...] = ()
        identity_correlations: tuple[IdentityCorrelation, ...] = ()
        identity_diagnostics: tuple[IdentityDiagnostic, ...] = ()
        profile_url_audits: tuple[ProfileURLCollectionAudit, ...] = ()
        url_verification_results: tuple[URLVerificationResult, ...] = ()
        if enable_identity_collection:
            request = IdentityCollectionRequest(
                username=username,
                public_urls=tuple(public_urls),
                original_profile_urls=tuple(
                    (canonical_profile_url(finding.profile_url), original_url)
                    for finding in deduplicated
                    for original_url in _original_profile_urls(finding, summaries)
                ),
                profile_findings=tuple(deduplicated),
                include_profile_findings=include_profile_findings,
                local_evidence_content=identity_evidence_content,
                local_evidence_filename=identity_evidence_filename,
                progress_callback=progress_callback,
            )
            if progress_callback is not None:
                progress_callback("URL verification and identity enrichment", "running")
            try:
                identity_result: IdentityIntelligenceResult = self.identity_service.investigate(request, deduplicated)
                identity_attributes = identity_result.attributes
                deduplicated_identity_attributes = identity_result.deduplicated_attributes
                identity_correlations = identity_result.correlations
                threat_indicators = identity_result.threat_indicators
                identity_diagnostics = identity_result.diagnostics
                profile_url_audits = identity_result.profile_url_audits
                url_verification_results = identity_result.url_verification_results
                if progress_callback is not None:
                    progress_callback("Threat analysis", "completed")
            except Exception as exc:  # Identity sources must not disrupt profile results.
                now = datetime.now(timezone.utc)
                identity_diagnostics = (IdentityDiagnostic(
                    "identity_service", f"identity processing failed: {exc}", DiagnosticLevel.ERROR,
                ),)
                threat_indicators = analyze_threats((), deduplicated, diagnostics=identity_diagnostics)
                profile_url_audits = tuple(ProfileURLCollectionAudit(
                    finding.username, finding.platform, finding.profile_url,
                    finding.source_tools, False, ProfileURLCollectionStatus.FAILED, now,
                    error_or_warning=str(exc), reason_skipped="identity service failed before URL processing",
                    canonical_profile_url=canonical_profile_url(finding.profile_url),
                ) for finding in deduplicated)
                url_verification_results = tuple(URLVerificationResult(
                    finding.username, finding.platform, finding.profile_url, None,
                    finding.source_tools, URLVerificationStatus.ERROR, None, None, (), False,
                    now, finding.source_lineage, f"Identity/verification stage failed: {exc}",
                ) for finding in deduplicated)
                if progress_callback is not None:
                    progress_callback("URL verification and identity enrichment", "failed; profile findings were retained")
        else:
            threat_indicators = analyze_threats((), deduplicated)
            now = datetime.now(timezone.utc)
            profile_url_audits = tuple(ProfileURLCollectionAudit(
                finding.username, finding.platform, _original_profile_urls(finding, summaries)[0],
                finding.source_tools, False, ProfileURLCollectionStatus.DISCOVERED, now,
                reason_skipped="identity collection was disabled for this investigation",
                canonical_profile_url=canonical_profile_url(finding.profile_url),
                original_profile_urls=_original_profile_urls(finding, summaries),
            ) for finding in deduplicated)
            url_verification_results = tuple(URLVerificationResult(
                finding.username, finding.platform, finding.profile_url, None,
                finding.source_tools, URLVerificationStatus.SKIPPED, None, None, (), False,
                now, finding.source_lineage, "Public-page verification is opt-in and was disabled for this investigation.",
            ) for finding in deduplicated)
            if public_urls or identity_evidence_content is not None:
                identity_diagnostics = (IdentityDiagnostic(
                    "identity_service", "identity collection is disabled; supplied identity sources were not accessed",
                    DiagnosticLevel.INFO,
                ),)

        attack_surface = assess_attack_surface(
            deduplicated, url_verification_results, identity_attributes,
            identity_correlations, threat_indicators,
        )
        if progress_callback is not None:
            progress_callback("Attack surface assessment", "completed; no numeric compromise score is generated")

        return InvestigationResult(
            username=username,
            collector_summaries=tuple(summaries),
            normalized_findings=tuple(normalized),
            deduplicated_findings=tuple(deduplicated),
            correlation_results=tuple(correlations),
            assessments=tuple(assessments),
            warnings=tuple(warnings),
            errors=tuple(errors),
            investigated_at=investigated_at,
            identity_collection_enabled=enable_identity_collection,
            identity_attributes=identity_attributes,
            deduplicated_identity_attributes=deduplicated_identity_attributes,
            identity_correlations=identity_correlations,
            threat_indicators=threat_indicators,
            identity_diagnostics=identity_diagnostics,
            profile_url_audits=profile_url_audits,
            url_verification_results=url_verification_results,
            attack_surface=attack_surface,
        )


def _is_timeout_exception(exc: Exception) -> bool:
    """Recognize subprocess timeout exceptions without leaking collector APIs."""
    from subprocess import TimeoutExpired

    return isinstance(exc, TimeoutExpired) or "timeout" in type(exc).__name__.casefold()


def _text_or_empty(value: object) -> str:
    return value if isinstance(value, str) else ""


def _original_profile_urls(finding: Finding, summaries: Sequence[CollectorExecutionSummary]) -> tuple[str, ...]:
    """Recover untrimmed original profile URL cells associated with a Finding."""
    canonical = canonical_profile_url(finding.profile_url)
    tools = {item.casefold() for item in finding.source_tools}
    originals: list[str] = []
    for summary in summaries:
        if summary.collector_name.casefold() not in tools:
            continue
        for record in summary.raw_records:
            values = {key.strip().casefold(): value or "" for key, value in record.as_mapping().items()}
            raw_url = values.get("url_user", "")
            if not raw_url.strip():
                continue
            if values.get("username", "").strip() != finding.username:
                continue
            if values.get("name", "").strip() != finding.platform:
                continue
            try:
                if canonical_profile_url(raw_url.strip()) == canonical:
                    originals.append(raw_url)
            except ValueError:
                continue
    return tuple(dict.fromkeys(originals)) or (finding.profile_url,)


__all__ = ["CollectorExecutionSummary", "InvestigationResult", "InvestigationService"]
