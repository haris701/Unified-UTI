"""Non-numeric, explainable assessments for findings and their records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from uti.correlation import classify_source_independence
from uti.models import (
    EvidenceIndependence,
    Finding,
    OwnershipVerificationStatus,
    ValidationStatus,
)


class ProfileCheckOutcomeKind(str, Enum):
    """Meaning of a collector's reported profile check."""

    POSITIVE = "positive"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class CompletenessState(str, Enum):
    """Whether a record field is present, absent, or explicitly unknown."""

    AVAILABLE = "available"
    MISSING = "missing"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProfileCheckOutcome:
    """A collector result with its origin and observation timestamp."""

    outcome: ProfileCheckOutcomeKind
    collector_name: str
    collected_at: datetime
    reported_status: ValidationStatus


@dataclass(frozen=True, slots=True)
class FieldCompleteness:
    """Completeness state for one named record field."""

    name: str
    state: CompletenessState


@dataclass(frozen=True, slots=True)
class RecordCompletenessAssessment:
    """Presence assessment for the Finding's requested provenance fields."""

    fields: tuple[FieldCompleteness, ...]

    def state_for(self, field_name: str) -> CompletenessState:
        """Get one field state by name, raising ``KeyError`` if unknown."""
        for item in self.fields:
            if item.name == field_name:
                return item.state
        raise KeyError(field_name)

    @property
    def available_fields(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.fields if item.state is CompletenessState.AVAILABLE)

    @property
    def missing_fields(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.fields if item.state is CompletenessState.MISSING)

    @property
    def unknown_fields(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.fields if item.state is CompletenessState.UNKNOWN)


@dataclass(frozen=True, slots=True)
class FindingAssessment:
    """Separate outcome, record completeness, and lineage for one finding."""

    finding: Finding
    profile_check_outcomes: tuple[ProfileCheckOutcome, ...]
    record_completeness: RecordCompletenessAssessment
    source_independence: EvidenceIndependence

    @property
    def ownership_status(self) -> OwnershipVerificationStatus:
        """Ownership remains unverified regardless of the profile check."""
        return OwnershipVerificationStatus.UNVERIFIED

    @property
    def identity_verified(self) -> bool:
        """Identity is not assessed or verified by this assessment."""
        return False


_OUTCOME_BY_STATUS = {
    ValidationStatus.VALID: ProfileCheckOutcomeKind.POSITIVE,
    ValidationStatus.INVALID: ProfileCheckOutcomeKind.NEGATIVE,
    ValidationStatus.UNVERIFIED: ProfileCheckOutcomeKind.INCONCLUSIVE,
    ValidationStatus.ERROR: ProfileCheckOutcomeKind.ERROR,
}


def assess_profile_check(finding: Finding) -> ProfileCheckOutcome:
    """Represent the collector status without consulting HTTP status text."""
    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance")
    return ProfileCheckOutcome(
        outcome=_OUTCOME_BY_STATUS[finding.profile_check_status],
        collector_name=finding.source_tool,
        collected_at=finding.collected_at,
        reported_status=finding.profile_check_status,
    )


def assess_record_completeness(finding: Finding) -> RecordCompletenessAssessment:
    """Describe field presence; this does not assess evidence reliability."""
    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance")

    has_evidence = bool(finding.evidence)
    provenance = finding.evidence_provenance
    if not has_evidence:
        evidence_type_state = CompletenessState.MISSING
        source_url_state = CompletenessState.MISSING
    elif not provenance:
        evidence_type_state = CompletenessState.UNKNOWN
        source_url_state = CompletenessState.UNKNOWN
    else:
        evidence_type_state = (
            CompletenessState.UNKNOWN
            if any(item.evidence_type.casefold() == "unknown" for item in provenance)
            else CompletenessState.AVAILABLE
        )
        source_url_state = (
            CompletenessState.AVAILABLE
            if all(item.original_source_url is not None for item in provenance)
            else CompletenessState.UNKNOWN
        )

    timestamp_state = (
        CompletenessState.AVAILABLE
        if finding.collected_at.tzinfo is not None and finding.collected_at.utcoffset() is not None
        else CompletenessState.UNKNOWN
    )
    lineage_state = CompletenessState.AVAILABLE if finding.source_lineage else CompletenessState.MISSING
    return RecordCompletenessAssessment(
        fields=(
            FieldCompleteness("evidence", CompletenessState.AVAILABLE if has_evidence else CompletenessState.MISSING),
            FieldCompleteness("evidence_type", evidence_type_state),
            FieldCompleteness("original_source_url", source_url_state),
            FieldCompleteness("collection_timestamp", timestamp_state),
            FieldCompleteness("source_lineage", lineage_state),
        )
    )


def assess_finding(finding: Finding) -> FindingAssessment:
    """Assess one finding without producing an aggregate or identity score."""
    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance")
    return FindingAssessment(
        finding=finding,
        profile_check_outcomes=(assess_profile_check(finding),),
        record_completeness=assess_record_completeness(finding),
        source_independence=classify_source_independence(
            item.source_lineage for item in finding.evidence_provenance
        ),
    )


__all__ = [
    "CompletenessState",
    "FieldCompleteness",
    "FindingAssessment",
    "ProfileCheckOutcome",
    "ProfileCheckOutcomeKind",
    "RecordCompletenessAssessment",
    "assess_finding",
    "assess_profile_check",
    "assess_record_completeness",
]
