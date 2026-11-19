"""Shared data structures for normalized UTI findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import math

from uti.utils.urls import canonical_profile_url


class ValidationStatus(str, Enum):
    """A collector's profile-check outcome, not an ownership-verification result.

    ``VALID`` means only that the collector reported a positive detection for
    the profile URL under its own checks. It does not confirm current
    reachability, control of the account, or the identity of its owner.
    """

    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


# A clearer semantic name for new consumers; keep ValidationStatus as the
# existing public API so current callers and serialized values remain stable.
ProfileCheckStatus = ValidationStatus


class OwnershipVerificationStatus(str, Enum):
    """Ownership verification state supported by this research engine.

    No collector currently verifies ownership, so ``UNVERIFIED`` is the only
    representable state. A positive profile check cannot set ownership.
    """

    UNVERIFIED = "unverified"


class EvidenceIndependence(str, Enum):
    """What source lineage permits us to say about matching evidence."""

    INDEPENDENT = "independent"
    DEPENDENT = "dependent"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RawCollectorRecord:
    """One parsed CSV row retained before collector normalization.

    Values are decoded CSV cell contents in original column order; URLs are
    not trimmed or canonicalized here. ``extra_values`` preserves cells past
    the declared header for malformed rows when the CSV reader can parse them.
    """

    collector_name: str
    line_number: int
    headers: tuple[str, ...]
    values: tuple[str | None, ...]
    extra_values: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.collector_name, str) or not self.collector_name.strip():
            raise ValueError("collector_name must be a non-empty string")
        if isinstance(self.line_number, bool) or not isinstance(self.line_number, int) or self.line_number < 1:
            raise ValueError("line_number must be a positive integer")
        object.__setattr__(self, "collector_name", self.collector_name.strip())
        object.__setattr__(self, "headers", tuple(self.headers))
        object.__setattr__(self, "values", tuple(self.values))
        object.__setattr__(self, "extra_values", tuple(self.extra_values))

    def as_mapping(self) -> dict[str, str | None]:
        """Return header/value pairs without normalizing their contents."""
        return {header: self.values[index] if index < len(self.values) else None for index, header in enumerate(self.headers)}


@dataclass(frozen=True, slots=True)
class SourceLineage:
    """Provenance for one collector observation.

    ``underlying_data_source`` is an explicit identifier supplied by an
    adapter or researcher. Missing identifiers remain unknown; collector
    names alone do not establish source independence.
    """

    collector_name: str
    underlying_data_source: str | None = None
    collection_method: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.collector_name, str) or not self.collector_name.strip():
            raise ValueError("collector_name must be a non-empty string")
        object.__setattr__(self, "collector_name", self.collector_name.strip())
        for name in ("underlying_data_source", "collection_method"):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{name} must be a string or None")
                object.__setattr__(self, name, value.strip() or None)


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    """One evidence observation with its type, location, and source lineage."""

    value: str
    evidence_type: str
    source_lineage: SourceLineage
    original_source_url: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("evidence value must be a non-empty string")
        if not isinstance(self.evidence_type, str) or not self.evidence_type.strip():
            raise ValueError("evidence_type must be a non-empty string")
        if not isinstance(self.source_lineage, SourceLineage):
            raise ValueError("evidence source_lineage must be a SourceLineage")
        object.__setattr__(self, "value", self.value.strip())
        object.__setattr__(self, "evidence_type", self.evidence_type.strip())
        if self.original_source_url is not None:
            if not isinstance(self.original_source_url, str):
                raise ValueError("original_source_url must be a string or None")
            try:
                canonical_profile_url(self.original_source_url)
            except ValueError as exc:
                raise ValueError("original_source_url must be an absolute HTTP(S) URL") from exc
            object.__setattr__(self, "original_source_url", self.original_source_url.strip())


@dataclass(frozen=True, slots=True)
class Finding:
    """A normalized, source-attributed observation about a queried username.

    ``validation_status`` (also exposed as ``profile_check_status``) describes
    only the collector's profile check. Ownership remains unverified and is
    exposed separately; a positive check does not establish identity.

    ``confidence`` and ``confidence_reasons`` are retained for backward
    compatibility with older consumers. They hold the legacy, uncalibrated
    composite heuristic only; they are not profile quality, evidence
    reliability, probabilities, or identity confidence. New investigation
    results use structured assessments and do not calculate this value.
    """

    username: str
    platform: str
    profile_url: str
    source_tool: str
    collected_at: datetime
    evidence: tuple[str, ...] = ()
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    confidence: float | None = field(
        default=None,
        metadata={"legacy": True, "meaning": "uncalibrated legacy heuristic; not identity confidence"},
    )
    confidence_reasons: tuple[str, ...] = field(
        default=(), metadata={"legacy": True, "meaning": "explanation for legacy confidence only"}
    )
    source_tools: tuple[str, ...] = ()
    source_lineage: tuple[SourceLineage, ...] = ()
    evidence_provenance: tuple[EvidenceProvenance, ...] = ()
    ownership_status: OwnershipVerificationStatus = OwnershipVerificationStatus.UNVERIFIED

    def __post_init__(self) -> None:
        """Validate invariants and normalize immutable collection fields."""
        for name in ("username", "platform", "profile_url", "source_tool"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())

        try:
            canonical_profile_url(self.profile_url)
        except ValueError as exc:
            raise ValueError(f"invalid profile_url: {exc}") from exc

        if not isinstance(self.collected_at, datetime):
            raise ValueError("collected_at must be a datetime")
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must be timezone-aware")
        object.__setattr__(self, "collected_at", self.collected_at.astimezone(timezone.utc))

        if not isinstance(self.validation_status, ValidationStatus):
            try:
                object.__setattr__(self, "validation_status", ValidationStatus(self.validation_status))
            except (ValueError, TypeError) as exc:
                raise ValueError("validation_status must be a ValidationStatus value") from exc

        if not isinstance(self.ownership_status, OwnershipVerificationStatus):
            try:
                object.__setattr__(self, "ownership_status", OwnershipVerificationStatus(self.ownership_status))
            except (ValueError, TypeError) as exc:
                raise ValueError("ownership_status must remain unverified") from exc

        object.__setattr__(self, "evidence", _string_tuple(self.evidence, "evidence"))
        object.__setattr__(self, "confidence_reasons", _string_tuple(self.confidence_reasons, "confidence_reasons"))

        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("confidence must be a finite number between 0.0 and 1.0")
            if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
                raise ValueError("confidence must be a finite number between 0.0 and 1.0")
            if not self.confidence_reasons:
                raise ValueError("confidence_reasons are required when confidence is set")
        lineages = self.source_lineage or (SourceLineage(self.source_tool),)
        lineages = tuple(dict.fromkeys(_validated_tuple(lineages, SourceLineage, "source_lineage")))

        if self.evidence_provenance:
            provenance = _validated_tuple(self.evidence_provenance, EvidenceProvenance, "evidence_provenance")
        else:
            provenance = tuple(EvidenceProvenance(item, "unknown", lineages[0]) for item in self.evidence)
        lineages = tuple(dict.fromkeys(lineages + tuple(item.source_lineage for item in provenance)))
        object.__setattr__(self, "source_lineage", lineages)
        tools = (self.source_tool,) + tuple(self.source_tools) + tuple(item.collector_name for item in lineages)
        object.__setattr__(self, "source_tools", _string_tuple(tools, "source_tools", unique=True))
        object.__setattr__(self, "evidence_provenance", provenance)
        object.__setattr__(self, "evidence", tuple(dict.fromkeys(self.evidence + tuple(item.value for item in provenance))))

    @property
    def profile_check_status(self) -> ProfileCheckStatus:
        """Semantically explicit alias for the legacy validation status."""
        return self.validation_status

    @property
    def identity_verified(self) -> bool:
        """Whether ownership/identity was verified (always false in this engine)."""
        return False


def _string_tuple(values: object, field_name: str, *, unique: bool = False) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    try:
        items = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(f"{field_name} must be a string or an iterable of strings") from exc
    if any(not isinstance(item, str) for item in items):
        raise ValueError(f"{field_name} items must be strings")
    cleaned = tuple(item.strip() for item in items if item.strip())
    return tuple(dict.fromkeys(cleaned)) if unique else cleaned


def _validated_tuple(values: object, item_type: type, field_name: str) -> tuple:
    try:
        items = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise ValueError(f"{field_name} must be an iterable of {item_type.__name__} values") from exc
    if any(not isinstance(item, item_type) for item in items):
        raise ValueError(f"{field_name} must contain only {item_type.__name__} values")
    return items
