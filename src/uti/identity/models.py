"""Evidence-backed identity observations, kept separate from profile Findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from uti.models import EvidenceProvenance, SourceLineage
from uti.utils.urls import canonical_profile_url


class IdentityAttributeType(str, Enum):
    DISPLAY_NAME = "display_name"
    PUBLICLY_STATED_NAME = "publicly_stated_name"
    EMAIL = "email"
    PHONE = "phone"
    WEBSITE = "website"
    DOMAIN = "domain"
    SOCIAL_PROFILE = "social_profile"
    BIO = "bio"
    ALIAS = "alias"
    SECONDARY_USERNAME = "secondary_username"
    ORGANIZATION = "organization"
    JOB_TITLE = "job_title"
    PROFESSIONAL_AFFILIATION = "professional_affiliation"
    TECHNOLOGY = "technology"
    SKILL = "skill"
    COARSE_LOCATION = "coarse_location"
    PROFILE_IMAGE_URL = "profile_image_url"
    OTHER = "other"


class VerificationStatus(str, Enum):
    SOURCE_REPORTED = "source_reported"
    FORMAT_VALID = "format_valid"
    INDEPENDENTLY_CORROBORATED = "independently_corroborated"
    UNVERIFIED = "unverified"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class AssociationStatus(str, Enum):
    EXPLICITLY_ASSOCIATED_BY_SOURCE = "explicitly_associated_by_source"
    POTENTIAL_ASSOCIATION = "potential_association"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    PUBLIC_PERSONAL = "public_personal"
    UNKNOWN = "unknown"


class DiagnosticLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ProfileURLCollectionStatus(str, Enum):
    """Outcome of identity collection for a discovered profile URL."""

    DISCOVERED = "discovered"
    SELECTED = "selected"
    FETCHED = "fetched"
    PARTIALLY_FETCHED = "partially_fetched"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ProfileURLCollectionAudit:
    """Provenance and outcome for one candidate profile URL."""

    username: str
    platform: str
    original_profile_url: str
    discovery_collectors: tuple[str, ...]
    identity_collection_attempted: bool
    fetch_status: ProfileURLCollectionStatus
    collected_at: datetime
    extracted_attribute_count: int = 0
    canonical_profile_url: str | None = None
    http_status: int | None = None
    error_or_warning: str | None = None
    reason_skipped: str | None = None
    original_profile_urls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("username", "platform", "original_profile_url"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())
        if not isinstance(self.identity_collection_attempted, bool):
            raise ValueError("identity_collection_attempted must be a boolean")
        if not isinstance(self.fetch_status, ProfileURLCollectionStatus):
            object.__setattr__(self, "fetch_status", ProfileURLCollectionStatus(self.fetch_status))
        if not isinstance(self.collected_at, datetime) or self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must be timezone-aware")
        object.__setattr__(self, "collected_at", self.collected_at.astimezone(timezone.utc))
        if isinstance(self.extracted_attribute_count, bool) or not isinstance(self.extracted_attribute_count, int) or self.extracted_attribute_count < 0:
            raise ValueError("extracted_attribute_count must be a non-negative integer")
        if self.http_status is not None and (isinstance(self.http_status, bool) or not isinstance(self.http_status, int) or not 100 <= self.http_status <= 599):
            raise ValueError("http_status must be a valid HTTP status code or None")
        object.__setattr__(self, "discovery_collectors", tuple(dict.fromkeys(str(item).strip() for item in self.discovery_collectors if str(item).strip())))
        raw_urls = tuple(str(item) for item in self.original_profile_urls if str(item).strip())
        if not raw_urls:
            raw_urls = (self.original_profile_url,)
        object.__setattr__(self, "original_profile_urls", tuple(dict.fromkeys(raw_urls)))
        if self.canonical_profile_url is not None:
            canonical_profile_url(self.canonical_profile_url)


@dataclass(frozen=True, slots=True)
class IdentityAttribute:
    """One observation of an identity-related value and its source evidence.

    This model records what a source or investigator supplied. It does not
    represent a verified identity or prove that the value is controlled by a
    particular person.
    """

    attribute_type: IdentityAttributeType
    original_value: str
    normalized_value: str
    source_tool: str
    source_url: str | None
    collected_at: datetime
    evidence: str
    evidence_type: str
    source_lineage: tuple[SourceLineage, ...]
    evidence_provenance: tuple[EvidenceProvenance, ...]
    verification_status: VerificationStatus = VerificationStatus.SOURCE_REPORTED
    association_status: AssociationStatus = AssociationStatus.UNKNOWN
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    warnings: tuple[str, ...] = ()
    associated_username: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("original_value", "normalized_value", "source_tool", "evidence", "evidence_type"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            object.__setattr__(self, field_name, value.strip())
        for field_name, enum_type in (
            ("attribute_type", IdentityAttributeType),
            ("verification_status", VerificationStatus),
            ("association_status", AssociationStatus),
            ("sensitivity", Sensitivity),
        ):
            value = getattr(self, field_name)
            if not isinstance(value, enum_type):
                try:
                    object.__setattr__(self, field_name, enum_type(value))
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{field_name} has an unsupported value") from exc
        if not isinstance(self.collected_at, datetime) or self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must be timezone-aware")
        object.__setattr__(self, "collected_at", self.collected_at.astimezone(timezone.utc))
        if self.source_url is not None:
            if not isinstance(self.source_url, str):
                raise ValueError("source_url must be a string or None")
            canonical_profile_url(self.source_url.strip())
            object.__setattr__(self, "source_url", self.source_url.strip())
        if not self.source_lineage or any(not isinstance(item, SourceLineage) for item in self.source_lineage):
            raise ValueError("source_lineage must contain at least one SourceLineage")
        if any(not isinstance(item, EvidenceProvenance) for item in self.evidence_provenance):
            raise ValueError("evidence_provenance must contain EvidenceProvenance records")
        object.__setattr__(self, "source_lineage", tuple(dict.fromkeys(self.source_lineage)))
        object.__setattr__(self, "evidence_provenance", tuple(self.evidence_provenance))
        object.__setattr__(self, "warnings", tuple(str(item) for item in self.warnings))
        if self.associated_username is not None:
            if not isinstance(self.associated_username, str) or not self.associated_username.strip():
                raise ValueError("associated_username must be a non-empty string or None")
            object.__setattr__(self, "associated_username", self.associated_username.strip())


@dataclass(frozen=True, slots=True)
class IdentityDiagnostic:
    """Warning or error associated with an identity collector operation."""

    collector_name: str
    message: str
    level: DiagnosticLevel = DiagnosticLevel.WARNING
    source_url: str | None = None
    line_number: int | None = None
    details: str | None = None

    def __post_init__(self) -> None:
        if not self.collector_name.strip() or not self.message.strip():
            raise ValueError("collector_name and message must be non-empty")
        if not isinstance(self.level, DiagnosticLevel):
            object.__setattr__(self, "level", DiagnosticLevel(self.level))

