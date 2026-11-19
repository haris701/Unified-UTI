"""Conservative normalization for identity attributes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import re
from typing import Any
from urllib.parse import urlsplit

from uti.models import EvidenceProvenance, SourceLineage
from uti.utils.urls import canonical_profile_url
from uti.identity.models import (
    AssociationStatus,
    IdentityAttribute,
    IdentityAttributeType,
    Sensitivity,
    VerificationStatus,
)


_EMAIL = re.compile(r"^[^\s@<>]+@[^\s@<>.]+(?:\.[^\s@<>.]+)+$")
_PHONE_CHARS = re.compile(r"^[+0-9().\s-]+$")
_WHITESPACE = re.compile(r"\s+")


def normalize_identity_attribute(
    raw: Mapping[str, Any],
    *,
    source_tool: str | None = None,
    collected_at: datetime | None = None,
) -> IdentityAttribute:
    """Validate a source mapping and retain both original and normalized values."""
    if not isinstance(raw, Mapping):
        raise ValueError("identity attribute must be a mapping")
    try:
        attribute_type = IdentityAttributeType(str(raw.get("attribute_type", raw.get("type", "other"))).strip().casefold())
    except ValueError as exc:
        raise ValueError("unsupported identity attribute_type") from exc
    original = raw.get("original_value", raw.get("value"))
    if not isinstance(original, str) or not original.strip():
        raise ValueError("identity attribute requires a non-empty value")
    original = original.strip()
    normalized, derived_verification = _normalize_value(attribute_type, original, raw.get("country_context"))

    tool = source_tool or raw.get("source_tool") or raw.get("collector_name")
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("identity attribute requires source_tool")
    source_url = raw.get("source_url", raw.get("original_source_url"))
    if source_url is not None and not isinstance(source_url, str):
        raise ValueError("source_url must be a string")
    lineage_raw = raw.get("source_lineage")
    if isinstance(lineage_raw, SourceLineage):
        lineages = (lineage_raw,)
    elif isinstance(lineage_raw, Mapping):
        lineages = (SourceLineage(
            collector_name=str(lineage_raw.get("collector_name", tool)),
            underlying_data_source=lineage_raw.get("underlying_data_source"),
            collection_method=lineage_raw.get("collection_method"),
        ),)
    elif lineage_raw is None:
        lineages = (SourceLineage(tool, raw.get("underlying_data_source"), raw.get("collection_method")),)
    else:
        lineages = tuple(lineage_raw)

    timestamp = _parse_timestamp(raw.get("collected_at"), collected_at)
    evidence = raw.get("evidence", f"{attribute_type.value} recorded by {tool}")
    if not isinstance(evidence, str) or not evidence.strip():
        raise ValueError("evidence must be a non-empty string")
    evidence_type = raw.get("evidence_type", f"{tool}_identity_observation")
    if not isinstance(evidence_type, str) or not evidence_type.strip():
        raise ValueError("evidence_type must be a non-empty string")
    try:
        verification = VerificationStatus(raw.get("verification_status", derived_verification.value))
        association = AssociationStatus(raw.get("association_status", "unknown"))
        sensitivity = Sensitivity(raw.get("sensitivity", _default_sensitivity(attribute_type).value))
    except ValueError as exc:
        raise ValueError(f"unsupported identity status: {exc}") from exc
    provenance_raw = raw.get("evidence_provenance")
    if provenance_raw is None:
        provenance = (EvidenceProvenance(evidence, evidence_type, lineages[0], source_url),)
    else:
        provenance = tuple(provenance_raw)
    return IdentityAttribute(
        attribute_type=attribute_type,
        original_value=original,
        normalized_value=normalized,
        source_tool=tool.strip(),
        source_url=source_url,
        collected_at=timestamp,
        evidence=evidence,
        evidence_type=evidence_type,
        source_lineage=lineages,
        evidence_provenance=provenance,
        verification_status=verification,
        association_status=association,
        sensitivity=sensitivity,
        warnings=tuple(raw.get("warnings", ())),
        associated_username=raw.get("associated_username"),
    )


def _normalize_value(attribute_type: IdentityAttributeType, value: str, country_context: Any) -> tuple[str, VerificationStatus]:
    if attribute_type is IdentityAttributeType.EMAIL:
        if not _EMAIL.fullmatch(value):
            raise ValueError("email has invalid syntax")
        local, domain = value.rsplit("@", 1)
        canonical_domain = urlsplit(canonical_profile_url(f"https://{domain}/")).hostname
        if not canonical_domain:
            raise ValueError("email domain is invalid")
        return f"{local}@{canonical_domain}", VerificationStatus.FORMAT_VALID
    if attribute_type in {IdentityAttributeType.WEBSITE, IdentityAttributeType.SOCIAL_PROFILE, IdentityAttributeType.PROFILE_IMAGE_URL}:
        return canonical_profile_url(value), VerificationStatus.FORMAT_VALID
    if attribute_type is IdentityAttributeType.DOMAIN:
        candidate = value.strip().rstrip(".")
        canonical = urlsplit(canonical_profile_url(f"https://{candidate}/")).hostname
        if not canonical:
            raise ValueError("domain is invalid")
        return canonical, VerificationStatus.FORMAT_VALID
    if attribute_type is IdentityAttributeType.PHONE:
        if not _PHONE_CHARS.fullmatch(value):
            raise ValueError("phone has unsupported characters")
        digits = re.sub(r"\D", "", value)
        if not digits:
            raise ValueError("phone has no digits")
        if country_context is None:
            # No country is inferred; punctuation and national formatting remain.
            return value, VerificationStatus.SOURCE_REPORTED
        if not isinstance(country_context, str) or not re.fullmatch(r"\+[1-9][0-9]{0,2}", country_context.strip()):
            raise ValueError("country_context must be an explicit calling code such as +1")
        normalized = f"+{digits}" if value.lstrip().startswith("+") else f"{country_context.strip()}{digits}"
        if not 8 <= len(normalized.lstrip("+")) <= 15:
            raise ValueError("phone length is outside the supported international range")
        return normalized, VerificationStatus.FORMAT_VALID
    if attribute_type in {IdentityAttributeType.DISPLAY_NAME, IdentityAttributeType.PUBLICLY_STATED_NAME}:
        normalized = _WHITESPACE.sub(" ", value).strip()
        return normalized, VerificationStatus.SOURCE_REPORTED
    if attribute_type is IdentityAttributeType.ALIAS:
        return _WHITESPACE.sub(" ", value).strip(), VerificationStatus.SOURCE_REPORTED
    if attribute_type is IdentityAttributeType.COARSE_LOCATION:
        return _WHITESPACE.sub(" ", value).strip(), VerificationStatus.SOURCE_REPORTED
    return _WHITESPACE.sub(" ", value).strip(), VerificationStatus.SOURCE_REPORTED


def _default_sensitivity(attribute_type: IdentityAttributeType) -> Sensitivity:
    if attribute_type in {IdentityAttributeType.EMAIL, IdentityAttributeType.PHONE, IdentityAttributeType.COARSE_LOCATION}:
        return Sensitivity.PUBLIC_PERSONAL
    return Sensitivity.PUBLIC


def _parse_timestamp(value: Any, fallback: datetime | None) -> datetime:
    if value is None:
        value = fallback or datetime.now(timezone.utc)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("collected_at must be an ISO-8601 timestamp") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collected_at must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)

