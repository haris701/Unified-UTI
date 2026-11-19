"""Normalize common collector result shapes into :class:`uti.models.Finding`."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import math
from typing import Any

from uti.models import EvidenceProvenance, Finding, SourceLineage, ValidationStatus


_ALIASES = {
    "username": ("username", "queried_username", "account"),
    "platform": ("platform", "site", "service"),
    "profile_url": ("profile_url", "url", "link"),
    "source_tool": ("source_tool", "source", "tool"),
}


def _first(raw: Mapping[str, Any], field: str, *, default: Any = None) -> Any:
    for key in _ALIASES[field]:
        if raw.get(key) is not None:
            return raw[key]
    return default


def _lineage(raw: Mapping[str, Any], collector_name: str) -> SourceLineage:
    declared = raw.get("source_lineage")
    if isinstance(declared, SourceLineage):
        return declared
    if declared is not None and not isinstance(declared, Mapping):
        raise ValueError("source_lineage must be a mapping or SourceLineage")
    values = {**raw, **declared} if isinstance(declared, Mapping) else raw
    collector = values.get("collector_name", values.get("source_tool", collector_name))
    if collector is None:
        collector = collector_name
    dataset = values.get(
        "underlying_data_source",
        values.get("source_dataset", values.get("data_source", values.get("dataset"))),
    )
    method = values.get("collection_method", values.get("method"))
    try:
        return SourceLineage(
            collector_name=collector,
            underlying_data_source=dataset,
            collection_method=method,
        )
    except ValueError as exc:
        raise ValueError(f"invalid source_lineage: {exc}") from exc


def _evidence_items(
    value: Any,
    *,
    default_type: str,
    default_source_url: str | None,
    default_lineage: SourceLineage,
) -> tuple[tuple[str, ...], tuple[EvidenceProvenance, ...]]:
    if value is None:
        return (), ()

    entries: list[Any]
    if isinstance(value, str):
        entries = [value]
    elif isinstance(value, Mapping):
        if "value" in value or "content" in value:
            entries = [value]
        else:
            if any(
                not isinstance(key, str)
                or not key.strip()
                or not isinstance(item, (str, int, float, bool))
                or (isinstance(item, float) and not math.isfinite(item))
                for key, item in value.items()
            ):
                raise ValueError("evidence mappings must contain string keys and scalar values")
            entries = [{"value": f"{key}: {item}", "evidence_type": key} for key, item in value.items()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        entries = list(value)
    else:
        raise ValueError("evidence must be a string, sequence, or mapping")

    provenance: list[EvidenceProvenance] = []
    for entry in entries:
        if isinstance(entry, str):
            evidence_value, entry_values = entry, {}
        elif isinstance(entry, Mapping):
            evidence_value = entry.get("value", entry.get("content"))
            if not isinstance(evidence_value, str):
                raise ValueError("structured evidence entries require a string value")
            entry_values = entry
        else:
            raise ValueError("evidence sequences must contain strings or structured mappings")

        evidence_type = entry_values.get("evidence_type", entry_values.get("type", default_type))
        if evidence_type is None:
            evidence_type = default_type
        source_url = entry_values.get(
            "original_source_url",
            entry_values.get("source_url", entry_values.get("url", default_source_url)),
        )
        entry_lineage = default_lineage
        if entry_values.get("source_lineage") is not None:
            entry_lineage = _lineage(entry_values, default_lineage.collector_name)
        try:
            provenance.append(
                EvidenceProvenance(
                    value=evidence_value,
                    evidence_type=evidence_type,
                    source_lineage=entry_lineage,
                    original_source_url=source_url,
                )
            )
        except ValueError as exc:
            raise ValueError(f"invalid evidence provenance: {exc}") from exc

    values = tuple(dict.fromkeys(item.value for item in provenance))
    return values, tuple(provenance)


def _timestamp(value: Any, fallback: datetime | None) -> datetime:
    if value is None:
        value = fallback
    if value is None:
        raise ValueError("missing required field: collected_at (or pass an explicit fallback)")
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("collected_at must be an ISO-8601 timestamp") from exc
    if not isinstance(value, datetime):
        raise ValueError("collected_at must be a datetime or ISO-8601 string")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collected_at must include a timezone")
    return value.astimezone(timezone.utc)


def normalize_finding(
    raw: Mapping[str, Any],
    *,
    source_tool: str | None = None,
    collected_at: datetime | None = None,
) -> Finding:
    """Convert a source-specific mapping into a validated ``Finding``.

    Recognizes common aliases such as ``site``/``platform`` and
    ``url``/``profile_url``. Missing required fields and invalid values raise
    ``ValueError`` with a field-oriented message.
    """
    if not isinstance(raw, Mapping):
        raise ValueError("raw finding must be a mapping")

    required: dict[str, str] = {}
    for name in ("username", "platform", "profile_url"):
        value = _first(raw, name)
        if value is None or not str(value).strip():
            raise ValueError(f"missing required field: {name}")
        required[name] = str(value).strip()

    tool = source_tool or _first(raw, "source_tool")
    if tool is None or not str(tool).strip():
        raise ValueError("missing required field: source_tool")
    lineage = _lineage(raw, str(tool).strip())

    status_value = raw.get("validation_status", raw.get("status", "unverified"))
    status_aliases = {"found": "valid", "available": "valid", "not_found": "invalid", "unknown": "unverified"}
    status_text = status_value.value if isinstance(status_value, ValidationStatus) else str(status_value).strip().lower()
    try:
        status = ValidationStatus(status_aliases.get(status_text, status_text))
    except ValueError as exc:
        raise ValueError(f"unsupported validation status: {status_value}") from exc

    confidence_value = raw.get("confidence")
    try:
        confidence = None if confidence_value is None else float(confidence_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence must be numeric") from exc

    confidence_reasons = raw.get("confidence_reasons", ())
    if isinstance(confidence_reasons, str):
        confidence_reasons = (confidence_reasons,)
    if not isinstance(confidence_reasons, Sequence) or isinstance(confidence_reasons, (bytes, bytearray)) or any(
        not isinstance(reason, str) for reason in confidence_reasons
    ):
        raise ValueError("confidence_reasons must be a string or a sequence of strings")

    evidence, evidence_provenance = _evidence_items(
        raw.get("evidence"),
        default_type=raw.get("evidence_type") or "unknown",
        default_source_url=raw.get("original_source_url", raw.get("evidence_url", raw.get("source_url"))),
        default_lineage=lineage,
    )

    return Finding(
        username=required["username"],
        platform=required["platform"],
        profile_url=required["profile_url"],
        source_tool=str(tool).strip(),
        evidence=evidence,
        collected_at=_timestamp(raw.get("collected_at"), collected_at),
        validation_status=status,
        confidence=confidence,
        confidence_reasons=tuple(confidence_reasons),
        source_lineage=(lineage,),
        evidence_provenance=evidence_provenance,
    )
