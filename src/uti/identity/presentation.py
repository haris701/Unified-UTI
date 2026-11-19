"""Profile-centric views that keep each attribute attached to its source URL."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from uti.identity.models import IdentityAttribute, ProfileURLCollectionAudit
from uti.models import Finding
from uti.utils.urls import canonical_profile_url


@dataclass(frozen=True, slots=True)
class ProfileIntelligenceRecord:
    """One discovered profile and only attributes observed at that exact URL."""

    finding: Finding
    attributes: tuple[IdentityAttribute, ...]
    collection_audit: ProfileURLCollectionAudit | None


def build_profile_intelligence(
    findings: Iterable[Finding],
    attributes: Iterable[IdentityAttribute],
    audits: Iterable[ProfileURLCollectionAudit],
) -> tuple[ProfileIntelligenceRecord, ...]:
    """Join evidence by canonical source URL, never by username or attribute value."""
    attributes_by_url: dict[str, list[IdentityAttribute]] = {}
    for attribute in attributes:
        if attribute.source_url is None:
            continue
        try:
            key = canonical_profile_url(attribute.source_url)
        except ValueError:
            continue
        attributes_by_url.setdefault(key, []).append(attribute)

    audits_by_url = {}
    for audit in audits:
        url = audit.canonical_profile_url
        if url is None:
            try:
                url = canonical_profile_url(audit.original_profile_url)
            except ValueError:
                continue
        audits_by_url[url] = audit

    records = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        canonical = canonical_profile_url(finding.profile_url)
        key = (finding.username, canonical)
        if key in seen:
            continue
        seen.add(key)
        records.append(ProfileIntelligenceRecord(
            finding=finding,
            attributes=tuple(attributes_by_url.get(canonical, ())),
            collection_audit=audits_by_url.get(canonical),
        ))
    return tuple(records)


__all__ = ["ProfileIntelligenceRecord", "build_profile_intelligence"]
