"""Duplicate-finding detection and evidence-preserving merging."""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Iterable

from uti.models import Finding, ValidationStatus
from uti.utils.urls import canonical_profile_url


_STATUS_RANK = {
    ValidationStatus.VALID: 3,
    ValidationStatus.UNVERIFIED: 2,
    ValidationStatus.ERROR: 1,
    ValidationStatus.INVALID: 0,
}


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge repeats for the same username and canonical profile URL.

    The output retains all distinct evidence and collector names. It remains
    one finding per username/URL pair; distinct URLs are never collapsed just
    because they share a username.
    """
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("findings must contain only Finding instances")
        # Username casing may be significant; without platform-specific rules,
        # preserve it to avoid merging distinct accounts.
        key = (finding.username, canonical_profile_url(finding.profile_url))
        current = merged.get(key)
        if current is None:
            merged[key] = finding
            continue

        winner = finding if _quality(finding) > _quality(current) else current
        merged[key] = replace(
            winner,
            evidence=tuple(dict.fromkeys(current.evidence + finding.evidence)),
            source_tools=tuple(dict.fromkeys(current.source_tools + finding.source_tools)),
            source_lineage=tuple(dict.fromkeys(current.source_lineage + finding.source_lineage)),
            evidence_provenance=current.evidence_provenance + finding.evidence_provenance,
            # Merging changes the record, so clear a stale legacy score.
            confidence=None,
            confidence_reasons=(),
        )
    return list(merged.values())


def _quality(finding: Finding) -> tuple[int, int]:
    return (
        _STATUS_RANK[finding.validation_status],
        len(finding.evidence),
    )


