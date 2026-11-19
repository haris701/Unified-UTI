"""Legacy numeric scoring compatibility API.

New investigation results use non-numeric assessments from ``assessments``.
"""

from __future__ import annotations

from dataclasses import replace

from uti.models import Finding, ValidationStatus
from uti.utils.urls import canonical_profile_url


def score_finding(finding: Finding) -> Finding:
    """Legacy API: return a copy with the historical numeric heuristic.

    The value is uncalibrated, is not a probability, and does not express
    profile detection quality, evidence reliability, or identity. It remains
    available for existing callers only; new pipeline code must use the
    structured assessments and must not present this value as confidence.
    """
    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance")
    score = 0.0
    reasons: list[str] = []
    if finding.validation_status is ValidationStatus.VALID:
        score += 0.30
        reasons.append("collector reported a positive profile check (+0.30)")
    elif finding.validation_status is ValidationStatus.INVALID:
        reasons.append("collector reported a negative profile check (+0.00)")
    else:
        reasons.append("profile check is inconclusive (+0.00)")

    try:
        canonical_profile_url(finding.profile_url)
    except ValueError:
        reasons.append("profile URL could not be canonicalized (+0.00)")
    else:
        score += 0.20
        reasons.append("absolute HTTP(S) profile URL is present (+0.20)")

    if finding.username and finding.platform and finding.source_tool:
        score += 0.20
        reasons.append("username, platform, and source are present (+0.20)")

    if finding.evidence:
        score += 0.10
        reasons.append("one or more evidence items are present (+0.10)")
    else:
        reasons.append("no evidence items are present (+0.00)")

    data_sources = {
        item.source_lineage.underlying_data_source.casefold()
        for item in finding.evidence_provenance
        if item.source_lineage.underlying_data_source is not None
    }
    lineage_unknown = not finding.evidence_provenance or any(
        item.source_lineage.underlying_data_source is None
        for item in finding.evidence_provenance
    )
    if lineage_unknown:
        reasons.append("source independence is unknown; no independence bonus (+0.00)")
    elif len(data_sources) >= 2:
        score += 0.10
        reasons.append("at least two explicitly distinct underlying data sources (+0.10)")
    else:
        reasons.append("lineage shows no distinct underlying sources; no independence bonus (+0.00)")

    score = min(score, 1.0)
    return replace(finding, confidence=round(score, 2), confidence_reasons=tuple(reasons))


# Explicitly named compatibility alias for consumers migrating old score use.
score_finding_legacy = score_finding
