"""Pure data adapters for dashboard tables and summaries."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from uti.identity.attack_surface import AttackSurfaceAssessment
from uti.identity.url_verification import URLVerificationResult


def url_verification_rows(results: Iterable[URLVerificationResult]) -> list[dict[str, Any]]:
    """Format verification records for display without changing their meaning."""
    return [{
        "Username": item.username,
        "Platform": item.platform,
        "Original URL": item.original_url,
        "Final URL": item.final_url or "-",
        "Discovered by": ", ".join(item.discovering_collectors),
        "Status": item.status.value.upper(),
        "HTTP": item.http_status if item.http_status is not None else "-",
        "Profile-specific evidence": item.profile_specific,
        "Page title": item.page_title or "-",
        "Page metadata": " | ".join(f"{key}={value}" for key, value in item.page_metadata) or "-",
        "Checked (UTC)": item.verified_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Reason": item.reason,
    } for item in results]


def attack_surface_category_rows(assessment: AttackSurfaceAssessment) -> list[dict[str, Any]]:
    """Return readable category labels and distinct evidence counts."""
    if not isinstance(assessment, AttackSurfaceAssessment):
        raise TypeError("assessment must be an AttackSurfaceAssessment")
    return [
        {"Category": name.replace("_", " ").title(), "Distinct evidence values": count}
        for name, count in assessment.category_summaries
    ]


__all__ = ["attack_surface_category_rows", "url_verification_rows"]
