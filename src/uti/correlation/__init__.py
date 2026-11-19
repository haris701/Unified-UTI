"""Evidence correlation API."""

from uti.correlation.engine import (
    CorrelationGroup,
    EvidenceMatch,
    classify_source_independence,
    correlate_findings,
)

__all__ = ["CorrelationGroup", "EvidenceMatch", "classify_source_independence", "correlate_findings"]
