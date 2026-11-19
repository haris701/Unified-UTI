"""Finding assessments and legacy score compatibility API."""

from uti.scoring.assessments import (
    CompletenessState,
    FieldCompleteness,
    FindingAssessment,
    ProfileCheckOutcome,
    ProfileCheckOutcomeKind,
    RecordCompletenessAssessment,
    assess_finding,
    assess_profile_check,
    assess_record_completeness,
)
from uti.scoring.rules import score_finding, score_finding_legacy

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
    "score_finding",
    "score_finding_legacy",
]
