"""Identity intelligence models, collectors, correlation, and analysis."""

from uti.identity.analysis import ThreatIndicator, ThreatIndicatorType, ThreatSeverity, analyze_threats
from uti.identity.attack_surface import AttackSurfaceAssessment, assess_attack_surface
from uti.identity.correlation import IdentityCorrelation, correlate_identity_attributes
from uti.identity.deduplication import DeduplicatedIdentityAttribute, deduplicate_identity_attributes
from uti.identity.models import (
    AssociationStatus,
    IdentityAttribute,
    IdentityAttributeType,
    IdentityDiagnostic,
    ProfileURLCollectionAudit,
    ProfileURLCollectionStatus,
    Sensitivity,
    VerificationStatus,
)
from uti.identity.normalization import normalize_identity_attribute
from uti.identity.presentation import ProfileIntelligenceRecord, build_profile_intelligence
from uti.identity.service import IdentityIntelligenceResult, IdentityIntelligenceService
from uti.identity.url_verification import URLVerificationResult, URLVerificationService, URLVerificationStatus

__all__ = [
    "AssociationStatus", "AttackSurfaceAssessment", "DeduplicatedIdentityAttribute", "IdentityAttribute",
    "IdentityAttributeType", "IdentityCorrelation", "IdentityDiagnostic",
    "IdentityIntelligenceResult", "IdentityIntelligenceService",
    "ProfileIntelligenceRecord", "ProfileURLCollectionAudit", "ProfileURLCollectionStatus",
    "Sensitivity", "ThreatIndicator", "ThreatIndicatorType", "ThreatSeverity",
    "URLVerificationResult", "URLVerificationService", "URLVerificationStatus",
    "VerificationStatus", "analyze_threats", "assess_attack_surface", "correlate_identity_attributes",
    "deduplicate_identity_attributes", "normalize_identity_attribute",
    "build_profile_intelligence",
]
