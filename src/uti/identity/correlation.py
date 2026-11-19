"""Candidate identity-attribute correlations with explicit source independence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from uti.identity.deduplication import DeduplicatedIdentityAttribute
from uti.identity.models import AssociationStatus, IdentityAttribute, IdentityAttributeType
from uti.models import EvidenceIndependence, EvidenceProvenance, SourceLineage
from uti.correlation.engine import classify_source_independence
from uti.utils.urls import canonical_profile_url


@dataclass(frozen=True, slots=True)
class IdentityCorrelation:
    """A candidate match between observations, never an identity assertion."""

    attribute_type: IdentityAttributeType
    normalized_value: str
    observations: tuple[IdentityAttribute, ...]
    source_lineage: tuple[SourceLineage, ...]
    supporting_evidence: tuple[EvidenceProvenance, ...]
    source_independence: EvidenceIndependence
    association_status: AssociationStatus
    reason: str
    interpretation: str = "matching public attribute only; account ownership and identity are not verified"


def correlate_identity_attributes(
    attributes: Iterable[DeduplicatedIdentityAttribute],
) -> tuple[IdentityCorrelation, ...]:
    """Report repeated exact attributes across distinct source observations."""
    correlations: list[IdentityCorrelation] = []
    for group in attributes:
        observations = group.observations
        signatures = {(item.source_tool.casefold(), (item.source_url or "").casefold()) for item in observations}
        if len(signatures) < 2:
            continue
        lineages = tuple(dict.fromkeys(lineage for item in observations for lineage in item.source_lineage))
        provenance = tuple(item for observation in observations for item in observation.evidence_provenance)
        source_urls = {canonical_profile_url(item.source_url) for item in observations if item.source_url}
        if len(source_urls) == 1 and all(item.source_url for item in observations):
            # The identical page was observed twice; do not count tools as
            # independent evidence when they share the same response source.
            independence = EvidenceIndependence.DEPENDENT
        else:
            independence = classify_source_independence(lineages)
        if independence is EvidenceIndependence.INDEPENDENT:
            reason = "exact normalized attribute repeated across explicitly distinct declared data sources; candidate corroboration only"
        elif independence is EvidenceIndependence.DEPENDENT:
            reason = "exact normalized attribute repeated across observations with a shared declared data source"
        else:
            reason = "exact normalized attribute repeated, but source independence is unknown"
        correlations.append(IdentityCorrelation(
            attribute_type=group.attribute_type,
            normalized_value=group.normalized_value,
            observations=observations,
            source_lineage=lineages,
            supporting_evidence=provenance,
            source_independence=independence,
            association_status=AssociationStatus.POTENTIAL_ASSOCIATION,
            reason=reason,
        ))
    return tuple(correlations)

