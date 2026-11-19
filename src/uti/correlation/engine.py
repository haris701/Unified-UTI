"""Explainable candidate grouping with explicit evidence lineage."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from uti.models import EvidenceIndependence, EvidenceProvenance, Finding, SourceLineage
from uti.utils.urls import canonical_profile_url


@dataclass(frozen=True, slots=True)
class EvidenceMatch:
    """An evidence value seen in more than one finding, with lineage status."""

    value: str
    evidence_type: str
    independence: EvidenceIndependence
    source_lineage: tuple[SourceLineage, ...]

    @property
    def repeated(self) -> bool:
        """Whether this is a repeat/shared observation, not independent support."""
        return self.independence is not EvidenceIndependence.INDEPENDENT


@dataclass(frozen=True, slots=True)
class CorrelationGroup:
    """A candidate association; membership never verifies real-world identity."""

    findings: tuple[Finding, ...]
    same_profile_candidate: bool
    shared_evidence: tuple[EvidenceMatch, ...]
    interpretation: str = "candidate correlation only; identity is not verified"

    @property
    def independently_corroborated_evidence(self) -> tuple[EvidenceMatch, ...]:
        """Evidence matches whose explicitly declared datasets differ."""
        return tuple(item for item in self.shared_evidence if item.independence is EvidenceIndependence.INDEPENDENT)

    @property
    def repeated_evidence(self) -> tuple[EvidenceMatch, ...]:
        """Evidence repeats that are dependent or whose lineage is unknown."""
        return tuple(item for item in self.shared_evidence if item.repeated)

    @property
    def reasons(self) -> tuple[str, ...]:
        """Compatibility view of the explicit profile/evidence match details."""
        reasons: list[str] = []
        if self.same_profile_candidate:
            reasons.append("same canonical profile URL (candidate; identity is not verified)")
        for item in self.shared_evidence:
            if item.independence is EvidenceIndependence.INDEPENDENT:
                label = "independently corroborated evidence"
            elif item.independence is EvidenceIndependence.DEPENDENT:
                label = "repeated evidence from a known shared source"
            else:
                label = "shared evidence with unknown source independence"
            reasons.append(f"{label}: {item.evidence_type}={item.value}")
        return tuple(reasons)


def correlate_findings(findings: Iterable[Finding]) -> list[CorrelationGroup]:
    """Group findings that may be related, without inferring verified identity.

    A group requires an exact, case-sensitive queried username and either a
    canonical profile URL match or a normalized value/type evidence match.
    Evidence is independent only when both sides declare distinct underlying
    datasets. Missing lineage remains unknown.
    """
    items = list(findings)
    if any(not isinstance(item, Finding) for item in items):
        raise TypeError("findings must contain only Finding instances")

    adjacency: list[set[int]] = [set() for _ in items]
    edges: dict[tuple[int, int], tuple[bool, tuple[EvidenceMatch, ...]]] = {}
    for left in range(len(items)):
        for right in range(left + 1, len(items)):
            first, second = items[left], items[right]
            if first.username != second.username:
                continue
            same_profile = canonical_profile_url(first.profile_url) == canonical_profile_url(second.profile_url)
            shared = _shared_evidence(first.evidence_provenance, second.evidence_provenance)
            if same_profile or shared:
                adjacency[left].add(right)
                adjacency[right].add(left)
                edges[(left, right)] = (same_profile, shared)

    groups: list[CorrelationGroup] = []
    visited: set[int] = set()
    for start in range(len(items)):
        if start in visited or not adjacency[start]:
            continue
        stack, component = [start], set()
        while stack:
            node = stack.pop()
            if node in component:
                continue
            component.add(node)
            stack.extend(adjacency[node] - component)

        same_profile = False
        shared_matches: dict[tuple[str, str], EvidenceMatch] = {}
        for (left, right), (profile_match, matches) in edges.items():
            if left in component and right in component:
                same_profile = same_profile or profile_match
                for match in matches:
                    key = (match.evidence_type.casefold(), _normalize(match.value))
                    existing = shared_matches.get(key)
                    if existing is None:
                        shared_matches[key] = match
                    else:
                        shared_matches[key] = EvidenceMatch(
                            match.value,
                            match.evidence_type,
                            _combine_status(existing.independence, match.independence),
                            tuple(dict.fromkeys(existing.source_lineage + match.source_lineage)),
                        )
        visited.update(component)
        groups.append(
            CorrelationGroup(
                findings=tuple(items[index] for index in sorted(component)),
                same_profile_candidate=same_profile,
                shared_evidence=tuple(shared_matches.values()),
            )
        )
    return groups


def classify_source_independence(lineages: Iterable[SourceLineage]) -> EvidenceIndependence:
    """Classify multiple declared source lineages without inferring origin.

    Fewer than two observations, missing underlying-source identifiers, or an
    empty input remain unknown. Multiple known source identifiers are
    independent; repeated observations from one known source are dependent.
    """
    items = tuple(lineages)
    if any(not isinstance(item, SourceLineage) for item in items):
        raise TypeError("lineages must contain only SourceLineage instances")
    if len(items) < 2 or any(item.underlying_data_source is None for item in items):
        return EvidenceIndependence.UNKNOWN
    sources = {item.underlying_data_source.casefold() for item in items if item.underlying_data_source is not None}
    if len(sources) > 1:
        return EvidenceIndependence.INDEPENDENT
    return EvidenceIndependence.DEPENDENT


def _shared_evidence(first: tuple[EvidenceProvenance, ...], second: tuple[EvidenceProvenance, ...]) -> tuple[EvidenceMatch, ...]:
    first_map: dict[tuple[str, str], list[EvidenceProvenance]] = {}
    second_map: dict[tuple[str, str], list[EvidenceProvenance]] = {}
    for evidence in first:
        first_map.setdefault((evidence.evidence_type.casefold(), _normalize(evidence.value)), []).append(evidence)
    for evidence in second:
        second_map.setdefault((evidence.evidence_type.casefold(), _normalize(evidence.value)), []).append(evidence)

    matches: list[EvidenceMatch] = []
    for key in first_map.keys() & second_map.keys():
        left_items, right_items = first_map[key], second_map[key]
        lineages = tuple(dict.fromkeys(item.source_lineage for item in left_items + right_items))
        matches.append(
            EvidenceMatch(
                value=left_items[0].value,
                evidence_type=left_items[0].evidence_type,
                independence=_independence(left_items, right_items),
                source_lineage=lineages,
            )
        )
    return tuple(matches)


def _independence(first: list[EvidenceProvenance], second: list[EvidenceProvenance]) -> EvidenceIndependence:
    if any(
        item.source_lineage.underlying_data_source is None
        for item in first + second
    ):
        return EvidenceIndependence.UNKNOWN
    first_sources = {
        item.source_lineage.underlying_data_source.casefold()
        for item in first
        if item.source_lineage.underlying_data_source is not None
    }
    second_sources = {
        item.source_lineage.underlying_data_source.casefold()
        for item in second
        if item.source_lineage.underlying_data_source is not None
    }
    if any(left != right for left in first_sources for right in second_sources):
        return EvidenceIndependence.INDEPENDENT
    if not first_sources or not second_sources:
        return EvidenceIndependence.UNKNOWN
    return EvidenceIndependence.DEPENDENT


def _combine_status(first: EvidenceIndependence, second: EvidenceIndependence) -> EvidenceIndependence:
    if EvidenceIndependence.UNKNOWN in (first, second):
        return EvidenceIndependence.UNKNOWN
    if EvidenceIndependence.INDEPENDENT in (first, second):
        return EvidenceIndependence.INDEPENDENT
    return EvidenceIndependence.DEPENDENT


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())
