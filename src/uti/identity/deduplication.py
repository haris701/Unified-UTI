"""Evidence-preserving exact-value identity attribute deduplication."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from uti.identity.models import IdentityAttribute, IdentityAttributeType


@dataclass(frozen=True, slots=True)
class DeduplicatedIdentityAttribute:
    """One exact normalized attribute with every observation retained."""

    attribute_type: IdentityAttributeType
    normalized_value: str
    observations: tuple[IdentityAttribute, ...]


def deduplicate_identity_attributes(attributes: Iterable[IdentityAttribute]) -> tuple[DeduplicatedIdentityAttribute, ...]:
    """Group exact normalized values without merging people or dropping sources."""
    groups: dict[tuple[IdentityAttributeType, str], list[IdentityAttribute]] = {}
    for item in attributes:
        if not isinstance(item, IdentityAttribute):
            raise TypeError("attributes must contain IdentityAttribute values")
        groups.setdefault((item.attribute_type, item.normalized_value), []).append(item)
    return tuple(
        DeduplicatedIdentityAttribute(kind, value, tuple(observations))
        for (kind, value), observations in groups.items()
    )

