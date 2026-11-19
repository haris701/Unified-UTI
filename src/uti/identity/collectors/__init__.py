"""Opt-in identity data collectors; no external API adapters are bundled."""

from uti.identity.collectors.base import (
    IdentityCollectionRequest,
    IdentityCollectionResult,
    IdentityCollector,
    IdentityCollectorService,
)
from uti.identity.collectors.local_file import LocalEvidenceIdentityCollector
from uti.identity.collectors.public_page import PublicPageIdentityCollector, PublicPageFetcher

__all__ = [
    "IdentityCollectionRequest", "IdentityCollectionResult", "IdentityCollector",
    "IdentityCollectorService", "LocalEvidenceIdentityCollector",
    "PublicPageFetcher", "PublicPageIdentityCollector",
]
