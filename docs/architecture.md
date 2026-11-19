# Unified-UTI architecture

Unified-UTI separates username profile candidates from identity-related observations. Existing profile collection remains in `uti.collectors`; `uti.models.Finding` remains the canonical profile record. Identity observations use independent models in `uti.identity.models` so an email, display name, or URL is not implicitly promoted into a profile finding.

## Investigation flow

`uti.services.InvestigationService` runs Sherlock and Maigret independently, validates their Findings, deduplicates exact username/profile URL matches, runs candidate correlation, and creates structured profile and completeness assessments. Public page verification and identity enrichment are separately represented but share one explicitly opt-in safe retrieval to avoid duplicate requests. Identity processing accepts investigator-provided public URLs, eligible profile candidates, and authorized local CSV/JSON evidence. Identity results are exact-value deduplicated with all observations retained, correlated with source-independence labels, and passed to explainable threat indicators and investigation-level attack-surface summaries.

```text
Sherlock / Maigret -> Finding -> normalization -> deduplication -> profile correlation / assessment
                                                \
Opt-in profile URLs -> safe URL verification -> (same response) -> evidence enrichment
                                                                  -> identity attributes -> deduplication/correlation
                                                                  -> threat indicators -> attack surface summary
Authorized local evidence ---------------------------------------> identity attributes
```

## Modules

- `uti.identity.models`: identity attributes, verification/association states, diagnostics.
- `uti.identity.normalization`: type-specific conservative normalization retaining original values.
- `uti.identity.collectors.base`: collector protocol and per-collector failure isolation.
- `uti.identity.collectors.public_page`: bounded, opt-in HTML metadata and explicit contact-link extraction.
- `uti.identity.collectors.local_file`: authorized CSV/JSON import with row diagnostics and content hash lineage.
- `uti.identity.correlation`: candidate exact-value relationships; unknown lineage stays unknown.
- `uti.identity.analysis`: informational defensive exposure indicators; no maliciousness or identity score.
- `uti.identity.url_verification`: outcome classification for safe page responses; HTTP 200 alone is inconclusive and accessible profile markers do not establish ownership.
- `uti.identity.attack_surface`: investigation-level evidence counts and narrative; no numeric exposure score.
- `uti.reporting`: in-memory Excel workbooks using only the selected `InvestigationResult`.

No persistence layer, external identity API, breach database, or platform-specific identity parser/verifier is implemented. Generic explicit HTML and JSON-LD rules are used. Sherlock and Maigret continue to use their own packaged site databases; Unified-UTI does not maintain a parallel platform list.

Ownership remains `UNVERIFIED` and `identity_verified=False`. Source-reported attributes and candidate correlations do not prove that the subject controls an account or that two records refer to one person.
