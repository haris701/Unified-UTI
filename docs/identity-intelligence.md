# Identity intelligence

Identity intelligence is a separate, evidence-preserving layer for explicitly public or investigator-authorized attributes. It is disabled by default for each investigation.

## Supported inputs

1. **Discovered profiles**: when identity collection is enabled, positive profile candidates from Sherlock and Maigret are passed automatically through the URL verification stage and then to the public-page parser only when profile-specific content markers are present. Other discovery collector names are marked `UNSUPPORTED`. Strict HTTP(S), public DNS/IP, validated redirects, robots.txt, response size, DNS/request timeout and HTML content-type checks apply. The adapter does not execute JavaScript, follow links, or download arbitrary files.
2. **Investigator-supplied public URLs**: the service API retains optional direct URL input for advanced integrations, but the normal dashboard workflow no longer asks for URLs already discovered by Sherlock/Maigret.
3. **Local authorized CSV/JSON evidence**: upload schema supports `attribute_type` or `type`, and `value` or `original_value`, with optional `source_url`, evidence fields, timestamp, verification/association status, sensitivity, phone country context, and associated username. Invalid rows become diagnostics; the source file SHA-256 and row number are recorded in lineage. Inputs are size-limited.

There are no external APIs, breach lookups, private data sources, email/phone enumeration, or credential checks. API adapter integration is not implemented. Discovery support currently recognizes Sherlock and Maigret as collector sources; URL safety and robots checks still apply independently to every page.

## Configuration

No environment variables or API keys are used by the implemented identity sources. `PublicPageFetcher` can be injected with `timeout_seconds` (default 6), `max_response_bytes` (1,000,000), `max_urls` (50), and `min_interval_seconds` (1). The dashboard lets the operator set the per-investigation eligible profile-page cap from 1 to 5,000 (default 50). The cap counts unique, eligible pages that can actually be fetched; invalid URLs, unsupported sources, negative checks, and duplicate URLs do not consume it. When it is reached, remaining eligible URLs are shown as `SKIPPED` in the profile URL collection audit. Public-page checks run one at a time, so high limits can take a long time. The local import collector remains available through the Python API and defaults to a 2,000,000-byte file limit. Applications can configure these objects in Python and inject collector adapters through `IdentityIntelligenceService(collectors=[...])`. Passing an empty list disables identity sources; omitting `collectors` selects the built-in adapters. The dashboard exposes identity opt-in; discovered Sherlock/Maigret profiles are selected automatically when enabled.

## Attribute types and interpretation

The model supports display name, publicly stated name, email, phone, website, domain, social profile, bio, alias, explicitly linked secondary username, organization, job title, professional affiliation, technology, skill, coarse location, profile image URL, and other. The generic parser handles explicit profile markup, common profile metadata, JSON-LD Person/ProfilePage fields, `mailto:` and `tel:` links, visible public email addresses, explicitly linked `rel=me` websites, and exact technology terms present in profile evidence. URLs explicitly written into profile descriptions are retained as website observations. No external platform-specific identity parser is currently bundled. It does not infer missing fields or guarantee a page publishes extractable data. Original and normalized values are kept separately. Email domain casing is normalized without changing the local part. Phone formatting is preserved unless an explicit country calling code is supplied. Names and aliases only have whitespace normalized.

`SOURCE_REPORTED` means a source or supplied evidence stated the value. `FORMAT_VALID` means syntax/URL validation only. `INDEPENDENTLY_CORROBORATED` is available in the model but is not automatically assigned by a match. `UNVERIFIED`, `INVALID`, and `UNKNOWN` retain their literal meanings. None of these statuses verifies control or identity. Association can be explicit from the source, potential, unrelated, or unknown; a candidate association is not an identity verdict.

Every attribute retains source tool, source URL, UTC collection timestamp, evidence text/type, source lineage, provenance, and warnings. Missing underlying dataset lineage is unknown. Duplicate values retain every observation. Same-page observations are dependent; otherwise independence is only independent where existing provenance declares distinct underlying sources, and unknown in all other cases.

`ProfileURLCollectionAudit` records every discovered URL as `DISCOVERED`, `FETCHED`, `FAILED`, `SKIPPED`, or `UNSUPPORTED` (with `SELECTED` and `PARTIALLY_FETCHED` reserved for future adapters). It retains the original collector URL cells, canonical URL, discovery collector(s), attempted flag, HTTP status when known, timestamp, extracted count, and skip/error reason. `URLVerificationResult` separately captures original/final URL, HTTP status, title, bounded metadata, profile-specific marker, outcome, timestamp, provenance and explanation. A generic HTTP 200 is `INCONCLUSIVE`; only explicit profile-specific content can be `VERIFIED_ACCESSIBLE`, which still does not verify ownership. One safe response is used for verification and enrichment rather than fetched twice.

## Threat indicators

Implemented rules emit informational indicators for public identity/contact exposure, digital footprint, developer/technology disclosure, professional information, organization/domain associations, and collection quality diagnostics. Indicators include evidence, exact source profile URLs, related attributes/findings, severity rationale, recommendations, and limitations. Matching candidate URLs reported by multiple collectors are described as source overlap, not independent identity corroboration. No maliciousness or identity score is produced. Potential impersonation, profile inconsistency and source-reliability rules remain unimplemented because current evidence cannot justify them.

## API use

```python
from uti.services import InvestigationService

result = InvestigationService().investigate(
    "uti_demo_test_2026",
    enable_identity_collection=True,
)
```

The example invokes the default Sherlock and Maigret collectors, which make normal network requests. When enabled, eligible discovered profiles are also passed to the public-page collector. Use only an authorized synthetic or approved research account. Unit tests mock collectors and public HTTP interactions.
