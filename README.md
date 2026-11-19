# Unified User Threat Intelligence (UTI)

Unified User Threat Intelligence (UTI) is a Python research project for collecting and organizing publicly available information associated with a supplied username. It combines isolated OSINT collectors, preserves evidence provenance, and provides a Streamlit investigation workspace.

## Project goals

- Provide a modular orchestration layer for multiple username-search sources.
- Normalize results into a common evidence format while retaining the original source and collection time.
- Deduplicate matching findings and correlate related evidence across sources.
- Present profile-check outcomes, record completeness, and source independence as separate assessments.
- Present findings and their provenance in a Streamlit dashboard.
- Support responsible, authorized research using public information and designated testing accounts.

## Planned sources

Potential sources include Sherlock, Maigret, Blackbird, and other suitable tools. Sherlock and Maigret adapters are implemented, but the external tools are not installed or run automatically by this project. Blackbird and other sources remain future integrations. Each source should be connected through an isolated collector adapter, with its requirements, usage limits, and output behavior documented before use.

## Proposed data flow

1. A user submits a username and an explicitly selected research scope.
2. The orchestration layer dispatches the query to enabled collectors.
3. Collectors return source-specific results and metadata.
4. Normalizers convert results into a shared evidence schema.
5. Correlation and deduplication group likely related findings without discarding source records.
6. Assessments report collector outcomes, record completeness, and source independence without combining them into a score.
7. Storage retains a research run and its evidence; reporting and the dashboard expose results.

A normalized finding records the queried username, platform, profile URL, collection time, validation status, and source lineage. Each evidence provenance entry records an evidence value and type, its collector, optional underlying data source and collection method, and optional original source URL. Missing data-source lineage is represented as unknown. A username match alone is never treated as evidence of shared identity.

## Repository layout

```text
.
├── data/
│   ├── processed/       # Derived, normalized research data (future use)
│   └── raw/             # Source outputs for authorized runs (future use)
├── docs/                # Design notes, schemas, and research documentation
├── reports/             # Generated reports (future use)
├── scripts/             # Developer and research helper scripts (future use)
├── src/
│   └── uti/
│       ├── collectors/  # Adapters for external OSINT sources
│       ├── config/       # Application and collector configuration
│       ├── correlation/  # Cross-source matching and deduplication
│       ├── dashboard/   # Streamlit application and UI components
│       ├── normalizers/ # Source-to-common-schema transformations
│       ├── reporting/   # Export and report generation
│       ├── scoring/     # Structured profile and record assessments
│       ├── services/    # Unified investigation orchestration
│       ├── storage/     # Persistence and research-run access
│       └── utils/       # Shared helpers
└── tests/               # Unit and integration tests (future use)
```

The empty `__init__.py` files mark `uti` and its planned components as Python packages. `.gitkeep` files preserve otherwise-empty directories in version control.

## Responsible research

Use UTI only for authorized research, including testing accounts you control or have permission to assess. Limit collection to publicly available information, respect source terms and rate limits, and avoid bypassing access controls. Treat findings as leads that require human review; do not use automated matches as the sole basis for consequential decisions. Minimize retained data, protect local research outputs, and document the purpose and scope of each study.

## Processing layer

The initial processing layer is implemented using only the Python standard library:

- `uti.models.Finding` is the immutable shared record. Its `source_lineage` contains collector name, optional underlying data source, and collection method. Its `evidence_provenance` records each evidence value, evidence type, original source URL, and the lineage that produced it.
- `uti.normalizers.normalize_finding` accepts common field aliases and structured evidence entries. Dataset aliases include `underlying_data_source`, `source_dataset`, `data_source`, and `dataset`; evidence accepts `evidence_type`/`type` and `original_source_url`/`source_url`/`url`. A missing dataset identifier remains unknown.
- `uti.deduplication.deduplicate_findings` merges records for the same exact queried username and canonical profile URL, retaining source lineages and every evidence provenance record. It does not use a legacy numeric confidence value to choose a record.
- `uti.correlation.correlate_findings` returns candidate groups with a `same_profile_candidate` flag and typed shared-evidence matches. Each match is classified as `INDEPENDENT`, `DEPENDENT`, or `UNKNOWN`. Only distinct, explicitly declared underlying dataset identifiers count as independent. Results and reason text explicitly say identity is not verified.
- `uti.scoring.assess_finding` reports profile-check outcome, field-by-field record completeness, and source independence without a composite score. `uti.scoring.score_finding` remains only as a legacy, uncalibrated compatibility API and is not used by the investigation service.
- `uti.collectors.sherlock.SherlockCollector` invokes a configured Sherlock executable with a safe argument list, timeout, isolated output folder, and mocked-testable subprocess boundary. It parses Sherlock's documented CSV format and preserves each row as a candidate finding; it does not treat a username result as identity evidence.
- `uti.collectors.maigret.MaigretCollector` invokes Maigret with controlled subprocess options and preserves non-claimed statuses as diagnostics. `uti.services.InvestigationService` runs both adapters independently and returns findings, candidate correlations, and structured assessments.
- `uti.identity` is a separate, opt-in domain for public identity observations. When enabled, it checks positive Sherlock/Maigret profile candidates under strict URL safety, robots, validated redirect, response-size, DNS/request-timeout, and content-type rules. The same safe page response feeds URL verification and enrichment. Authorized local CSV/JSON evidence import is also supported. No external APIs, breach sources, or private-data lookups are included.
- URL verification distinguishes profile-specific accessible content, redirect, not-found, access restriction, inconclusive response, timeout, error, and skip. Generic HTTP 200 pages do not count as verified profile content. Page accessibility is never account ownership verification.
- Identity attributes retain original and normalized values, exact source profile URL, evidence, lineage, provenance, timestamp, verification status, and association status. Supported generic HTML/JSON-LD extraction includes explicitly published contact details, names/aliases, linked public pages, organizations, job titles, professional affiliations, skills/technology terms, and coarse location. Exact matches preserve all observations; unknown lineage stays unknown.
- Threat rules include informational identity/contact, digital footprint, developer/technology, professional, domain/organization, and evidence-quality indicators. Impersonation, profile inconsistency, and source-reliability rules are not generated because the evidence/rules needed to support those claims are not implemented. Attack Surface Assessment provides distinct evidence counts and a dynamic narrative, with no numeric exposure or compromise score.
- Collector run summaries retain parsed raw CSV cell values separately from normalized findings. `uti.reporting` exports either the full investigation workbook or a separate findings workbook from the selected in-memory result without rerunning collectors.

`Finding.validation_status` is retained for compatibility and records a collector's profile-check outcome only. New consumers should prefer `Finding.profile_check_status` for that meaning. `Finding.ownership_status` is separately and explicitly `UNVERIFIED`; the model does not currently allow a verified ownership state, and `Finding.identity_verified` is always `False`. A `VALID` or Sherlock `Claimed` result must never be displayed or exported as verified identity or account ownership. Profile checks also do not guarantee that a URL remains reachable later.

`Finding.confidence` and `confidence_reasons` are retained for backward compatibility only. Their historical numeric values are uncalibrated and do not measure detection quality, evidence reliability, or identity confidence. New investigation results expose structured assessments and candidate correlations separately; there is no identity score. See [docs/scoring.md](docs/scoring.md) and [docs/investigation-service.md](docs/investigation-service.md) for assessment meanings and pipeline use.

All tests use fictional usernames and synthetic data; Sherlock and Maigret adapter tests mock subprocess execution and perform no searches. Correlation groups identify candidates for human review; they never verify that findings refer to the same real person. The external tools are not installed by this project. See [docs/sherlock-collector.md](docs/sherlock-collector.md), [docs/maigret-collector.md](docs/maigret-collector.md), and [docs/investigation-service.md](docs/investigation-service.md) for adapter and pipeline usage.

Identity collection is disabled unless explicitly enabled for an investigation. When enabled in the normal dashboard workflow, positive profiles from Sherlock and Maigret are selected automatically for bounded page retrieval. Fetching uses public DNS/IP checks, robots.txt, individually validated and pinned redirect destinations, default HTTP(S) ports, response-size and timeout limits, and HTML-only parsing. This is a bounded research helper, not a guarantee of source terms compliance or identity attribution. See [docs/url-verification.md](docs/url-verification.md), [docs/identity-intelligence.md](docs/identity-intelligence.md), [docs/threat-analysis.md](docs/threat-analysis.md), [docs/attack-surface.md](docs/attack-surface.md), [docs/configuration.md](docs/configuration.md), and [docs/excel-reporting.md](docs/excel-reporting.md).

## Getting started

Use Python 3.10 or newer. The dashboard requires Streamlit and Excel exports use openpyxl. From the repository root, activate the existing virtual environment in PowerShell, install requirements, and run the built-in unit tests:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Start the dashboard from the same environment with:

```powershell
$env:PYTHONPATH = "src"
streamlit run src/uti/dashboard/app.py
```

The `PYTHONPATH` assignment lets Python import the package from the `src/` layout without installing it. See [docs/dashboard.md](docs/dashboard.md) for dashboard views, selected-investigation behavior, and Excel exports.

## Next development steps

1. Define research scope controls and retention rules.
2. Add persistence and report export with explicit retention settings.
3. Extend collector coverage and evaluate profile-check behavior using authorized test accounts.
4. Continue refining the dashboard without exposing legacy composite confidence values as quality or identity measures.
