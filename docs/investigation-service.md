# Unified investigation service

`uti.services.InvestigationService` runs the configured Sherlock and Maigret collectors for one username, then applies the existing finding processing components:

1. Collectors return findings already validated as the shared `Finding` model. The service validates each result again while preserving provenance and lineage.
2. Findings are deduplicated by exact username and canonical profile URL. The existing deduplicator retains evidence and source lineage from both tools.
3. The correlation engine runs over deduplicated findings. A matching username alone does not create a correlation; a candidate group requires a same-profile URL or matching evidence.
4. Structured assessments report each collector's profile-check outcome, field-by-field record completeness, and source independence. No composite score is calculated.

Sherlock and Maigret run concurrently as independent collectors. Returned errors, warnings, process output, exit status, timeout state, tool-specific diagnostics, and parsed raw CSV row fields are kept in `collector_summaries`. `RawCollectorRecord` retains decoded CSV header/value pairs and original cell strings separately from the normalized Finding. A failed or timed-out collector does not prevent the other collector's findings from passing through the pipeline. Top-level `warnings` and `errors` provide convenient aggregated messages. `investigated_at` records when orchestration began.

All findings and assessments keep ownership status `UNVERIFIED` and `identity_verified` false. Correlation results describe candidate relationships only and remain separate from record assessments.

Identity collection is separately disabled by default. Enable it using `investigate(username, enable_identity_collection=True, identity_evidence_content=..., identity_evidence_filename=...)`. Positive profile candidates from Sherlock and Maigret are automatically supplied to the safe page collector when identity collection is enabled. The same page response produces a separate URL verification outcome and, only when profile-specific markers exist, identity enrichment. Collector support, strict URL validation, public IP checks, robots.txt, each validated redirect hop, DNS/request/read timeouts, response limits, and HTML content type determine whether a URL is fetched or how it is classified. Local files are passed as bytes and must use a `.csv` or `.json` filename. Identity adapters retain diagnostics and per-URL audit outcomes rather than discarding other identity results. Threat indicators are descriptive and separate from identity correlations.

`InvestigationResult.profile_url_audits` records each candidate's original and canonical URL, collector provenance, whether collection was attempted, fetch status, HTTP code where available, collection time, extracted attribute count, and failure/skip reason. `build_profile_intelligence` links attributes to profiles only by canonical source URL; it never associates attributes using a matching username or value.

`InvestigationResult.url_verification_results` separately records original/final URLs, candidate outcome, HTTP code, page title, bounded page metadata, profile-specific marker, timestamp, lineage, and reason. HTTP 200 on a generic page remains inconclusive. `InvestigationResult.attack_surface` summarizes unique evidence values and verification results without a numeric score. A `progress_callback(stage, detail)` can be supplied to `investigate` to receive synchronous stage updates; collector process internals are not streamed.

The Streamlit session can hold multiple investigations and selects one for viewing/export. `uti.reporting.export_investigation_workbook(result)` retains the existing seven sheets and adds identity, verification, and assessment sheets. `uti.reporting.export_findings_workbook(result)` remains the separate three-sheet findings workbook. `uti.reporting.export_identity_workbook(result)` creates a dedicated identity workbook including URL verification and attack-surface assessment. These are pure exporters over the supplied `InvestigationResult`; they do not invoke collectors. Raw sheets contain decoded parsed CSV fields, not byte-for-byte CSV formatting, and temporary collector output paths are never returned. See [identity-intelligence.md](identity-intelligence.md), [url-verification.md](url-verification.md), [attack-surface.md](attack-surface.md), [architecture.md](architecture.md), and [excel-reporting.md](excel-reporting.md).

## Use

The exact API is `InvestigationService(*, sherlock_collector=None, maigret_collector=None).investigate(username)`. If collector arguments are omitted, it creates `SherlockCollector()` and `MaigretCollector()` with their defaults. To configure real executions, create the collectors and inject them:

```python
from uti.collectors import MaigretCollector, SherlockCollector
from uti.services import InvestigationService

service = InvestigationService(
    sherlock_collector=SherlockCollector(
        executable="sherlock",
        timeout_seconds=600,
        request_timeout_seconds=10,
    ),
    maigret_collector=MaigretCollector(
        executable="maigret",
        timeout_seconds=600,
        request_timeout_seconds=30,
        max_connections=20,
    ),
)
result = service.investigate("uti_demo_test_2026")

print(result.username)
print("Findings:", len(result.deduplicated_findings))
print("Correlations:", len(result.correlation_results))
for assessment in result.assessments:
    finding = assessment.finding
    print(finding.platform, finding.profile_url)
    print("Source independence:", assessment.source_independence.value)
    for outcome in assessment.profile_check_outcomes:
        print("Profile check:", outcome.outcome.value, "from", outcome.collector_name, "at", outcome.collected_at)
    print("Available fields:", assessment.record_completeness.available_fields)
    print("Missing fields:", assessment.record_completeness.missing_fields)
    print("Unknown fields:", assessment.record_completeness.unknown_fields)
for error in result.errors:
    print("ERROR:", error)
for warning in result.warnings:
    print("WARNING:", warning)
```

Calling `investigate` launches both collectors and makes their normal network requests. Use authorized research accounts and an appropriate project scope. To exercise the orchestration in tests, collectors are injected as mocked objects and no external searches are run.

## Manual Kali smoke test

The manual script `scripts/manual_investigation_smoke_test.py` runs both installed executables through this same service, displays status and findings per collector, processing totals, correlations, structured assessments, warnings, errors, and the ownership safeguards. It is not invoked by the unit-test suite.

From the Kali terminal, run:

```bash
cd /media/sf_Unified-UTI
source .venv/bin/activate
PYTHONPATH=src python scripts/manual_investigation_smoke_test.py \
  uti_demo_test_2026 \
  --timeout-seconds 900 \
  --sherlock-request-timeout-seconds 10 \
  --maigret-request-timeout-seconds 30 \
  --max-connections 20
```

The defaults assume `sherlock` and `maigret` are available on `PATH`. If either executable is elsewhere, pass `--sherlock-executable /path/to/sherlock` or `--maigret-executable /path/to/maigret`. `--timeout-seconds` is the separate overall process timeout for each collector; the two request-timeout options set their per-site timeout, and `--max-connections` configures Maigret. A collector failure is reported, and the other collector's results are still processed. This manual command makes real network requests; run it only for an authorized account and approved research scope.

Tests can be run from the project root in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```
