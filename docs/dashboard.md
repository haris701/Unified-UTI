# Unified-UTI dashboard

The Streamlit dashboard is a presentation layer over `InvestigationService`. It does not duplicate collector, normalization, deduplication, correlation, or assessment logic. Sherlock and Maigret run only after a user submits the investigation form.

## Run locally

From the project root, install the dashboard dependency and start the app:

```bash
python -m pip install -r requirements.txt
PYTHONPATH=src streamlit run src/uti/dashboard/app.py
```

The executable names default to `sherlock` and `maigret` from `PATH`. Use the collector configuration expander to set executable paths, a shared per-process timeout, each tool's request timeout, and Maigret's maximum connections.

## Workspace views

- **Dashboard** contains the single username investigation workflow, session activity and findings counts, and separate Sherlock and Maigret execution cards. Before a run it shows an empty workspace, without sample data.
- **Findings** provides a simple search over deduplicated profiles. Profile URLs open as links, with evidence available in a detail section. Ownership is labeled `UNVERIFIED` in the details.
- **Identity Intelligence** automatically passes positive Sherlock/Maigret profile candidates to the identity collector when enabled. Tabs separate profile summaries, collection audit, and identity attributes. Details remain attached to their exact source URL.
- **URL Verification** summarizes outcomes and shows a compact candidate table. Selecting a URL reveals the response details, metadata, and reason. Generic HTTP 200 is inconclusive; accessibility does not verify ownership.
- **Threat Analysis** filters explainable evidence-backed indicators by type and severity, shows source profile URLs and exact related attributes/findings, plus limitations and recommended defensive review. It does not label a person or account malicious.
- **Attack Surface Assessment** summarizes unique candidate pages, verification outcomes, distinct attribute exposure categories, supported correlations, indicators, evidence limitations, and linked recommendations. No numeric score is generated.
- **Evidence & Provenance** uses tabs to separate collected evidence, structured assessment, original collector rows, and identity evidence.
- Candidate correlation groups are no longer shown as a separate dashboard page or overview metric. Correlation data remains part of the investigation and existing Excel reports.
- **Export / Reports** downloads a complete report covering the investigation's findings, identity intelligence, URL checks, threat analysis, attack-surface summary, evidence, and diagnostics, plus separate findings and identity workbooks. Changing the selected investigation only changes the in-memory result being viewed/exported; it never reruns collectors.

Sherlock and Maigret run at the same time to reduce waiting; each collector has its own timeout and failures remain isolated. Optional public-page checks run one at a time to respect site access rules. A high profile-page limit can therefore take a long time; start with a small limit and increase it only when needed.

During a submitted run, Streamlit reports stage progress for Sherlock, Maigret, finding normalization/deduplication, profile URL checks, identity collectors, each public-page candidate, identity correlation, threat analysis, and attack-surface assessment. Collector subprocess internals are not streamed; the UI updates when each collector returns.

## Excel exports

The **Complete Report · All Sections (.xlsx)** action keeps the original seven sheets and adds Profile Intelligence, Identity Attributes, Dedup Identity Attributes, Profile URL Collection Audit, Identity Correlations, Threat Indicators, Identity Diagnostics, URL Verification, and Attack Surface Assessment. **Export Findings (.xlsx)** remains a three-sheet workbook. **Export Identity Intelligence (.xlsx)** includes identity evidence plus URL Verification and Attack Surface Assessment. Every action uses the selected investigation and in-memory results; none calls `InvestigationService` or reruns collectors.

Collector results preserve parsed CSV row fields before normalization in `RawCollectorRecord` values. The raw sheets contain those original decoded CSV cell values (including the untrimmed `url_user` field), while normalized sheets separately show the Finding URL and its canonical URL. CSV quoting and byte-for-byte file formatting are not retained; source output files remain temporary and are not exposed. Formula-like external text is written as literal text in workbook cells.

All workbook sheets include a frozen header row, filters, and bounded readable column widths. Empty result collections are exported as header-only sheets; summary and diagnostic information remains available. Investigation history is held only in the current Streamlit session and is cleared when that session ends.

The dashboard intentionally displays no legacy `Finding.confidence` value. It presents the structured profile-check and record-completeness assessments and does not produce an identity score. HTTP status codes do not override the collector-reported outcome. Every result remains `UNVERIFIED` for ownership and `False` for `identity_verified`.

Investigation results are held in the Streamlit session only; this dashboard does not persist them to the project storage directories. Collector warnings and errors remain visible, and one collector's failure does not block the other collector's findings.

The layout uses Streamlit's native page configuration and link-column support with a local dark navy theme and responsive CSS refinements. See the official [page configuration](https://docs.streamlit.io/develop/api-reference/configuration/st.set_page_config) and [dataframe link column](https://docs.streamlit.io/develop/api-reference/data/st.column_config/st.column_config.linkcolumn) references.
