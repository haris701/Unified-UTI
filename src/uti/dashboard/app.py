"""Unified-UTI Streamlit dashboard entry point.

Run from the project root with ``streamlit run src/uti/dashboard/app.py``.
Collectors only run after an explicit form submission.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
import re
import sys
from math import ceil
from typing import Any

PROJECT_SRC = Path(__file__).resolve().parents[2]
if str(PROJECT_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_SRC))

import streamlit as st

from uti.collectors import MaigretCollector, SherlockCollector
from uti.dashboard.components import collector_card, metric_card, render_brand, section_label
from uti.dashboard.styles import apply_theme, empty_state, page_header
from uti.dashboard.viewmodels import attack_surface_category_rows
from uti.models import Finding
from uti.identity.presentation import build_profile_intelligence
from uti.identity.collectors import LocalEvidenceIdentityCollector, PublicPageFetcher, PublicPageIdentityCollector
from uti.identity.service import IdentityIntelligenceService
from uti.reporting import export_findings_workbook, export_identity_workbook, export_investigation_workbook
from uti.services import InvestigationResult, InvestigationService
from uti.utils.urls import canonical_profile_url


PAGES = (
    "Dashboard",
    "Findings",
    "Identity Intelligence",
    "URL Verification",
    "Threat Analysis",
    "Attack Surface Assessment",
    "Evidence & Provenance",
    "Export / Reports",
)
_RESULT_KEY = "uti_investigation_result"
_HISTORY_KEY = "uti_investigation_history"
_HISTORY_WIDGET = "uti_selected_investigation"
_PENDING_SELECTION = "uti_pending_investigation_selection"
_PAGE_ICONS = {
    "Dashboard": "⌂",
    "Findings": "⌕",
    "Identity Intelligence": "◎",
    "URL Verification": "↗",
    "Threat Analysis": "⛨",
    "Attack Surface Assessment": "◈",
    "Evidence & Provenance": "▤",
    "Export / Reports": "⇩",
}


def main() -> None:
    st.set_page_config(
        page_title="Unified-UTI | Intelligence Workspace",
        page_icon="U",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    apply_theme()
    pending = st.session_state.pop(_PENDING_SELECTION, None)
    if pending is not None:
        st.session_state[_HISTORY_WIDGET] = pending
    selected_page = _sidebar_navigation()
    result = st.session_state.get(_RESULT_KEY)

    if selected_page == "Dashboard":
        _render_overview(result)
    elif selected_page == "Findings":
        _render_findings(result)
    elif selected_page == "Identity Intelligence":
        _render_identity_intelligence(result)
    elif selected_page == "URL Verification":
        _render_url_verification(result)
    elif selected_page == "Threat Analysis":
        _render_threat_analysis(result)
    elif selected_page == "Attack Surface Assessment":
        _render_attack_surface(result)
    elif selected_page == "Evidence & Provenance":
        _render_evidence(result)
    else:
        _render_exports(result)


def _sidebar_navigation() -> str:
    with st.sidebar:
        render_brand()
        section_label("Workspace")
        if st.session_state.get("uti_navigation") not in PAGES:
            st.session_state.pop("uti_navigation", None)
        selected = st.radio(
            "Navigation",
            PAGES,
            format_func=lambda page: f"{_PAGE_ICONS[page]}   {page}",
            label_visibility="collapsed",
            key="uti_navigation",
        )
        history = st.session_state.get(_HISTORY_KEY, [])
        if history:
            labels = [label for label, _ in history]
            current = st.session_state.get(_RESULT_KEY)
            current_label = next((label for label, item in history if item is current), labels[-1])
            selected_label = st.selectbox(
                "Selected investigation", labels,
                index=labels.index(current_label) if current_label in labels else len(labels) - 1,
                key=_HISTORY_WIDGET,
            )
            selected_result = next(item for label, item in history if label == selected_label)
            st.session_state[_RESULT_KEY] = selected_result
        else:
            st.caption("No investigation in this session")
    return selected


def _render_overview(result: InvestigationResult | None) -> None:
    page_header(
        "Intelligence workspace",
        "Investigation overview",
        "Run a scoped username search and review its source-attributed findings.",
    )
    _render_scan_form(key_suffix="overview")
    result = st.session_state.get(_RESULT_KEY)

    section_label("Current investigation")
    if result is None:
        _render_empty_overview()
        return

    positive = sum(
        outcome.outcome.value == "positive"
        for assessment in result.assessments
        for outcome in assessment.profile_check_outcomes
    )
    collector_checks = sum(item.findings_count for item in result.collector_summaries)
    columns = st.columns(4, gap="medium")
    metrics = (
        ("Investigations", len(st.session_state.get(_HISTORY_KEY, [])), "This browser session"),
        ("Collector findings", collector_checks, "Source-level candidate results"),
        ("Unique profiles", len(result.deduplicated_findings), "After URL-based deduplication"),
        ("Positive checks", positive, "Tool-reported positive outcomes"),
    )
    for column, (label, value, note) in zip(columns, metrics):
        with column:
            metric_card(label, value, note)

    st.markdown("<div style='height:.8rem'></div>", unsafe_allow_html=True)
    summaries = {item.collector_name: item for item in result.collector_summaries}
    section_label("Collector status")
    first, second = st.columns(2, gap="medium")
    with first:
        collector_card("Sherlock", summaries.get("sherlock"))
    with second:
        collector_card("Maigret", summaries.get("maigret"))

    if result.errors:
        st.warning("The investigation completed with collector or processing issues. Available findings are retained.")
    elif result.deduplicated_findings:
        st.success(f"Investigation completed for {result.username}.")
    else:
        st.info("Both collectors completed without returning candidate findings.")
    _render_run_messages(result)
    _render_recent_activity()


def _render_empty_overview() -> None:
    columns = st.columns(4, gap="medium")
    for column, label, note in zip(
        columns,
        ("Investigations", "Collector findings", "Unique profiles", "Positive checks"),
        ("No run yet", "No run yet", "No run yet", "No run yet"),
    ):
        with column:
            metric_card(label, "—", note)
    empty_state(
        "Your workspace is ready",
        "Start an investigation above. Results appear here after Sherlock and Maigret finish or report an issue.",
    )
    _render_recent_activity()


def _render_scan_form(*, key_suffix: str) -> None:
    with st.form(f"uti_investigation_form_{key_suffix}", clear_on_submit=False):
        st.markdown("**Search a username**")
        username = st.text_input(
            "Username",
            value="",
            placeholder="e.g. uti_demo_test_2026",
            label_visibility="collapsed",
            key=f"uti_username_{key_suffix}",
        )
        st.caption("Only run searches for accounts within your authorized research scope.")
        with st.expander("Investigation configuration", expanded=False):
            section_label("Optional identity intelligence")
            identity_enabled = st.checkbox(
                "Enable identity collection for this investigation",
                value=True,
                key=f"uti_identity_enabled_v2_{key_suffix}",
                help="Enabled by default. Turn it off to skip public profile-page checks.",
            )
            st.markdown(
                '<div class="uti-help-copy">When enabled, UTI checks eligible public profile pages found by '
                'Sherlock and Maigret. It reads pages only when site rules and safety checks allow it. '
                'Some pages may not show information UTI can extract.</div>',
                unsafe_allow_html=True,
            )
            max_profile_urls = st.number_input(
                "Maximum profile pages to check",
                min_value=1,
                max_value=5000,
                value=500,
                step=25,
                key=f"uti_identity_max_urls_v2_{key_suffix}",
                help="Pages are checked one at a time. Higher limits can take much longer.",
            )
            st.markdown("---")
            section_label("Collector configuration")
            left, right = st.columns(2)
            with left:
                sherlock_executable = st.text_input("Sherlock executable", value="sherlock", key=f"uti_sherlock_bin_{key_suffix}")
                overall_timeout = st.number_input(
                    "Overall timeout per collector (seconds)", min_value=1, max_value=3600, value=600, step=30,
                    key=f"uti_timeout_{key_suffix}",
                )
                sherlock_timeout = st.number_input(
                    "Sherlock request timeout (seconds)", min_value=1, max_value=300, value=10, step=1,
                    key=f"uti_sherlock_request_{key_suffix}",
                )
            with right:
                maigret_executable = st.text_input("Maigret executable", value="maigret", key=f"uti_maigret_bin_{key_suffix}")
                maigret_timeout = st.number_input(
                    "Maigret request timeout (seconds)", min_value=1, max_value=300, value=30, step=1,
                    key=f"uti_maigret_request_{key_suffix}",
                )
                max_connections = st.number_input(
                    "Maigret maximum connections", min_value=1, max_value=100, value=20, step=1,
                    key=f"uti_maigret_connections_{key_suffix}",
                )
        submitted = st.form_submit_button("Run investigation", type="primary", use_container_width=True)

    if not submitted:
        return
    if not username.strip():
        st.warning("Enter a username to start an investigation.")
        return

    try:
        sherlock = SherlockCollector(
            executable=sherlock_executable.strip(),
            timeout_seconds=float(overall_timeout),
            request_timeout_seconds=float(sherlock_timeout),
        )
        maigret = MaigretCollector(
            executable=maigret_executable.strip(),
            timeout_seconds=float(overall_timeout),
            request_timeout_seconds=float(maigret_timeout),
            max_connections=int(max_connections),
        )
        identity_service = IdentityIntelligenceService((
            PublicPageIdentityCollector(fetcher=PublicPageFetcher(max_urls=int(max_profile_urls))),
            LocalEvidenceIdentityCollector(),
        ))
        service = InvestigationService(
            sherlock_collector=sherlock,
            maigret_collector=maigret,
            identity_service=identity_service,
        )
        with st.status("Running Sherlock and Maigret", expanded=True) as progress_status:
            collector_states = {"Sherlock": "starting", "Maigret": "starting"}
            last_candidate = 0

            def report_progress(stage: str, detail: str) -> None:
                nonlocal last_candidate
                if stage in collector_states:
                    collector_states[stage] = detail
                    label = " · ".join(f"{name}: {state}" for name, state in collector_states.items())
                    progress_status.update(label=label, state="running")
                    return

                if stage == "OSINT enrichment":
                    return
                if stage == "URL verification":
                    match = re.search(r"candidate\s+(\d+)\s+of\s+(\d+)", detail, re.IGNORECASE)
                    if match:
                        current, total = (int(value) for value in match.groups())
                        update_step = max(5, ceil(total / 20))
                        if current != total and current - last_candidate < update_step:
                            return
                        last_candidate = current
                        detail = f"Checking public profile pages: {current} of {total}"
                progress_status.update(label=f"{stage}: {detail}", state="running")

            result = service.investigate(
                username.strip(),
                enable_identity_collection=identity_enabled,
                include_profile_findings=True,
                progress_callback=report_progress,
            )
            progress_status.update(label="Investigation stages completed", state="complete")
        st.session_state[_RESULT_KEY] = result
        history = list(st.session_state.get(_HISTORY_KEY, []))
        label = f"{len(history) + 1}. {result.username} · {result.investigated_at.strftime('%Y-%m-%d %H:%M UTC')}"
        history.append((label, result))
        st.session_state[_HISTORY_KEY] = history
        st.session_state[_PENDING_SELECTION] = label
        st.rerun()
        if result.errors:
            st.warning("Investigation finished with collector issues. Review the status and errors below.")
        elif result.deduplicated_findings:
            st.success(f"Investigation complete — {len(result.deduplicated_findings)} unique profile candidates.")
        else:
            st.info("Investigation completed; no candidate findings were returned.")
    except (TypeError, ValueError, OSError) as exc:
        st.error(f"Could not start the investigation: {exc}")


def _render_run_messages(result: InvestigationResult) -> None:
    if result.warnings:
        with st.expander(f"Warnings · {len(result.warnings)}", expanded=False):
            for warning in result.warnings:
                st.text(warning)
    if result.errors:
        with st.expander(f"Errors · {len(result.errors)}", expanded=bool(result.errors)):
            for error in result.errors:
                st.text(error)


def _require_result(result: InvestigationResult | None) -> bool:
    if result is None:
        empty_state("No investigation loaded", "Run an investigation to populate this view with collected results.")
        return False
    return True


def _outcome_label(outcome: Any) -> str:
    value = getattr(outcome, "outcome", "inconclusive")
    value = getattr(value, "value", value)
    labels = {
        "positive": "● Positive",
        "negative": "○ Negative",
        "inconclusive": "◌ Inconclusive",
        "error": "! Error",
    }
    return labels.get(str(value).casefold(), "◌ Inconclusive")


def _status_for_assessment(assessment: Any) -> str:
    values = []
    for outcome in assessment.profile_check_outcomes:
        values.append(f"{_outcome_label(outcome)} · {outcome.collector_name}")
    return "; ".join(values) if values else "Inconclusive"


def _render_findings(result: InvestigationResult | None) -> None:
    page_header("Results", "Findings", "Search the collected profile candidates and open source pages for review.")
    if not _require_result(result):
        return
    assert result is not None
    findings = result.deduplicated_findings
    if not findings:
        empty_state("No profile candidates", "The collectors returned no findings for this investigation.")
        return

    assessment_map = {
        (item.finding.username, item.finding.profile_url): item for item in result.assessments
    }
    query = st.text_input("Search findings", placeholder="Search platform, URL, or collector", key="uti_findings_search")

    rows: list[dict[str, str]] = []
    visible_findings: list[Finding] = []
    for finding in findings:
        assessment = assessment_map.get((finding.username, finding.profile_url))
        status = _status_for_assessment(assessment) if assessment else "Inconclusive"
        haystack = " ".join((finding.platform, finding.profile_url, *finding.source_tools)).casefold()
        if query.strip() and query.strip().casefold() not in haystack:
            continue
        visible_findings.append(finding)
        rows.append(
            {
                "Platform": finding.platform,
                "Profile URL": finding.profile_url,
                "Profile check": status,
                "Sources": ", ".join(finding.source_tools),
                "Collected": finding.collected_at.strftime("%Y-%m-%d %H:%M UTC"),
            }
        )

    st.caption(f"Showing {len(rows)} of {len(findings)} deduplicated findings. A positive check is a collector-reported candidate, not proof of account ownership.")
    if not rows:
        empty_state("No matching findings", "Try another search term or clear the search box.")
        return
    st.dataframe(
        rows,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Platform": st.column_config.TextColumn("Platform", width="medium"),
            "Profile URL": st.column_config.LinkColumn("Profile", display_text="Open profile ↗", validate=r"^https?://"),
            "Profile check": st.column_config.TextColumn("Profile check", width="medium"),
            "Sources": st.column_config.TextColumn("Collectors", width="medium"),
            "Collected": st.column_config.TextColumn("Collected", width="small"),
        },
    )
    labels, finding_map = _finding_choices(result, visible_findings)
    selected = st.selectbox("Finding details", labels, key="uti_finding_detail")
    finding = finding_map[selected]
    with st.expander("Evidence and source details", expanded=False):
        st.write(f"Profile check: {_status_for_assessment(assessment_map.get((finding.username, finding.profile_url)))}")
        st.write(f"Ownership: {finding.ownership_status.value.upper()} · Identity verified: {finding.identity_verified}")
        for item in finding.evidence_provenance:
            st.markdown(f"**{escape(item.evidence_type)} · {escape(item.source_lineage.collector_name)}**")
            st.text(item.value)
            st.caption(f"Original source URL: {item.original_source_url or 'Unknown'}")


def _finding_choices(
    result: InvestigationResult,
    findings: tuple[Finding, ...] | list[Finding] | None = None,
) -> tuple[list[str], dict[str, Finding]]:
    labels: list[str] = []
    finding_map: dict[str, Finding] = {}
    selected_findings = result.deduplicated_findings if findings is None else findings
    for index, finding in enumerate(selected_findings):
        label = f"{finding.platform} · {finding.username} · {index + 1}"
        labels.append(label)
        finding_map[label] = finding
    return labels, finding_map


def _render_evidence(result: InvestigationResult | None) -> None:
    page_header("Source record", "Evidence & provenance", "Inspect evidence values and the lineage behind each finding.")
    if not _require_result(result):
        return
    assert result is not None
    if not result.deduplicated_findings:
        if result.identity_attributes:
            _render_identity_evidence(result)
            return
        empty_state("No evidence to review", "Findings and their source records will appear after collection.")
        return

    labels, finding_map = _finding_choices(result)
    selected = st.selectbox("Select a finding", labels, key="uti_evidence_finding")
    finding = finding_map[selected]
    assessment = next(
        (item for item in result.assessments if item.finding.username == finding.username and item.finding.profile_url == finding.profile_url),
        None,
    )
    st.markdown(f"### {escape(finding.platform)}")
    st.link_button("Open profile", finding.profile_url)
    st.caption("Account ownership is UNVERIFIED.")
    evidence_tab, assessment_tab, records_tab, identity_tab = st.tabs(
        ("Evidence", "Assessment", "Original records", "Identity evidence")
    )

    with evidence_tab:
        if not finding.evidence_provenance:
            st.caption("No evidence values were recorded for this finding.")
        else:
            evidence_rows = [{
                "Evidence": item.value,
                "Evidence type": item.evidence_type,
                "Collector": item.source_lineage.collector_name,
                "Data source": item.source_lineage.underlying_data_source or "Unknown",
                "Method": item.source_lineage.collection_method or "Unknown",
                "Original source URL": item.original_source_url or "",
            } for item in finding.evidence_provenance]
            st.dataframe(
                evidence_rows, hide_index=True, use_container_width=True,
                column_config={
                    "Original source URL": st.column_config.LinkColumn("Original source", validate=r"^https?://"),
                },
            )

    with assessment_tab:
        if assessment is None:
            st.caption("No structured assessment is available for this finding.")
        else:
            section_label("Collector-reported checks")
            for outcome in assessment.profile_check_outcomes:
                st.markdown(
                    f"- {_outcome_label(outcome)} · {escape(outcome.collector_name)} · "
                    f"{outcome.collected_at.strftime('%Y-%m-%d %H:%M UTC')}"
                )
            section_label("Record completeness")
            completion_rows = [{
                "Field": field.name.replace("_", " ").title(),
                "State": field.state.value.title(),
            } for field in assessment.record_completeness.fields]
            st.dataframe(completion_rows, hide_index=True, use_container_width=True)
            st.caption(f"Source independence: {assessment.source_independence.value.title()}")

    with records_tab:
        raw_rows = _raw_collector_rows(result, finding)
        if raw_rows:
            st.dataframe(raw_rows, hide_index=True, use_container_width=True)
        else:
            st.caption("No matching raw collector row was retained for this finding.")
        st.markdown("**Normalized finding**")
        st.json({
            "username": finding.username,
            "platform": finding.platform,
            "profile_url": finding.profile_url,
            "normalized_url": canonical_profile_url(finding.profile_url),
            "source_tool": finding.source_tool,
            "validation_status": finding.validation_status.value,
        })

    with identity_tab:
        _render_identity_evidence(result)


def _raw_collector_rows(result: InvestigationResult, finding: Finding) -> list[dict[str, str | int]]:
    """Return retained raw rows matching a finding, without changing source data."""
    rows: list[dict[str, str | int]] = []
    source_names = {name.casefold() for name in finding.source_tools}
    for summary in result.collector_summaries:
        if summary.collector_name.casefold() not in source_names:
            continue
        for record in summary.raw_records:
            values = record.as_mapping()
            try:
                raw_url = next(
                    (value or "" for header, value in values.items() if header.strip().casefold() == "url_user"),
                )
                raw_canonical = canonical_profile_url(raw_url.strip())
            except (StopIteration, ValueError):
                continue
            raw_username = next((value or "" for header, value in values.items() if header.strip().casefold() == "username"), "")
            raw_platform = next((value or "" for header, value in values.items() if header.strip().casefold() == "name"), "")
            if (
                raw_canonical == canonical_profile_url(finding.profile_url)
                and raw_username.strip() == finding.username
                and raw_platform.strip() == finding.platform
            ):
                rows.append({"CSV line": record.line_number, **values})
    return rows


def _render_identity_evidence(result: InvestigationResult) -> None:
    section_label("Identity attribute evidence")
    if not result.identity_attributes:
        st.caption("No identity attribute records are available for this investigation.")
        return
    labels = [f"{item.attribute_type.value} · {item.source_tool} · {index + 1}" for index, item in enumerate(result.identity_attributes)]
    selected = st.selectbox("Select identity evidence", labels, key="uti_identity_evidence_selected")
    attribute = result.identity_attributes[labels.index(selected)]
    st.markdown("**Original value**")
    st.code(attribute.original_value, language=None)
    st.markdown("**Normalized value**")
    st.code(attribute.normalized_value, language=None)
    st.write(f"Verification: {attribute.verification_status.value} · Association: {attribute.association_status.value}")
    st.write(f"Source: {attribute.source_tool} · Collected: {attribute.collected_at.strftime('%Y-%m-%d %H:%M UTC')}")
    if attribute.source_url:
        st.link_button("Open evidence source", attribute.source_url)
    st.caption(attribute.evidence)
    for lineage in attribute.source_lineage:
        st.text(f"Lineage: {lineage.collector_name} · dataset={lineage.underlying_data_source or 'unknown'} · method={lineage.collection_method or 'unknown'}")


def _render_identity_intelligence(result: InvestigationResult | None) -> None:
    page_header("Identity intelligence", "Profile intelligence", "Review each discovered profile and only the attributes collected from that exact source URL.")
    if not _require_result(result):
        return
    assert result is not None
    if not result.identity_collection_enabled:
        st.info("Identity collection was off for this investigation. Discovered profile candidates are still listed; their pages were not fetched.")
    attributes = result.identity_attributes
    profiles = build_profile_intelligence(result.deduplicated_findings, attributes, result.profile_url_audits)
    profile_tab, audit_tab, attribute_tab = st.tabs(
        ("Profiles", "Collection audit", "Identity attributes")
    )
    with profile_tab:
        _render_profile_intelligence(result, profiles)
    with audit_tab:
        _render_profile_audit(result)
    with attribute_tab:
        _render_identity_attributes(attributes)


def _render_profile_intelligence(result: InvestigationResult, profiles: tuple[Any, ...]) -> None:
    section_label("Profile intelligence results")
    if not profiles:
        empty_state("No discovered profiles", "Sherlock and Maigret did not return profile URLs for this investigation.")
        return

    all_platforms = sorted({profile.finding.platform for profile in profiles}, key=str.casefold)
    all_statuses = sorted({
        profile.collection_audit.fetch_status.value.upper() if profile.collection_audit else "DISCOVERED"
        for profile in profiles
    })
    filter_platform, filter_availability, filter_status = st.columns(3, gap="medium")
    selected_platforms = filter_platform.multiselect(
        "Platform", all_platforms, default=all_platforms, key="uti_profile_platform_filter"
    )
    availability_options = ("Attributes found", "No attributes found")
    selected_availability = filter_availability.multiselect(
        "Attribute availability", availability_options, default=list(availability_options),
        key="uti_profile_availability_filter",
    )
    selected_collection_statuses = filter_status.multiselect(
        "Collection status", all_statuses, default=all_statuses, key="uti_profile_collection_filter"
    )

    profile_rows = []
    visible_profiles = []
    field_types = {
        "Display name": {"display_name"},
        "Public email": {"email"},
        "Website": {"website", "domain"},
        "Organization": {"organization"},
    }
    for profile in profiles:
        audit = profile.collection_audit
        collection_status = audit.fetch_status.value.upper() if audit else "DISCOVERED"
        available = bool(profile.attributes)
        if profile.finding.platform not in selected_platforms or collection_status not in selected_collection_statuses:
            continue
        if ("Attributes found" if available else "No attributes found") not in selected_availability:
            continue
        visible_profiles.append(profile)
        values = {}
        for label, kinds in field_types.items():
            matching = [item.original_value for item in profile.attributes if item.attribute_type.value in kinds]
            values[label] = ", ".join(dict.fromkeys(matching)) if matching else "-"
        profile_rows.append({
            "Username": profile.finding.username,
            "Platform": profile.finding.platform,
            "Profile": profile.finding.profile_url,
            **values,
            "Collection": collection_status,
            "URL check": _verification_status(result, profile.finding.profile_url),
        })
    if not profile_rows:
        empty_state("No profiles match these filters", "Clear a filter to show more discovered profiles.")
    else:
        st.dataframe(
            profile_rows, hide_index=True, use_container_width=True,
            column_config={
                "Profile": st.column_config.LinkColumn("Profile", display_text="Open profile", validate=r"^https?://"),
                "Display name": st.column_config.TextColumn("Display name", width="medium"),
                "Public email": st.column_config.TextColumn("Public email", width="medium"),
                "Website": st.column_config.TextColumn("Website", width="medium"),
                "Organization": st.column_config.TextColumn("Organization", width="medium"),
            },
        )
    st.caption("Values are shown only when evidence was collected from that profile URL. A matching value does not establish common identity.")
    if visible_profiles:
        detail_labels = [f"{p.finding.platform} · {p.finding.profile_url}" for p in visible_profiles]
        selected_profile = st.selectbox("Inspect profile evidence", detail_labels, key="uti_profile_intelligence_detail")
        detail = visible_profiles[detail_labels.index(selected_profile)]
        if detail.attributes:
            for index, item in enumerate(detail.attributes, start=1):
                with st.expander(f"{item.attribute_type.value.replace('_', ' ').title()} · {index}", expanded=False):
                    st.write(f"Value: {item.original_value}")
                    st.caption(f"Source: {item.source_tool} · {item.source_url or 'Unknown URL'}")
                    st.write(f"Evidence: {item.evidence}")
                    st.caption(f"Evidence type: {item.evidence_type} · Collected: {item.collected_at.strftime('%Y-%m-%d %H:%M UTC')}")
                    st.markdown("**Source lineage and provenance**")
                    for lineage in item.source_lineage:
                        st.caption(f"{lineage.collector_name} · dataset={lineage.underlying_data_source or 'unknown'} · method={lineage.collection_method or 'unknown'}")
                    for provenance in item.evidence_provenance:
                        st.caption(f"{provenance.evidence_type}: {provenance.value} · {provenance.original_source_url or 'source URL unknown'}")


def _render_profile_audit(result: InvestigationResult) -> None:
    section_label("Profile URL collection audit")
    if result.profile_url_audits:
        audit_rows = [{
                "Username": item.username,
                "Platform": item.platform,
                "Original URL": " | ".join(item.original_profile_urls),
                "Canonical URL": item.canonical_profile_url or "Unavailable",
                "Discovered by": ", ".join(item.discovery_collectors),
                "Status": item.fetch_status.value.upper(),
                "HTTP": item.http_status if item.http_status is not None else "-",
                "Attributes": item.extracted_attribute_count,
                "Issue": item.error_or_warning or item.reason_skipped or "-",
            }
            for item in result.profile_url_audits]
        st.dataframe(
            audit_rows,
            hide_index=True,
            use_container_width=True,
            column_config={
                "Original URL": st.column_config.LinkColumn("Original URL", validate=r"^https?://"),
                "Canonical URL": st.column_config.LinkColumn("Canonical URL", validate=r"^https?://"),
            },
        )
    else:
        empty_state("No profile URLs to audit", "No candidate profile URLs were returned by the username collectors.")


def _render_identity_attributes(attributes: tuple[Any, ...]) -> None:
    section_label("Identity attributes and evidence")
    if attributes:
        types = sorted({item.attribute_type.value for item in attributes})
        selected_types = st.multiselect("Attribute type", types, default=types, key="uti_identity_type_filter")
        rows = [{
            "Type": item.attribute_type.value.replace("_", " ").title(),
            "Value": item.original_value,
            "Source": item.source_tool,
            "Source URL": item.source_url or "",
            "Evidence": item.evidence,
            "Evidence type": item.evidence_type,
            "Collected (UTC)": item.collected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Sensitivity": item.sensitivity.value.title(),
        } for item in attributes if item.attribute_type.value in selected_types]
        if rows:
            st.dataframe(rows, hide_index=True, use_container_width=True, column_config={
                "Source URL": st.column_config.LinkColumn("Source URL", display_text="Open source", validate=r"^https?://"),
            })
        else:
            empty_state("No attributes match this filter", "Choose another attribute type to see its source evidence.")
        st.caption("Values are reported from their source pages. They do not verify account ownership.")
    else:
        empty_state("No identity attributes", "No supported identity values were collected for this investigation.")


def _render_url_verification(result: InvestigationResult | None) -> None:
    page_header("Page checks", "URL verification", "See whether a discovered profile link opens profile-specific public content. This does not confirm who owns the account.")
    if not _require_result(result):
        return
    assert result is not None
    if not result.identity_collection_enabled:
        st.info("URL verification uses public-page requests and therefore follows the investigation’s identity collection opt-in.")
    records = result.url_verification_results
    if not records:
        empty_state("No URLs to verify", "No profile candidates were returned by the collectors.")
        return

    status_counts: dict[str, int] = {}
    for record in records:
        status_counts[record.status.value.upper()] = status_counts.get(record.status.value.upper(), 0) + 1
    status_names = ("verified_accessible", "inconclusive", "not_found")
    metric_columns = st.columns(4, gap="medium")
    metric_labels = ("Profile-specific pages", "Unclear results", "Pages not found")
    for column, status_name, metric_label in zip(metric_columns[:3], status_names, metric_labels):
        with column:
            metric_card(metric_label, status_counts.get(status_name.upper(), 0))
    other_count = len(records) - sum(status_counts.get(name.upper(), 0) for name in status_names)
    with metric_columns[3]:
        metric_card("Other outcomes", other_count)

    compact_rows = [{
        "Platform": item.platform,
        "Candidate URL": item.original_url,
        "Result": _url_status_label(item.status.value),
        "HTTP": item.http_status if item.http_status is not None else "-",
        "Profile-specific": "Yes" if item.profile_specific else "No",
        "Checked (UTC)": item.verified_at.strftime("%Y-%m-%d %H:%M UTC"),
    } for item in records]
    st.dataframe(
        compact_rows,
        hide_index=True,
        use_container_width=True,
        column_config={
            "Candidate URL": st.column_config.LinkColumn("Candidate URL", display_text="Open candidate", validate=r"^https?://"),
            "Result": st.column_config.TextColumn("Result", width="medium"),
        },
    )
    record_labels = [f"{item.platform} · {item.original_url}" for item in records]
    selected = st.selectbox("Review verification details", record_labels, key="uti_url_verification_detail")
    record = records[record_labels.index(selected)]
    with st.expander("Page response and collection details", expanded=False):
        st.write(f"Result: {_url_status_label(record.status.value)}")
        st.write(f"HTTP status: {record.http_status if record.http_status is not None else '-'}")
        st.write(f"Final URL: {record.final_url or '-'}")
        st.write(f"Page title: {record.page_title or '-'}")
        if record.page_metadata:
            st.write("Page metadata")
            st.json(dict(record.page_metadata))
        st.write(f"Reason: {record.reason}")
        st.caption(f"Checked: {record.verified_at.strftime('%Y-%m-%d %H:%M:%S UTC')} · Sources: {', '.join(record.discovering_collectors) or 'Unknown'}")
    st.caption("A profile-specific page has profile-shaped page details. Generic pages and HTTP 200 responses alone are inconclusive. No result confirms account ownership.")


def _url_status_label(status: str) -> str:
    """Return plain-language wording that avoids implying identity verification."""
    labels = {
        "verified_accessible": "Profile-specific page",
        "not_found": "Not found",
        "redirected": "Redirected",
        "access_restricted": "Access restricted",
        "inconclusive": "Unclear",
        "timeout": "Timed out",
        "error": "Could not check",
        "skipped": "Not checked",
    }
    return labels.get(status.casefold(), "Unknown result")


def _verification_status(result: InvestigationResult, profile_url: str) -> str:
    try:
        key = canonical_profile_url(profile_url)
    except ValueError:
        return _url_status_label("skipped")
    for item in result.url_verification_results:
        try:
            if canonical_profile_url(item.original_url.strip()) == key:
                return _url_status_label(item.status.value)
        except ValueError:
            continue
    return _url_status_label("skipped")


def _render_attack_surface(result: InvestigationResult | None) -> None:
    page_header("Exposure overview", "Attack surface assessment", "Evidence-backed summary of observed public footprint. No compromise score is calculated.")
    if not _require_result(result):
        return
    assert result is not None
    assessment = result.attack_surface
    if assessment is None:
        empty_state("Assessment unavailable", "This investigation has no attack-surface assessment record.")
        return
    st.markdown(f"### Overall assessment · {assessment.overall_status.upper()}")
    st.write(assessment.overall_assessment)
    columns = st.columns(5, gap="medium")
    metrics = (
        ("Discovered URLs", assessment.discovered_profile_urls),
        ("Profile-specific accessible", assessment.verified_accessible_profiles),
        ("Inconclusive", assessment.inconclusive_urls),
        ("Failed / skipped", assessment.failed_or_skipped_urls),
        ("Unique identity attributes", assessment.identity_attributes_found),
    )
    for column, (label, value) in zip(columns, metrics):
        with column:
            metric_card(label, value, "Observed in collected evidence")
    st.markdown("#### Exposure categories")
    st.dataframe(attack_surface_category_rows(assessment), hide_index=True, use_container_width=True)
    st.markdown("#### Evidence-backed defensive actions")
    if assessment.recommended_actions:
        for action in assessment.recommended_actions:
            st.markdown(f"- {action}")
    else:
        st.caption("No specific action was generated from the available evidence.")
    st.markdown("#### Limitations")
    for limitation in assessment.evidence_limitations:
        st.caption(limitation)


def _render_threat_analysis(result: InvestigationResult | None) -> None:
    page_header("Defensive review", "Threat analysis", "Explainable exposure indicators derived from collected evidence; no maliciousness score is generated.")
    if not _require_result(result):
        return
    assert result is not None
    if not result.threat_indicators:
        empty_state("No actionable threat indicators", "No actionable threat indicators were identified from the available evidence.")
        return
    st.markdown('<div class="uti-disclaimer">Indicators are leads for defensive review. They do not establish malicious intent, account ownership, or common identity.</div>', unsafe_allow_html=True)
    type_options = sorted({item.indicator_type.value for item in result.threat_indicators})
    severity_options = sorted({item.severity.value for item in result.threat_indicators})
    type_col, severity_col = st.columns(2, gap="medium")
    with type_col:
        selected_types = st.multiselect("Indicator type", type_options, default=type_options, key="uti_threat_type_filter")
    with severity_col:
        selected_severities = st.multiselect("Severity", severity_options, default=severity_options, key="uti_threat_severity_filter")
    filtered = [item for item in result.threat_indicators if item.indicator_type.value in selected_types and item.severity.value in selected_severities]
    if not filtered:
        empty_state("No matching indicators", "Adjust the type or severity filters to review other indicators.")
    for index, indicator in enumerate(filtered, start=1):
        with st.expander(f"{indicator.indicator_type.value.replace('_', ' ').title()} · {indicator.severity.value.upper()}", expanded=index == 1):
            st.write(indicator.description)
            st.caption(f"Severity basis: {indicator.severity_reason}")
            if indicator.supporting_evidence:
                section_label(f"Supporting evidence · {len(indicator.supporting_evidence)}")
                st.caption(" · ".join(indicator.supporting_evidence))
            if indicator.related_identity_attributes:
                section_label("Related identity attributes")
                for attribute_index, attribute in enumerate(indicator.related_identity_attributes, start=1):
                    st.text(f"{attribute.attribute_type.value}: {attribute.original_value}")
                    st.caption(f"Source: {attribute.source_url or 'Unknown'} · {attribute.verification_status.value} · {attribute.association_status.value}")
                    st.caption(attribute.evidence)
            section_label("Source profile URLs")
            for source_index, reference in enumerate(indicator.source_profile_urls or indicator.source_references, start=1):
                st.link_button("Open source profile", reference, key=f"uti_threat_profile_source_{index}_{source_index}")
            if indicator.related_username_findings:
                st.caption("Related username findings (candidate profiles):")
                for finding_index, finding in enumerate(indicator.related_username_findings, start=1):
                    st.link_button(f"{finding.platform} profile", finding.profile_url, key=f"uti_threat_finding_{index}_{finding_index}")
            section_label("Source references")
            for source_index, reference in enumerate(indicator.source_references, start=1):
                st.link_button(
                    "Open source",
                    reference,
                    key=f"uti_threat_evidence_source_{index}_{source_index}",
                )
            st.markdown(f"**Recommended defensive action:** {escape(indicator.recommended_action)}")
            for limitation in indicator.limitations:
                st.caption(limitation)


def _render_recent_activity() -> None:
    history = st.session_state.get(_HISTORY_KEY, [])
    section_label("Recent investigation activity")
    if not history:
        st.caption("Investigation history is available for this session only.")
        return
    rows = [
        {
            "Username": item.username,
            "Started (UTC)": item.investigated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "Findings": len(item.normalized_findings),
            "Deduplicated": len(item.deduplicated_findings),
            "Issues": len(item.warnings) + len(item.errors),
        }
        for _, item in reversed(history[-5:])
    ]
    st.dataframe(rows, hide_index=True, use_container_width=True)


def _render_export_buttons(result: InvestigationResult, *, key_suffix: str) -> None:
    from re import sub

    safe_name = sub(r"[^A-Za-z0-9_-]+", "_", result.username).strip("_") or "investigation"
    first, second, third = st.columns(3, gap="medium")
    with first:
        try:
            full_data = export_investigation_workbook(result)
        except Exception as exc:
            st.error(f"Could not generate the investigation workbook: {exc}")
        else:
            st.download_button(
                "Complete Report · All Sections (.xlsx)", full_data,
                file_name=f"{safe_name}_investigation.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"uti_full_export_{key_suffix}",
                use_container_width=True,
                help="Download the selected investigation, including collector rows, findings, correlations, and diagnostics.",
            )
    with second:
        try:
            findings_data = export_findings_workbook(result)
        except Exception as exc:
            st.error(f"Could not generate the findings workbook: {exc}")
        else:
            st.download_button(
                "Export Findings (.xlsx)", findings_data,
                file_name=f"{safe_name}_findings.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"uti_findings_export_{key_suffix}",
                use_container_width=True,
                help="Download normalized findings, deduplicated findings, and finding diagnostics.",
            )
    with third:
        try:
            identity_data = export_identity_workbook(result)
        except Exception as exc:
            st.error(f"Could not generate the identity workbook: {exc}")
        else:
            st.download_button(
                "Export Identity Intelligence (.xlsx)", identity_data,
                file_name=f"{safe_name}_identity_intelligence.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"uti_identity_export_{key_suffix}",
                use_container_width=True,
                help="Download identity attributes, correlations, threat indicators, and diagnostics for the selected investigation.",
            )


def _render_exports(result: InvestigationResult | None) -> None:
    page_header(
        "Export center", "Investigation reports",
        "Download reports for the selected investigation. The complete report includes findings, identity intelligence, URL checks, threat analysis, attack-surface summary, evidence, and diagnostics. Reports use saved session results and do not rerun collectors.",
    )
    if not _require_result(result):
        return
    assert result is not None
    st.markdown(
        '<div class="uti-disclaimer">All workbooks preserve the unverified ownership state. Profile checks and correlations are candidate evidence only.</div>',
        unsafe_allow_html=True,
    )
    st.markdown("**Complete report · All sections** · Summary, findings, identity intelligence, URL checks, threat analysis, attack-surface summary, evidence, and diagnostics.")
    st.markdown("**Findings workbook** · All findings, deduplicated findings, and finding diagnostics.")
    st.markdown("**Identity Intelligence workbook** · All identity attributes, deduplicated attributes, correlations, threat indicators, and diagnostics.")
    if not result.normalized_findings:
        st.info("This investigation has no findings. All three workbooks remain available with empty result sheets and diagnostics.")
    _render_export_buttons(result, key_suffix="reports")


if __name__ == "__main__":
    main()
