"""In-memory Excel exports for one selected Unified-UTI investigation."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
import json
import re
from typing import Any, Iterable
from io import BytesIO

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from uti.models import Finding, RawCollectorRecord
from uti.services.investigation import InvestigationResult
from uti.identity.models import IdentityAttribute
from uti.identity.presentation import build_profile_intelligence
from uti.utils.urls import canonical_profile_url


_RAW_HEADERS = {
    "sherlock": ("username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"),
    "maigret": ("username", "name", "url_main", "url_user", "exists", "http_status", "error_reason"),
}
_HEADER_FILL = PatternFill("solid", fgColor="163154")
_HEADER_FONT = Font(name="Aptos", bold=True, color="FFFFFF")
_BODY_FONT = Font(name="Aptos", size=10, color="1F2937")
_FORMULA_PREFIX = re.compile(r"^[\s\x00-\x1f]*[=+@-]")


def export_investigation_workbook(result: InvestigationResult) -> bytes:
    """Build the complete investigation workbook without running collectors."""
    _require_result(result)
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    _write_table(summary, ("Metric", "Value"), _summary_rows(result))

    raw_sherlock = [item for item in _all_raw_records(result) if item.collector_name.casefold() == "sherlock"]
    raw_maigret = [item for item in _all_raw_records(result) if item.collector_name.casefold() == "maigret"]
    _write_raw_sheet(workbook.create_sheet("Raw Sherlock"), "sherlock", raw_sherlock)
    _write_raw_sheet(workbook.create_sheet("Raw Maigret"), "maigret", raw_maigret)

    normalized_headers = (
        "Username", "Platform", "Original raw URL", "Original profile URL", "Normalized profile URL",
        "Source tool", "Evidence", "Evidence type", "Original source URL", "HTTP status",
        "Collection timestamp", "Validation status", "Source lineage", "Evidence provenance",
        "Ownership status", "Identity verified",
    )
    _write_table(
        workbook.create_sheet("Normalized Findings"), normalized_headers,
        (_finding_row(finding, _matching_raw_records(result, finding)) for finding in result.normalized_findings),
    )

    deduplicated_headers = (
        "Username", "Platform", "Original raw URLs", "Original profile URL", "Normalized profile URL",
        "Contributing collectors", "Evidence", "Evidence types", "HTTP statuses", "Collection timestamps",
        "Validation status", "Source lineage", "Evidence provenance", "Ownership status", "Identity verified",
    )
    _write_table(
        workbook.create_sheet("Deduplicated Findings"), deduplicated_headers,
        (_deduplicated_row(finding, _matching_raw_records(result, finding)) for finding in result.deduplicated_findings),
    )
    _write_table(
        workbook.create_sheet("Correlations"),
        ("Candidate group", "Candidate members", "Same profile candidate", "Correlation reasons", "Supporting evidence", "Source information", "Independence assessment", "Interpretation"),
        (_correlation_row(index, group) for index, group in enumerate(result.correlation_results, start=1)),
    )
    _write_table(
        workbook.create_sheet("Diagnostics"),
        ("Category", "Collector", "Line", "Message", "Details"),
        _diagnostic_rows(result),
    )
    _write_identity_sheets(workbook, result, deduplicated_title="Dedup Identity Attributes")
    _write_assessment_sheets(workbook, result)
    return _save(workbook)


def export_findings_workbook(result: InvestigationResult) -> bytes:
    """Build a separate three-sheet findings workbook for one investigation."""
    _require_result(result)
    workbook = Workbook()
    headers = (
        "Username", "Platform", "Profile URL", "Original raw URL", "Normalized URL", "Source Tool",
        "Evidence", "Evidence Type", "HTTP Status", "Validation Status", "Collection Timestamp",
        "Source Lineage", "Evidence Provenance", "Ownership Status", "Identity Verified",
    )
    _write_table(
        workbook.active, headers,
        (_all_finding_row(finding, _matching_raw_records(result, finding)) for finding in result.normalized_findings),
    )
    workbook.active.title = "All Findings"
    dedup_headers = (
        "Username", "Platform", "Profile URL", "Original raw URLs", "Normalized URL", "Source Tools",
        "Evidence", "Evidence Types", "HTTP Statuses", "Collection Timestamps", "Validation Status",
        "Source Lineage", "Evidence Provenance", "Ownership Status", "Identity Verified",
    )
    _write_table(
        workbook.create_sheet("Deduplicated Findings"), dedup_headers,
        (_deduplicated_row(finding, _matching_raw_records(result, finding)) for finding in result.deduplicated_findings),
    )
    _write_table(
        workbook.create_sheet("Finding Diagnostics"),
        ("Category", "Collector", "Line", "Message", "Details"),
        _diagnostic_rows(result),
    )
    return _save(workbook)


def export_identity_workbook(result: InvestigationResult) -> bytes:
    """Build the identity evidence, URL verification, and assessment workbook."""
    _require_result(result)
    workbook = Workbook()
    first_sheet = workbook.active
    first_sheet.title = "Profile Intelligence"
    _write_identity_sheets(
        workbook, result, profile_sheet=first_sheet,
        attribute_title="All Identity Attributes",
        deduplicated_title="Dedup Identity Attributes",
    )
    _write_assessment_sheets(workbook, result)
    return _save(workbook)


def _write_identity_sheets(
    workbook: Workbook,
    result: InvestigationResult,
    *,
    profile_sheet: Any = None,
    attribute_title: str = "Identity Attributes",
    deduplicated_title: str = "Deduplicated Identity Attributes",
) -> None:
    _write_table(
        profile_sheet or workbook.create_sheet("Profile Intelligence"),
        (
            "Username", "Platform", "Profile URL", "Display Name", "Publicly Stated Name",
            "Public Email", "Public Phone", "Description / Biography", "Website", "Organization",
            "Coarse Location", "Secondary Username", "Linked Profile", "Job Title",
            "Professional Affiliation", "Technology / Skills", "Collection Status",
            "Verification Status", "Association Status", "URL Verification",
        ),
        _profile_intelligence_rows(result),
    )
    _write_table(
        workbook.create_sheet(attribute_title),
        (
            "Attribute Type", "Original Value", "Normalized Value", "Source URL", "Collection Timestamp",
            "Evidence", "Evidence Type", "Source Tool", "Source Lineage", "Evidence Provenance",
            "Verification Status", "Association Status", "Sensitivity", "Associated Username", "Warnings",
        ),
        (_identity_attribute_row(item) for item in result.identity_attributes),
    )
    _write_table(
        workbook.create_sheet(deduplicated_title),
        (
            "Attribute Type", "Normalized Value", "Original Values", "Source URLs", "Collection Timestamps",
            "Evidence", "Source Tools", "Source Lineage", "Evidence Provenance", "Verification Statuses",
            "Association Statuses", "Sensitivity",
        ),
        (_deduplicated_identity_row(item) for item in result.deduplicated_identity_attributes),
    )
    _write_table(
        workbook.create_sheet("Profile URL Collection Audit"),
        (
            "Username", "Platform", "Original Profile URLs", "Canonical Profile URL", "Discovered By",
            "Collection Attempted", "Fetch Status", "HTTP Status", "Collection Timestamp",
            "Extracted Attribute Count", "Error or Warning", "Reason Skipped",
        ),
        (_profile_audit_row(item) for item in result.profile_url_audits),
    )
    _write_table(
        workbook.create_sheet("Identity Correlations"),
        (
            "Attribute Type", "Matched Value", "Candidate Sources", "Correlation Reason", "Source Independence",
            "Association Status", "Supporting Evidence", "Source Lineage", "Interpretation",
        ),
        (_identity_correlation_row(item) for item in result.identity_correlations),
    )
    _write_table(
        workbook.create_sheet("Threat Indicators"),
        (
            "Indicator Type", "Description", "Severity", "Severity Reason", "Supporting Evidence",
            "Source References", "Source Profile URLs", "Affected Attributes", "Related Username Findings",
            "Recommended Action", "Limitations",
        ),
        (_threat_indicator_row(item) for item in result.threat_indicators),
    )
    _write_table(
        workbook.create_sheet("Identity Diagnostics"),
        ("Collector", "Level", "Message", "Source URL", "Line", "Details"),
        (
            (item.collector_name, item.level.value, item.message, item.source_url or "", item.line_number or "", item.details or "")
            for item in result.identity_diagnostics
        ),
    )


def _write_assessment_sheets(workbook: Workbook, result: InvestigationResult) -> None:
    _write_table(
        workbook.create_sheet("URL Verification"),
        ("Username", "Platform", "Original URL", "Final URL", "Discovering Collectors", "Status", "HTTP Status", "Profile Specific", "Page Title", "Page Metadata", "Verified At UTC", "Source Lineage", "Reason"),
        ((
            item.username, item.platform, item.original_url, item.final_url or "",
            ", ".join(item.discovering_collectors), item.status.value, item.http_status,
            item.profile_specific, item.page_title or "", _json(item.page_metadata),
            item.verified_at.isoformat(), _json(item.source_lineage), item.reason,
        ) for item in result.url_verification_results),
    )
    assessment = result.attack_surface
    rows = []
    if assessment is not None:
        rows.extend((
            ("Overall status", assessment.overall_status),
            ("Overall assessment", assessment.overall_assessment),
            ("Discovered profile URLs", assessment.discovered_profile_urls),
            ("Unique eligible profile URLs", assessment.unique_eligible_profile_urls),
            ("Verified accessible profiles", assessment.verified_accessible_profiles),
            ("Inconclusive URLs", assessment.inconclusive_urls),
            ("Failed or skipped URLs", assessment.failed_or_skipped_urls),
            ("Distinct identity attributes", assessment.identity_attributes_found),
            ("Public contact indicators", assessment.public_contact_indicators),
            ("Developer/technology indicators", assessment.developer_technology_indicators),
            ("Professional information", assessment.professional_information_indicators),
            ("Websites/domains", assessment.public_websites_and_domains),
            ("Supported correlations", assessment.supported_correlations),
            ("Threat indicators", assessment.generated_threat_indicators),
        ))
        rows.extend((f"Category: {name}", count) for name, count in assessment.category_summaries)
        rows.extend(("Recommended action", item) for item in assessment.recommended_actions)
        rows.extend(("Limitation", item) for item in assessment.evidence_limitations)
        rows.append(("Numeric exposure score", "Not implemented; evidence is summarized without probability claims"))
    _write_table(workbook.create_sheet("Attack Surface Assessment"), ("Assessment item", "Value"), rows)


def _require_result(result: InvestigationResult) -> None:
    if not isinstance(result, InvestigationResult):
        raise TypeError("result must be an InvestigationResult")


def _save(workbook: Workbook) -> bytes:
    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _write_raw_sheet(sheet: Any, collector: str, records: list[RawCollectorRecord]) -> None:
    headers = list(records[0].headers) if records else list(_RAW_HEADERS[collector])
    header_row = ["CSV line", *headers]
    if records and any(record.extra_values for record in records):
        header_row.append("Extra cells")
    rows = []
    for record in records:
        values = list(record.values[:len(headers)])
        values.extend([None] * (len(headers) - len(values)))
        row: list[Any] = [record.line_number, *values]
        if "Extra cells" in header_row:
            row.append(" | ".join(record.extra_values))
        rows.append(row)
    _write_table(sheet, header_row, rows)


def _write_table(sheet: Any, headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> None:
    header_values = list(headers)
    sheet.append([_safe_value(value) for value in header_values])
    for row in rows:
        sheet.append([_safe_value(value) for value in row])
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(max(1, len(header_values)))}{max(1, sheet.max_row)}"
    for cell in sheet[1]:
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    sheet.row_dimensions[1].height = 30
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.font = _BODY_FONT
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if isinstance(cell.value, datetime):
                cell.number_format = "yyyy-mm-dd hh:mm:ss UTC"
    for column_cells in sheet.columns:
        column = get_column_letter(column_cells[0].column)
        max_length = max((len(str(cell.value)) if cell.value is not None else 0 for cell in column_cells), default=10)
        sheet.column_dimensions[column].width = min(max(max_length + 2, 13), 52)
    sheet.sheet_view.showGridLines = False


def _safe_value(value: Any) -> Any:
    """Keep untrusted text literal so spreadsheet applications do not execute it."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, str) and value != "-" and _FORMULA_PREFIX.match(value):
        return "'" + value
    if value is None or isinstance(value, (str, int, float, bool, datetime)):
        return value
    return _json(value)


def _json(value: Any) -> str:
    return json.dumps(value, default=_json_default, ensure_ascii=False, sort_keys=True)


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    return str(value)


def _all_raw_records(result: InvestigationResult) -> tuple[RawCollectorRecord, ...]:
    return tuple(record for summary in result.collector_summaries for record in summary.raw_records)


def _matching_raw_records(result: InvestigationResult, finding: Finding) -> tuple[RawCollectorRecord, ...]:
    tools = {tool.casefold() for tool in finding.source_tools}
    canonical = canonical_profile_url(finding.profile_url)
    return tuple(
        record for record in _all_raw_records(result)
        if record.collector_name.casefold() in tools
        and _record_value(record, "username").strip() == finding.username
        and _record_value(record, "name").strip() == finding.platform
        and _canonical_or_none(_record_value(record, "url_user").strip()) == canonical
    )


def _record_value(record: RawCollectorRecord, name: str) -> str:
    for header, value in record.as_mapping().items():
        if header.strip().casefold() == name.casefold():
            return value or ""
    return ""


def _canonical_or_none(url: str) -> str | None:
    try:
        return canonical_profile_url(url)
    except ValueError:
        return None


def _profile_url_values(finding: Finding, records: tuple[RawCollectorRecord, ...]) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(_record_value(record, "url_user") for record in records))
    return values


def _source_lineage(finding: Finding) -> str:
    return _json(finding.source_lineage)


def _evidence_provenance(finding: Finding) -> str:
    return _json(finding.evidence_provenance)


def _evidence_types(finding: Finding) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.evidence_type for item in finding.evidence_provenance))


def _http_statuses(records: tuple[RawCollectorRecord, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in (_record_value(item, "http_status") for item in records) if value))


def _all_finding_row(finding: Finding, records: tuple[RawCollectorRecord, ...]) -> tuple[Any, ...]:
    original_urls = _profile_url_values(finding, records)
    return (
        finding.username, finding.platform, finding.profile_url,
        " | ".join(original_urls), canonical_profile_url(finding.profile_url), finding.source_tool,
        " | ".join(finding.evidence), " | ".join(_evidence_types(finding)),
        " | ".join(_http_statuses(records)), finding.validation_status.value,
        finding.collected_at.isoformat(), _source_lineage(finding), _evidence_provenance(finding),
        finding.ownership_status.value, finding.identity_verified,
    )


def _finding_row(finding: Finding, records: tuple[RawCollectorRecord, ...]) -> tuple[Any, ...]:
    row = _all_finding_row(finding, records)
    return (
        row[0], row[1], row[3], row[2], row[4], row[5], row[6], row[7],
        " | ".join(item.original_source_url or "" for item in finding.evidence_provenance),
        row[8], row[10], row[9], row[11], row[12], row[13], row[14],
    )


def _deduplicated_row(finding: Finding, records: tuple[RawCollectorRecord, ...]) -> tuple[Any, ...]:
    original_urls = _profile_url_values(finding, records)
    http_statuses = _http_statuses(records)
    return (
        finding.username, finding.platform, finding.profile_url, " | ".join(original_urls),
        canonical_profile_url(finding.profile_url), ", ".join(finding.source_tools),
        " | ".join(finding.evidence), " | ".join(_evidence_types(finding)), " | ".join(http_statuses),
        finding.collected_at.isoformat(), finding.validation_status.value, _source_lineage(finding),
        _evidence_provenance(finding), finding.ownership_status.value, finding.identity_verified,
    )


def _summary_rows(result: InvestigationResult) -> Iterable[tuple[str, Any]]:
    summaries = {item.collector_name.casefold(): item for item in result.collector_summaries}
    for name in ("sherlock", "maigret"):
        summary = summaries.get(name)
        status = "Not run" if summary is None else (
            "Timed out" if summary.timed_out else "Error" if summary.error else
            "Complete" if summary.returncode == 0 else f"Exit {summary.returncode}"
        )
        yield (f"{name.title()} status", status)
        yield (f"{name.title()} findings count", summary.findings_count if summary else 0)
    yield ("Investigated username", result.username)
    yield ("Investigation timestamp (UTC)", result.investigated_at.isoformat())
    yield ("Total collector findings", sum(item.findings_count for item in result.collector_summaries))
    yield ("Normalized findings count", len(result.normalized_findings))
    yield ("Deduplicated findings count", len(result.deduplicated_findings))
    yield ("Correlations count", len(result.correlation_results))
    yield ("Ownership verification status", "UNVERIFIED")
    yield ("Identity verified", False)
    yield ("Warnings", "\n".join(result.warnings))
    yield ("Errors", "\n".join(result.errors))
    yield ("Identity collection enabled", result.identity_collection_enabled)
    yield ("Identity attributes", len(result.identity_attributes))
    yield ("Deduplicated identity attributes", len(result.deduplicated_identity_attributes))
    yield ("Identity correlations", len(result.identity_correlations))
    yield ("Threat indicators", len(result.threat_indicators))
    yield ("URL verification records", len(result.url_verification_results))
    if result.attack_surface is not None:
        yield ("Attack surface status", result.attack_surface.overall_status)
        yield ("Attack surface assessment", result.attack_surface.overall_assessment)


def _correlation_row(index: int, group: Any) -> tuple[Any, ...]:
    members = [f"{item.platform}: {item.profile_url} [{', '.join(item.source_tools)}]" for item in group.findings]
    evidence = [
        {"type": item.evidence_type, "value": item.value, "independence": item.independence.value}
        for item in group.shared_evidence
    ]
    sources = [lineage for finding in group.findings for lineage in finding.source_lineage]
    independence = ", ".join(sorted({item.independence.value for item in group.shared_evidence})) or "unknown"
    return (
        index, "\n".join(members), group.same_profile_candidate, "\n".join(group.reasons),
        _json(evidence), _json(sources), independence, group.interpretation,
    )


def _diagnostic_rows(result: InvestigationResult) -> Iterable[tuple[Any, ...]]:
    for warning in result.warnings:
        yield ("Warning", "", "", warning, "")
    for error in result.errors:
        yield ("Error", "", "", error, "")
    for summary in result.collector_summaries:
        if summary.error:
            yield ("Collector error", summary.collector_name, "", summary.error, f"returncode={summary.returncode}; timed_out={summary.timed_out}")
        for warning in summary.warnings:
            yield ("Parsing warning", summary.collector_name, "", warning, "")
        for diagnostic in summary.diagnostics:
            details = asdict(diagnostic) if is_dataclass(diagnostic) else diagnostic
            yield (
                "Collector diagnostic", summary.collector_name, getattr(diagnostic, "line_number", ""),
                getattr(diagnostic, "message", None) or getattr(diagnostic, "outcome", "diagnostic"), _json(details),
            )
    for assessment in result.assessments:
        missing = assessment.record_completeness.missing_fields
        unknown = assessment.record_completeness.unknown_fields
        if missing or unknown:
            yield (
                "Finding completeness", assessment.finding.source_tool, "",
                f"{assessment.finding.platform} {assessment.finding.profile_url}",
                _json({"missing": missing, "unknown": unknown}),
            )
    for diagnostic in result.identity_diagnostics:
        yield (
            "Identity diagnostic", diagnostic.collector_name, diagnostic.line_number or "",
            diagnostic.message, _json({"level": diagnostic.level.value, "source_url": diagnostic.source_url, "details": diagnostic.details}),
        )


def _identity_attribute_row(item: IdentityAttribute) -> tuple[Any, ...]:
    return (
        item.attribute_type.value, item.original_value, item.normalized_value, item.source_url or "",
        item.collected_at.isoformat(), item.evidence, item.evidence_type, item.source_tool,
        _json(item.source_lineage), _json(item.evidence_provenance), item.verification_status.value,
        item.association_status.value, item.sensitivity.value, item.associated_username or "",
        " | ".join(item.warnings),
    )


def _profile_intelligence_rows(result: InvestigationResult) -> Iterable[tuple[Any, ...]]:
    types_by_column = (
        ("display_name",), ("publicly_stated_name",), ("email",), ("phone",),
        ("bio",), ("website", "domain"), ("organization",), ("coarse_location",),
        ("secondary_username",), ("social_profile",), ("job_title",),
        ("professional_affiliation",), ("technology", "skill"),
    )
    for record in build_profile_intelligence(
        result.deduplicated_findings, result.identity_attributes, result.profile_url_audits,
    ):
        values = []
        for type_names in types_by_column:
            matching = tuple(dict.fromkeys(
                item.original_value for item in record.attributes
                if item.attribute_type.value in type_names
            ))
            values.append("\n".join(matching) if matching else "-")
        audit = record.collection_audit
        yield (
            record.finding.username, record.finding.platform, record.finding.profile_url,
            *values,
            audit.fetch_status.value.upper() if audit else "DISCOVERED",
            ", ".join(sorted({item.verification_status.value for item in record.attributes}) or {"unknown"}),
            ", ".join(sorted({item.association_status.value for item in record.attributes}) or {"unknown"}),
            _verification_status(result, record.finding.profile_url),
        )


def _verification_status(result: InvestigationResult, profile_url: str) -> str:
    key = canonical_profile_url(profile_url)
    for item in result.url_verification_results:
        try:
            if canonical_profile_url(item.original_url.strip()) == key:
                return item.status.value.upper()
        except ValueError:
            continue
    return "SKIPPED"


def _profile_audit_row(item: Any) -> tuple[Any, ...]:
    return (
        item.username, item.platform, " | ".join(item.original_profile_urls), item.canonical_profile_url or "",
        ", ".join(item.discovery_collectors), item.identity_collection_attempted, item.fetch_status.value,
        item.http_status, item.collected_at.isoformat(), item.extracted_attribute_count,
        item.error_or_warning or "", item.reason_skipped or "",
    )


def _deduplicated_identity_row(item: Any) -> tuple[Any, ...]:
    observations = item.observations
    return (
        item.attribute_type.value, item.normalized_value,
        _json(tuple(observation.original_value for observation in observations)),
        _json(tuple(observation.source_url for observation in observations)),
        _json(tuple(observation.collected_at for observation in observations)),
        _json(tuple(observation.evidence for observation in observations)),
        _json(tuple(observation.source_tool for observation in observations)),
        _json(tuple(lineage for observation in observations for lineage in observation.source_lineage)),
        _json(tuple(provenance for observation in observations for provenance in observation.evidence_provenance)),
        _json(tuple(observation.verification_status.value for observation in observations)),
        _json(tuple(observation.association_status.value for observation in observations)),
        _json(tuple(observation.sensitivity.value for observation in observations)),
    )


def _identity_correlation_row(item: Any) -> tuple[Any, ...]:
    return (
        item.attribute_type.value, item.normalized_value,
        _json(tuple({"collector": observation.source_tool, "source_url": observation.source_url} for observation in item.observations)),
        item.reason, item.source_independence.value, item.association_status.value,
        _json(item.supporting_evidence), _json(item.source_lineage), item.interpretation,
    )


def _threat_indicator_row(item: Any) -> tuple[Any, ...]:
    return (
        item.indicator_type.value, item.description, item.severity.value, item.severity_reason,
        _json(item.supporting_evidence), _json(item.source_references),
        _json(item.source_profile_urls), _json(item.affected_attributes),
        _json(tuple(finding.profile_url for finding in item.related_username_findings)),
        item.recommended_action, _json(item.limitations),
    )


__all__ = ["export_findings_workbook", "export_identity_workbook", "export_investigation_workbook"]
