"""Safe subprocess adapter for Maigret's CSV result output."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
import io
import math
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from uti.collectors.sherlock import _as_text, _resolve_executable, _validate_timeout, _validate_username_for_output
from uti.models import (
    EvidenceProvenance,
    Finding,
    OwnershipVerificationStatus,
    RawCollectorRecord,
    SourceLineage,
    ValidationStatus,
)
from uti.utils.urls import canonical_profile_url


_EXPECTED_COLUMNS = {
    "username",
    "name",
    "url_main",
    "url_user",
    "exists",
    "http_status",
    "error_reason",
}


class MaigretOutputError(ValueError):
    """Raised when Maigret output has a malformed CSV document or schema."""

    def __init__(self, message: str, raw_records: Iterable[RawCollectorRecord] = ()) -> None:
        super().__init__(message)
        self.raw_records = tuple(raw_records)


@dataclass(frozen=True, slots=True)
class MaigretDiagnostic:
    """A Maigret row that does not produce a candidate Finding."""

    username: str
    platform: str
    profile_url: str
    status: str
    http_status: str
    error_reason: str
    line_number: int
    message: str | None = None

    @property
    def outcome(self) -> str:
        """Return a stable meaning for the Maigret status or row issue."""
        known_outcomes = {
            "available": "not_found",
            "unknown": "inconclusive",
            "illegal": "invalid_username",
        }
        if self.message:
            if self.message.startswith("invalid profile URL"):
                return "invalid_profile_url"
            return "invalid_row"
        return known_outcomes.get(self.status.casefold(), "unrecognized_status")


class MaigretCsvFindings(tuple):
    """Tuple-compatible candidate findings with row diagnostics and warnings."""

    warnings: tuple[str, ...]
    diagnostics: tuple[MaigretDiagnostic, ...]
    raw_records: tuple[RawCollectorRecord, ...]

    def __new__(
        cls,
        findings: Iterable[Finding] = (),
        warnings: Iterable[str] = (),
        diagnostics: Iterable[MaigretDiagnostic] = (),
        raw_records: Iterable[RawCollectorRecord] = (),
    ) -> MaigretCsvFindings:
        result = super().__new__(cls, findings)
        result.warnings = tuple(warnings)
        result.diagnostics = tuple(diagnostics)
        result.raw_records = tuple(raw_records)
        return result


@dataclass(frozen=True, slots=True)
class MaigretRunResult:
    """Candidate findings and process/row diagnostics for one Maigret run."""

    username: str
    findings: tuple[Finding, ...]
    stdout: str
    stderr: str
    returncode: int | None
    error: str | None = None
    timed_out: bool = False
    warnings: tuple[str, ...] = ()
    diagnostics: tuple[MaigretDiagnostic, ...] = ()
    raw_records: tuple[RawCollectorRecord, ...] = ()


def parse_maigret_csv(
    content: str,
    *,
    queried_username: str,
    collected_at: datetime | None = None,
) -> MaigretCsvFindings:
    """Parse the Maigret CSV schema, returning only ``Claimed`` candidates.

    Non-claimed statuses are retained as diagnostics. Invalid individual rows
    are skipped with warnings; malformed CSV syntax and incompatible headers
    reject the document. A claimed profile result never verifies ownership.
    """
    if not isinstance(content, str):
        raise MaigretOutputError("CSV content must be text")
    if not isinstance(queried_username, str) or not queried_username.strip():
        raise ValueError("queried_username must be a non-empty string")

    timestamp = collected_at or datetime.now(timezone.utc)
    lineage = SourceLineage(
        collector_name="maigret",
        underlying_data_source=None,
        collection_method="Maigret CLI site-specific checks; CSV export",
    )
    findings: list[Finding] = []
    warnings: list[str] = []
    diagnostics: list[MaigretDiagnostic] = []
    raw_records: list[RawCollectorRecord] = []
    try:
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        raw_headers = reader.fieldnames or ()
        normalized = [str(header).strip().lstrip("\ufeff").casefold() for header in raw_headers]
        if set(normalized) != _EXPECTED_COLUMNS:
            missing = sorted(_EXPECTED_COLUMNS - set(normalized))
            unexpected = sorted(set(normalized) - _EXPECTED_COLUMNS)
            details = []
            if missing:
                details.append(f"missing columns: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected columns: {', '.join(unexpected)}")
            raise MaigretOutputError("Maigret CSV schema mismatch (" + "; ".join(details) + ")")
        if len(set(normalized)) != len(normalized):
            raise MaigretOutputError("Maigret CSV contains duplicate column names")
        header_map = dict(zip(normalized, raw_headers))

        for row in reader:
            line_number = reader.line_num
            extras = row.get(None)
            raw_records.append(
                RawCollectorRecord(
                    collector_name="maigret",
                    line_number=line_number,
                    headers=tuple(str(header) for header in raw_headers),
                    values=tuple(row.get(header) for header in raw_headers),
                    extra_values=tuple(extras) if isinstance(extras, list) else (),
                )
            )
            raw_values = {name: row.get(header_map[name]) for name in _EXPECTED_COLUMNS}
            username = (raw_values["username"] or "").strip()
            platform = (raw_values["name"] or "").strip()
            profile_url = (raw_values["url_user"] or "").strip()
            status_text = (raw_values["exists"] or "").strip()
            http_status = (raw_values["http_status"] or "").strip()
            error_reason = (raw_values["error_reason"] or "").strip()

            row_problem: str | None = None
            if None in row:
                row_problem = "row contains more fields than the CSV header"
            elif any(value is None for value in raw_values.values()):
                row_problem = "row is missing one or more CSV fields"
            elif not any((value or "").strip() for value in raw_values.values()):
                continue
            elif username != queried_username:
                row_problem = f"username {username!r} does not match requested username"
            elif not platform:
                row_problem = "platform name is empty"
            elif not raw_values["url_main"] or not raw_values["url_main"].strip():
                row_problem = "site URL is empty"
            elif not status_text:
                row_problem = "status is empty"

            if row_problem:
                warnings.append(f"Skipped Maigret CSV line {line_number}: {row_problem}")
                diagnostics.append(
                    MaigretDiagnostic(username, platform, profile_url, status_text, http_status, error_reason, line_number, row_problem)
                )
                continue

            # Maigret's non-positive statuses may legitimately omit url_user.
            # Interpret the status first and retain their raw URL (including
            # an empty value) in diagnostics without URL validation.
            normalized_status = status_text.casefold()
            if normalized_status != "claimed":
                diagnostics.append(
                    MaigretDiagnostic(username, platform, profile_url, status_text, http_status, error_reason, line_number)
                )
                continue

            # A candidate Finding is only meaningful when Maigret supplied a
            # non-empty, strictly valid profile URL.
            try:
                canonical_profile_url(profile_url)
            except ValueError as exc:
                message = f"invalid profile URL {profile_url!r}: {exc}"
                warnings.append(f"Skipped Maigret CSV line {line_number}: {message}")
                diagnostics.append(
                    MaigretDiagnostic(username, platform, profile_url, status_text, http_status, error_reason, line_number, message)
                )
                continue

            evidence_value = (
                f"Maigret candidate: status={status_text}; platform={platform}; "
                f"http_status={http_status or 'unknown'}; error_reason={error_reason or 'none'}; "
                "ownership=unverified"
            )
            evidence = EvidenceProvenance(
                value=evidence_value,
                evidence_type="maigret_presence_report",
                source_lineage=lineage,
                original_source_url=profile_url,
            )
            findings.append(
                Finding(
                    username=username,
                    platform=platform,
                    profile_url=profile_url,
                    source_tool="maigret",
                    collected_at=timestamp,
                    evidence=(evidence_value,),
                    validation_status=ValidationStatus.VALID,
                    source_lineage=(lineage,),
                    evidence_provenance=(evidence,),
                    ownership_status=OwnershipVerificationStatus.UNVERIFIED,
                )
            )
    except MaigretOutputError as exc:
        exc.raw_records = tuple(raw_records)
        raise
    except csv.Error as exc:
        raise MaigretOutputError(f"could not parse Maigret CSV: {exc}", raw_records) from exc

    return MaigretCsvFindings(findings, warnings, diagnostics, raw_records)


class MaigretCollector:
    """Run Maigret with safe arguments and parse its per-user CSV report."""

    def __init__(
        self,
        executable: str | os.PathLike[str] = "maigret",
        *,
        timeout_seconds: float = 600.0,
        request_timeout_seconds: float = 30.0,
        max_connections: int = 20,
    ) -> None:
        _validate_timeout(timeout_seconds, "timeout_seconds")
        _validate_timeout(request_timeout_seconds, "request_timeout_seconds")
        if isinstance(max_connections, bool) or not isinstance(max_connections, int) or max_connections <= 0:
            raise ValueError("max_connections must be a positive integer")
        self.executable = os.fspath(executable)
        if not self.executable.strip() or "\x00" in self.executable:
            raise ValueError("executable must not be empty")
        self.timeout_seconds = float(timeout_seconds)
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.max_connections = max_connections

    def collect(self, username: str) -> MaigretRunResult:
        """Run Maigret for a username; results remain unverified candidates."""
        _validate_username_for_output(username)
        started_at = datetime.now(timezone.utc)
        stdout = ""
        stderr = ""
        returncode: int | None = None
        errors: list[str] = []
        warnings: list[str] = []
        diagnostics: tuple[MaigretDiagnostic, ...] = ()
        raw_records: tuple[RawCollectorRecord, ...] = ()
        findings: tuple[Finding, ...] = ()
        timed_out = False

        try:
            with TemporaryDirectory(prefix="uti-maigret-") as output_dir:
                output_path = Path(output_dir) / f"report_{username}.csv"
                command = [
                    _resolve_executable(self.executable),
                    "--csv",
                    "--json",
                    "simple",
                    "--folderoutput",
                    output_dir,
                    "--no-autoupdate",
                    "--no-recursion",
                    "--timeout",
                    f"{self.request_timeout_seconds:g}",
                    "--max-connections",
                    str(self.max_connections),
                    "--",
                    username,
                ]
                try:
                    completed = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=self.timeout_seconds,
                        check=False,
                        shell=False,
                        cwd=output_dir,
                    )
                    stdout = completed.stdout or ""
                    stderr = completed.stderr or ""
                    returncode = completed.returncode
                    if returncode != 0:
                        errors.append(f"Maigret exited with status {returncode}")
                except subprocess.TimeoutExpired as exc:
                    stdout = _as_text(exc.stdout)
                    stderr = _as_text(exc.stderr)
                    timed_out = True
                    errors.append(f"Maigret exceeded the {self.timeout_seconds:g}-second timeout")
                except (FileNotFoundError, PermissionError, OSError, subprocess.SubprocessError, ValueError) as exc:
                    errors.append(f"could not execute Maigret: {exc}")

                if output_path.is_file():
                    try:
                        parsed = parse_maigret_csv(
                            output_path.read_text(encoding="utf-8-sig"),
                            queried_username=username,
                            collected_at=started_at,
                        )
                        findings = tuple(parsed)
                        warnings.extend(parsed.warnings)
                        diagnostics = parsed.diagnostics
                        raw_records = parsed.raw_records
                    except (OSError, UnicodeError, MaigretOutputError, ValueError) as exc:
                        errors.append(f"could not parse Maigret CSV output: {exc}")
                        raw_records = tuple(getattr(exc, "raw_records", ()))
                elif not errors:
                    errors.append("Maigret did not create its expected CSV output file")
        except OSError as exc:
            errors.append(f"could not prepare Maigret output directory: {exc}")

        return MaigretRunResult(
            username=username,
            findings=findings,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            error="; ".join(errors) if errors else None,
            timed_out=timed_out,
            warnings=tuple(warnings),
            diagnostics=diagnostics,
            raw_records=raw_records,
        )


__all__ = [
    "MaigretCollector",
    "MaigretCsvFindings",
    "MaigretDiagnostic",
    "MaigretOutputError",
    "MaigretRunResult",
    "parse_maigret_csv",
]
