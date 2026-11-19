"""Safe subprocess adapter for Sherlock's documented CSV result output."""

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
    "response_time_s",
}
_STATUSES = {
    "claimed": ValidationStatus.VALID,
    "available": ValidationStatus.INVALID,
    "unknown": ValidationStatus.ERROR,
    "illegal": ValidationStatus.ERROR,
    "waf": ValidationStatus.ERROR,
}


class SherlockOutputError(ValueError):
    """Raised when Sherlock's CSV output does not match its documented schema."""

    def __init__(self, message: str, raw_records: Iterable[RawCollectorRecord] = ()) -> None:
        super().__init__(message)
        self.raw_records = tuple(raw_records)


class SherlockCsvFindings(tuple):
    """Tuple-compatible parsed findings with warnings for skipped data rows."""

    warnings: tuple[str, ...]
    raw_records: tuple[RawCollectorRecord, ...]

    def __new__(
        cls,
        findings: Iterable[Finding] = (),
        warnings: Iterable[str] = (),
        raw_records: Iterable[RawCollectorRecord] = (),
    ) -> SherlockCsvFindings:
        result = super().__new__(cls, findings)
        result.warnings = tuple(warnings)
        result.raw_records = tuple(raw_records)
        return result


@dataclass(frozen=True, slots=True)
class SherlockRunResult:
    """Findings and complete process diagnostics from one Sherlock invocation."""

    username: str
    findings: tuple[Finding, ...]
    stdout: str
    stderr: str
    returncode: int | None
    error: str | None = None
    timed_out: bool = False
    warnings: tuple[str, ...] = ()
    raw_records: tuple[RawCollectorRecord, ...] = ()


def parse_sherlock_csv(
    content: str,
    *,
    queried_username: str,
    collected_at: datetime | None = None,
) -> SherlockCsvFindings:
    """Parse Sherlock's documented ``--csv`` report into normalized findings.

    Sherlock's CSV report has the columns ``username``, ``name``, ``url_main``,
    ``url_user``, ``exists``, ``http_status``, and ``response_time_s``. The
    ``exists`` field describes Sherlock's detection result; a ``Claimed`` row
    is only a lead and does not establish account ownership or identity.
    """
    if not isinstance(content, str):
        raise SherlockOutputError("CSV content must be text")
    if not queried_username or not queried_username.strip():
        raise ValueError("queried_username must be a non-empty string")

    timestamp = collected_at or datetime.now(timezone.utc)
    lineage = SourceLineage(
        collector_name="sherlock",
        underlying_data_source=None,
        collection_method="Sherlock CLI site-specific HTTP checks; CSV export",
    )
    findings: list[Finding] = []
    warnings: list[str] = []
    raw_records: list[RawCollectorRecord] = []
    try:
        reader = csv.DictReader(io.StringIO(content, newline=""), strict=True)
        headers = {str(header).strip().lstrip("\ufeff").casefold() for header in (reader.fieldnames or ())}
        if headers != _EXPECTED_COLUMNS:
            missing = sorted(_EXPECTED_COLUMNS - headers)
            unexpected = sorted(headers - _EXPECTED_COLUMNS)
            details = []
            if missing:
                details.append(f"missing columns: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected columns: {', '.join(unexpected)}")
            raise SherlockOutputError("Sherlock CSV schema mismatch (" + "; ".join(details) + ")")

        # Resolve column-name case/spacing variations while retaining Sherlock's
        # documented names as the schema contract.
        header_map = {str(header).strip().lstrip("\ufeff").casefold(): header for header in reader.fieldnames or ()}
        if len(header_map) != len(reader.fieldnames or ()):
            raise SherlockOutputError("Sherlock CSV contains duplicate column names")
        for row in reader:
            line_number = reader.line_num
            extras = row.get(None)
            raw_records.append(
                RawCollectorRecord(
                    collector_name="sherlock",
                    line_number=line_number,
                    headers=tuple(str(header) for header in (reader.fieldnames or ())),
                    values=tuple(row.get(header) for header in (reader.fieldnames or ())),
                    extra_values=tuple(extras) if isinstance(extras, list) else (),
                )
            )
            if None in row:
                raise SherlockOutputError(f"malformed Sherlock CSV row at line {line_number}")
            if any(row.get(header_map[name]) is None for name in _EXPECTED_COLUMNS):
                raise SherlockOutputError(f"incomplete Sherlock CSV row at line {line_number}")
            values = {name: (row.get(header_map[name]) or "").strip() for name in _EXPECTED_COLUMNS}
            if not any(values.values()):
                continue
            row_username = values["username"]
            if row_username != queried_username:
                raise SherlockOutputError(
                    f"CSV row {line_number} username {row_username!r} does not match requested username"
                )
            site_name = values["name"]
            profile_url = values["url_user"]
            try:
                canonical_profile_url(profile_url)
            except ValueError as exc:
                warnings.append(
                    f"Skipped Sherlock CSV line {line_number}: invalid profile URL "
                    f"{profile_url!r}: {exc}"
                )
                continue
            status_text = values["exists"].casefold()
            status = _STATUSES.get(status_text)
            if status is None:
                raise SherlockOutputError(f"unrecognized Sherlock status {values['exists']!r} at line {line_number}")
            for required_value in ("url_main", "http_status"):
                if not values[required_value]:
                    raise SherlockOutputError(f"missing {required_value} at line {line_number}")

            evidence_value = (
                f"Sherlock candidate: status={values['exists']}; platform={site_name}; "
                f"http_status={values['http_status'] or 'unknown'}; "
                f"response_time_s={values['response_time_s'] or 'unknown'}; ownership=unverified"
            )
            evidence = EvidenceProvenance(
                value=evidence_value,
                evidence_type="sherlock_presence_report",
                source_lineage=lineage,
                original_source_url=profile_url,
            )
            findings.append(
                Finding(
                    username=row_username,
                    platform=site_name,
                    profile_url=profile_url,
                    source_tool="sherlock",
                    collected_at=timestamp,
                    evidence=(evidence_value,),
                    validation_status=status,
                    source_lineage=(lineage,),
                    evidence_provenance=(evidence,),
                    ownership_status=OwnershipVerificationStatus.UNVERIFIED,
                )
            )
    except SherlockOutputError as exc:
        exc.raw_records = tuple(raw_records)
        raise
    except csv.Error as exc:
        raise SherlockOutputError(f"could not parse Sherlock CSV: {exc}", raw_records) from exc
    return SherlockCsvFindings(findings, warnings, raw_records)


class SherlockCollector:
    """Invoke Sherlock safely and parse its CSV result file.

    The executable is configurable by path or command name. No command shell
    is used, and each run gets an isolated temporary output directory.
    """

    def __init__(
        self,
        executable: str | os.PathLike[str] = "sherlock",
        *,
        timeout_seconds: float = 600.0,
        request_timeout_seconds: float = 10.0,
    ) -> None:
        _validate_timeout(timeout_seconds, "timeout_seconds")
        _validate_timeout(request_timeout_seconds, "request_timeout_seconds")
        self.executable = os.fspath(executable)
        if not self.executable.strip() or "\x00" in self.executable:
            raise ValueError("executable must not be empty")
        self.timeout_seconds = float(timeout_seconds)
        self.request_timeout_seconds = float(request_timeout_seconds)

    def collect(self, username: str) -> SherlockRunResult:
        """Run Sherlock for one username and return findings plus diagnostics.

        The adapter does not assert ownership. Callers should use authorized
        test accounts and review all returned candidates.
        """
        _validate_username_for_output(username)
        started_at = datetime.now(timezone.utc)
        stdout = ""
        stderr = ""
        returncode: int | None = None
        errors: list[str] = []
        warnings: list[str] = []
        raw_records: tuple[RawCollectorRecord, ...] = ()
        timed_out = False

        try:
            with TemporaryDirectory(prefix="uti-sherlock-") as output_dir:
                output_path = Path(output_dir) / f"{username}.csv"
                command = [
                    _resolve_executable(self.executable),
                    "--csv",
                    "--no-color",
                    "--print-found",
                    "--timeout",
                    f"{self.request_timeout_seconds:g}",
                    "--folderoutput",
                    output_dir,
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
                        errors.append(f"Sherlock exited with status {returncode}")
                except subprocess.TimeoutExpired as exc:
                    stdout = _as_text(exc.stdout)
                    stderr = _as_text(exc.stderr)
                    timed_out = True
                    errors.append(f"Sherlock exceeded the {self.timeout_seconds:g}-second timeout")
                except (FileNotFoundError, PermissionError, OSError, subprocess.SubprocessError, ValueError) as exc:
                    errors.append(f"could not execute Sherlock: {exc}")

                if output_path.is_file():
                    try:
                        parsed = parse_sherlock_csv(
                            output_path.read_text(encoding="utf-8-sig"),
                            queried_username=username,
                            collected_at=started_at,
                        )
                        findings = tuple(parsed)
                        warnings.extend(parsed.warnings)
                        raw_records = parsed.raw_records
                    except (OSError, UnicodeError, SherlockOutputError, ValueError) as exc:
                        findings = ()
                        raw_records = tuple(getattr(exc, "raw_records", ()))
                        errors.append(f"could not parse Sherlock CSV output: {exc}")
                else:
                    findings = ()
                    if not errors:
                        errors.append("Sherlock did not create its expected CSV output file")
        except OSError as exc:
            findings = ()
            errors.append(f"could not prepare Sherlock output directory: {exc}")

        return SherlockRunResult(
            username=username,
            findings=findings,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            error="; ".join(errors) if errors else None,
            timed_out=timed_out,
            warnings=tuple(warnings),
            raw_records=raw_records,
        )


def _validate_username_for_output(username: str) -> None:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username must be a non-empty string")
    if username != username.strip() or username in {".", ".."}:
        raise ValueError("username must be a trimmed single filename component")
    if any(character in username for character in ("/", "\\", ":", "\x00", "\r", "\n")):
        raise ValueError("username contains characters unsafe for Sherlock's output filename")


def _validate_timeout(value: float, name: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")


def _resolve_executable(executable: str) -> str:
    path = Path(executable).expanduser()
    if path.is_absolute() or path.parent != Path("."):
        return str(path.resolve())
    return shutil.which(executable) or executable


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
