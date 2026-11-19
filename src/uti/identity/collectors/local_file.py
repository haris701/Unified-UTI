"""Schema-validated import of investigator-authorized CSV and JSON evidence."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone

from uti.identity.collectors.base import IdentityCollectionRequest, IdentityCollectionResult
from uti.identity.models import DiagnosticLevel, IdentityDiagnostic
from uti.identity.normalization import normalize_identity_attribute
from uti.models import SourceLineage


_ALLOWED_FIELDS = {
    "attribute_type", "type", "value", "original_value", "source_url", "evidence",
    "evidence_type", "collected_at", "verification_status", "association_status",
    "sensitivity", "country_context", "associated_username",
}


class LocalEvidenceIdentityCollector:
    """Read only an explicitly supplied local evidence file, with row diagnostics."""

    name = "local_evidence_import"

    def __init__(self, *, max_file_bytes: int = 2_000_000) -> None:
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be a positive integer")
        self.max_file_bytes = max_file_bytes

    def collect(self, request: IdentityCollectionRequest) -> IdentityCollectionResult:
        content = request.local_evidence_content
        if content is None:
            return IdentityCollectionResult(self.name)
        filename = request.local_evidence_filename or "uploaded-evidence"
        if len(content) > self.max_file_bytes:
            return IdentityCollectionResult(self.name, diagnostics=(IdentityDiagnostic(
                self.name, f"evidence file exceeds the {self.max_file_bytes}-byte limit", DiagnosticLevel.ERROR,
            ),))
        suffix = filename.rsplit(".", 1)[-1].casefold() if "." in filename else ""
        try:
            text = content.decode("utf-8-sig", errors="strict")
        except UnicodeError as exc:
            return IdentityCollectionResult(self.name, diagnostics=(IdentityDiagnostic(self.name, f"file is not valid UTF-8: {exc}", DiagnosticLevel.ERROR),))
        try:
            rows = self._json_rows(text) if suffix == "json" else self._csv_rows(text) if suffix == "csv" else None
        except (ValueError, csv.Error, json.JSONDecodeError) as exc:
            return IdentityCollectionResult(self.name, diagnostics=(IdentityDiagnostic(self.name, f"could not parse {filename}: {exc}", DiagnosticLevel.ERROR),))
        if rows is None:
            return IdentityCollectionResult(self.name, diagnostics=(IdentityDiagnostic(self.name, "only CSV and JSON evidence files are supported", DiagnosticLevel.ERROR),))
        digest = hashlib.sha256(content).hexdigest()
        attributes = []
        diagnostics = []
        for line_number, row in rows:
            if not isinstance(row, dict):
                diagnostics.append(IdentityDiagnostic(self.name, "record must be an object", DiagnosticLevel.WARNING, line_number=line_number))
                continue
            unknown = set(row) - _ALLOWED_FIELDS
            if unknown:
                diagnostics.append(IdentityDiagnostic(self.name, f"unsupported fields: {', '.join(sorted(unknown))}", DiagnosticLevel.WARNING, line_number=line_number))
                continue
            row = dict(row)
            row.setdefault("source_tool", self.name)
            row.setdefault("source_lineage", SourceLineage(
                self.name, None,
                f"authorized local {suffix.upper()} import: {filename}; record {line_number}; sha256={digest}",
            ))
            row.setdefault("collected_at", datetime.now(timezone.utc))
            row.setdefault("evidence", f"Imported from {filename}, record {line_number}")
            row.setdefault("evidence_type", "authorized_local_evidence")
            try:
                attributes.append(normalize_identity_attribute(row, source_tool=self.name))
            except (TypeError, ValueError) as exc:
                diagnostics.append(IdentityDiagnostic(self.name, str(exc), DiagnosticLevel.WARNING, line_number=line_number))
        return IdentityCollectionResult(self.name, tuple(attributes), tuple(diagnostics))

    @staticmethod
    def _csv_rows(text: str) -> list[tuple[int, dict[str, str]]]:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if not reader.fieldnames or "attribute_type" not in reader.fieldnames and "type" not in reader.fieldnames:
            raise ValueError("CSV header must include attribute_type or type")
        if "value" not in reader.fieldnames and "original_value" not in reader.fieldnames:
            raise ValueError("CSV header must include value or original_value")
        results = []
        for row in reader:
            line = reader.line_num
            if None in row or any(value is None for value in row.values()):
                results.append((line, {}))
            else:
                results.append((line, dict(row)))
        return results

    @staticmethod
    def _json_rows(text: str) -> list[tuple[int, dict]]:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed = parsed.get("attributes")
        if not isinstance(parsed, list):
            raise ValueError("JSON must be an array or an object with an attributes array")
        return [(index, item) for index, item in enumerate(parsed, start=1)]

