# Maigret collector

The adapter in `src/uti/collectors/maigret.py` runs a configured `maigret` executable with `subprocess.run`, an argument list, and `shell=False`. Each run uses an isolated temporary folder, captures standard output, standard error, and return code, and enforces an overall process timeout. It locates the CSV report as `report_<username>.csv`.

The command requests CSV and simple JSON reports, disables automatic database updates and recursive username parsing, and sets request timeout and maximum connections. Maigret 0.6.6 documents these options and report formats in its [command line reference](https://maigret.readthedocs.io/en/latest/command-line-options.html). `--no-autoupdate` uses Maigret's existing bundled or cached site database without checking for updates; it does not make the site checks offline.

## Findings and diagnostics

The parser requires the columns `username`, `name`, `url_main`, `url_user`, `exists`, `http_status`, and `error_reason`. CSV syntax errors and incompatible headers are reported as output errors. A malformed individual row or invalid profile URL is skipped with a line-specific warning, and parsing continues where CSV structure allows.

Only rows whose `exists` value is `Claimed` produce a candidate `Finding`, with `ValidationStatus.VALID` representing Maigret's positive profile check. Claimed rows require a non-empty, strictly valid profile URL. `Available`, `Unknown`, `Illegal`, and unrecognized future statuses are preserved in `MaigretDiagnostic` entries on the parser result and `MaigretRunResult`; their `outcome` is respectively `not_found`, `inconclusive`, `invalid_username`, or `unrecognized_status`. These rows do not require a profile URL, and an empty URL is preserved in their diagnostic. They never become positive findings. Diagnostics retain platform, profile URL, status, HTTP status, error reason, and CSV line number.

Every candidate carries Maigret lineage and an evidence provenance record. Ownership remains `UNVERIFIED`, and `identity_verified` remains `False`. Matching usernames or matching accounts do not establish common ownership. HTTP status codes are retained as evidence and do not determine the profile-check status.

## Example

```python
from uti.collectors import MaigretCollector

collector = MaigretCollector(
    executable="/home/kali/.local/bin/maigret",
    timeout_seconds=600,
    request_timeout_seconds=30,
    max_connections=20,
)
result = collector.collect("uti_demo_test_2026")

print(result.returncode, result.error)
print(result.stdout, result.stderr)
for finding in result.findings:
    print(finding.platform, finding.profile_url, finding.profile_check_status.value)
for diagnostic in result.diagnostics:
    print(diagnostic.status, diagnostic.platform, diagnostic.error_reason)
```

Calling `collect` runs Maigret's normal network checks. Use authorized research accounts and a scope appropriate for the project. Unit tests use synthetic CSV and mocked subprocess calls; they do not invoke Maigret or make network requests.
