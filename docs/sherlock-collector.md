# Sherlock collector adapter

The adapter lives in `src/uti/collectors/sherlock.py`. It calls a configured Sherlock executable through `subprocess.run` with an argument list and `shell=False`, enforces a process timeout, captures stdout/stderr/exit status, and writes output into a temporary directory. It returns `SherlockRunResult`, which contains normalized findings and process diagnostics. The executable can be supplied by command name or full path.

## Verified output format

The adapter uses Sherlock's `--csv` export and passes `--folderoutput` a fresh temporary directory. Sherlock writes `<searched-username>.csv` there, which the adapter locates by that exact filename before the temporary directory is cleaned up. The upstream CLI currently documents these CSV columns: `username`, `name`, `url_main`, `url_user`, `exists`, `http_status`, and `response_time_s`. The parser maps `name` to platform, `url_user` to profile URL, and `exists` to the validation status. It preserves `http_status` and `response_time_s` in the evidence record. Sherlock's status values include `Claimed`, `Available`, `Unknown`, `Illegal`, and `WAF`.

The CLI's `--json` option loads the site-definition file; it is not a JSON result export. The CSV route was selected because it provides structured site, URL, and status fields. If a future Sherlock release changes this schema, the parser rejects incompatible files instead of silently guessing. See the [upstream usage documentation](https://github.com/sherlock-project/sherlock#general-usage) and [CSV writer in Sherlock's CLI](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/sherlock.py).

The parser validates every profile URL using the shared strict URL rules. If a row contains an invalid URL, that row is skipped and a line-specific explanation is returned in `SherlockCsvFindings.warnings` (and surfaced as `SherlockRunResult.warnings` by the collector); valid rows elsewhere in the file are retained. File-level problems such as malformed CSV structure, unexpected columns, or a username mismatch still reject the CSV.

Each parsed row gets collector lineage `sherlock`, with the underlying data source left unknown. Its evidence provenance includes type `sherlock_presence_report` and the row's profile URL as the source URL. A `Claimed` status is retained as Sherlock's candidate detection result (`ValidationStatus.VALID` describes the tool's result only); `Finding.ownership_status` remains `UNVERIFIED` and `Finding.identity_verified` is `False`. The result neither verifies account ownership nor guarantees that the URL remains reachable later.

The collector has two timeouts: `request_timeout_seconds` is passed to Sherlock as its per-site `--timeout` (default 10 seconds), while `timeout_seconds` limits the whole subprocess (default 600 seconds). Both can be configured independently.

## Kali Linux setup and use

The adapter does not install Sherlock. On a Kali system, install Sherlock separately using an approved installation route. Sherlock's upstream installation guide lists `pipx install sherlock-project` as an option and also documents Kali's package route; check the [current upstream installation guide](https://sherlockproject.xyz/installation) for current package guidance. With `pipx`, the typical setup commands are:

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx install sherlock-project
command -v sherlock
```

From the UTI project root, activate the project's Python environment and make `src/` importable:

```bash
source .venv/bin/activate
export PYTHONPATH=src
```

Then configure the executable path returned by `command -v sherlock` and call the adapter for an account authorized for the research:

```python
from uti.collectors import SherlockCollector

collector = SherlockCollector(
    executable="/home/kali/.local/bin/sherlock",
    timeout_seconds=600,
    request_timeout_seconds=10,
)
result = collector.collect("uti_test_account_42")

print(result.returncode, result.error)
print(result.stdout)
print(result.stderr)
for finding in result.findings:
    print(finding.platform, finding.profile_url, finding.validation_status.value)
```

Replace the executable path with the value returned on that Kali installation. Calling `collect` launches Sherlock and makes its normal network requests, so use it only with an authorized research scope. The unit tests use mocked subprocess results and do not invoke Sherlock.
