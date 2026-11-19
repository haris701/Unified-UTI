# Configuration

The application reads no API keys or external-service credentials. Collector executables and timeouts are configured in the dashboard. The per-collector overall timeout defaults to 600 seconds; Sherlock and Maigret request timeouts and Maigret connection count have separate controls.

Public identity collection is off unless enabled for an investigation. The page cap defaults to 50 and the dashboard permits 1–5,000 eligible unique URLs. Selecting a large cap can make an investigation take a long time because requests are sequential and rate-limited. Unsafe, unsupported, duplicate, non-positive, or over-cap results do not use a fetch slot. Remaining outcomes and reasons appear in the URL verification and Profile URL Collection Audit views.

Public page requests use a six-second timeout, one-megabyte response cap, default ports only, HTML-only enrichment, robots.txt checks, DNS timeout, pinned public addresses, and at most five validated redirects. No cookies, proxy environment, JavaScript execution, arbitrary downloads, or link traversal are enabled. These values can be configured by injecting `PublicPageFetcher` into `PublicPageIdentityCollector`.

## Kali Linux with a VirtualBox shared folder

Do not create `.venv` inside `/media/sf_Unified-UTI`: shared-folder filesystems may not support the symlink Python creates for `lib64`. Create the environment in Kali's home directory instead:

```bash
sudo apt update
sudo apt install -y python3-full
cd /media/sf_Unified-UTI
python3 -m venv ~/uti-venv
source ~/uti-venv/bin/activate
python -m pip install -r requirements.txt
export PYTHONPATH=src
python -m unittest discover -s tests -v
streamlit run src/uti/dashboard/app.py
```

The OSINT executables Sherlock and Maigret must be installed and maintained separately in Kali. Their tests in this repository mock subprocesses and do not run searches. Use only authorized synthetic/test usernames and approved research scope.
