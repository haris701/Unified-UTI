"""Constrained, opt-in retrieval and metadata parsing for public web pages."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import re
import queue
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from uti.identity.collectors.base import IdentityCollectionRequest, IdentityCollectionResult
from uti.identity.models import (
    AssociationStatus,
    DiagnosticLevel,
    IdentityDiagnostic,
    IdentityAttribute,
    IdentityAttributeType,
    Sensitivity,
    VerificationStatus,
    ProfileURLCollectionAudit,
    ProfileURLCollectionStatus,
)
from uti.identity.normalization import normalize_identity_attribute
from uti.models import EvidenceProvenance, Finding, SourceLineage, ValidationStatus
from uti.utils.urls import canonical_profile_url


_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])\.[A-Za-z]{2,}(?![\w.-])")
_WHITESPACE_RE = re.compile(r"\s+")
_PUBLIC_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_FORBIDDEN_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".test")
_DNS_LOOKUP_SLOTS = threading.BoundedSemaphore(8)
_TECH_TERMS = (
    "python", "javascript", "typescript", "java", "go", "rust", "c++", "c#",
    "php", "ruby", "kotlin", "swift", "react", "node.js", "django", "flask",
    "docker", "kubernetes", "aws", "azure", "gcp", "terraform", "linux",
)
_TECH_LABELS = {term.casefold(): term for term in (
    "Python", "JavaScript", "TypeScript", "Java", "Go", "Rust", "C++", "C#",
    "PHP", "Ruby", "Kotlin", "Swift", "React", "Node.js", "Django", "Flask",
    "Docker", "Kubernetes", "AWS", "Azure", "GCP", "Terraform", "Linux",
)}


@dataclass(frozen=True, slots=True)
class HTTPResponseData:
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class PublicPage:
    url: str
    content_type: str
    body: bytes
    status: int
    final_url: str | None = None
    redirect_count: int = 0


@dataclass(frozen=True, slots=True)
class _Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    family: int
    socktype: int
    proto: int
    sockaddr: tuple


class PublicPageFetchError(ValueError):
    """A requested URL was unsafe, disallowed, or could not be fetched safely."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class PublicPageFetcher:
    """Fetch one HTML page with pinned public DNS and validated redirect hops.

    The implementation uses only HTTP(S), default ports, a single resolved
    public address, TLS certificate validation, robots.txt, bounded bodies,
    and no cookies, JavaScript, proxy environment, or link traversal. Each
    redirect destination is revalidated and pinned before a connection.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 6.0,
        max_response_bytes: int = 1_000_000,
        max_urls: int = 50,
        max_redirects: int = 5,
        min_interval_seconds: float = 1.0,
        resolver=None,
        requester=None,
        sleeper=None,
    ) -> None:
        if timeout_seconds <= 0 or max_response_bytes <= 0 or max_urls <= 0 or max_redirects < 0 or min_interval_seconds < 0:
            raise ValueError("public fetch limits must be positive (min_interval may be zero)")
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = int(max_response_bytes)
        self.max_urls = int(max_urls)
        self.max_redirects = int(max_redirects)
        self.min_interval_seconds = float(min_interval_seconds)
        self._resolver = resolver or socket.getaddrinfo
        self._requester = requester or self._request_pinned
        self._sleeper = sleeper or time.sleep

    def fetch(self, url: str, *, allow_http_errors: bool = False) -> PublicPage:
        original_target = self._resolve_target(url)
        target = original_target
        visited: set[str] = set()
        redirect_count = 0
        while True:
            if target.url in visited:
                raise PublicPageFetchError("redirect loop detected")
            visited.add(target.url)
            self._check_robots(target)
            if self.min_interval_seconds:
                self._sleeper(self.min_interval_seconds)
            response = self._requester(target, target.url, self.max_response_bytes, self.timeout_seconds)
            if response.status in {301, 302, 303, 307, 308}:
                location = _header(response.headers, "location").strip()
                if not location:
                    raise PublicPageFetchError("redirect response did not include a Location header", status_code=response.status)
                if redirect_count >= self.max_redirects:
                    raise PublicPageFetchError("maximum redirect count exceeded", status_code=response.status)
                destination = urljoin(target.url, location)
                # Resolve and validate every hop independently. The resulting
                # socket connects to that exact validated address, preventing
                # a second DNS lookup from rebinding the destination.
                target = self._resolve_target(destination)
                redirect_count += 1
                continue
            if response.status < 200 or response.status >= 300:
                if not allow_http_errors:
                    raise PublicPageFetchError(f"page returned HTTP {response.status}", status_code=response.status)
                content_type = _header(response.headers, "content-type").split(";", 1)[0].strip().casefold()
                if content_type not in {"text/html", "application/xhtml+xml", "text/plain", "application/json"}:
                    content_type = content_type or "unknown"
                if len(response.body) > self.max_response_bytes:
                    raise PublicPageFetchError("page body exceeded the configured response-size limit", status_code=response.status)
                return PublicPage(original_target.url, content_type, response.body, response.status, target.url, redirect_count)
            content_type = _header(response.headers, "content-type").split(";", 1)[0].strip().casefold()
            if content_type not in {"text/html", "application/xhtml+xml"}:
                raise PublicPageFetchError(
                    f"unsupported page content type: {content_type or 'missing'}",
                    status_code=response.status,
                )
            if len(response.body) > self.max_response_bytes:
                raise PublicPageFetchError("page body exceeded the configured response-size limit", status_code=response.status)
            return PublicPage(original_target.url, content_type, response.body, response.status, target.url, redirect_count)

    def _check_robots(self, target: _Target) -> None:
        robots_url = urlunsplit((target.scheme, _authority(target.host, target.port, target.scheme), "/robots.txt", "", ""))
        robots_target = self._same_origin_target(target, robots_url)
        robots_response = self._requester(robots_target, robots_url, self.max_response_bytes, self.timeout_seconds)
        if robots_response.status in {301, 302, 303, 307, 308}:
            raise PublicPageFetchError("robots.txt redirected; access denied by fail-closed policy", status_code=robots_response.status)
        if robots_response.status in {404, 410}:
            return
        if robots_response.status != 200:
            raise PublicPageFetchError(
                f"robots.txt returned HTTP {robots_response.status}; access denied by fail-closed policy",
                status_code=robots_response.status,
            )
        robot_type = _header(robots_response.headers, "content-type").split(";", 1)[0].strip().casefold()
        if robot_type not in {"text/plain", "application/octet-stream"}:
            raise PublicPageFetchError("robots.txt has an unsupported content type")
        parser = RobotFileParser()
        parser.parse(robots_response.body.decode("utf-8", errors="replace").splitlines())
        if not parser.can_fetch("Unified-UTI", target.url):
            raise PublicPageFetchError("robots.txt disallows this page")

    def _resolve_target(self, url: str) -> _Target:
        if not isinstance(url, str) or not url.strip() or any(ord(ch) < 32 or ch.isspace() for ch in url.strip()):
            raise PublicPageFetchError("URL must be a non-empty whitespace-free HTTP(S) URL")
        try:
            canonical = canonical_profile_url(url.strip())
            parsed = urlsplit(canonical)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise PublicPageFetchError(f"invalid public URL: {exc}") from exc
        host = parsed.hostname or ""
        if port not in {80, 443} or (parsed.scheme == "http" and port != 80) or (parsed.scheme == "https" and port != 443):
            raise PublicPageFetchError("only default HTTP and HTTPS ports are allowed")
        if host == "localhost" or host.endswith(_FORBIDDEN_HOST_SUFFIXES) or (":" not in host and "." not in host):
            raise PublicPageFetchError("local, internal, and single-label hosts are not allowed")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and not literal.is_global:
            raise PublicPageFetchError("non-public IP destinations are not allowed")
        try:
            addresses = self._resolve_with_timeout(host, port)
        except OSError as exc:
            raise PublicPageFetchError(f"could not resolve public host: {exc}") from exc
        if not addresses:
            raise PublicPageFetchError("host did not resolve to a public address")
        resolved = []
        for entry in addresses:
            family, socktype, proto, _canonname, sockaddr = entry
            try:
                address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
            except ValueError as exc:
                raise PublicPageFetchError("DNS returned an invalid IP address") from exc
            if not address.is_global:
                raise PublicPageFetchError("DNS resolved to a non-public address; request blocked")
            resolved.append((family, socktype, proto, sockaddr))
        family, socktype, proto, sockaddr = resolved[0]
        return _Target(canonical, parsed.scheme, host, port, parsed.path or "/", family, socktype, proto, sockaddr)

    def _resolve_with_timeout(self, host: str, port: int):
        """Bound potentially blocking system DNS lookup without unbounded threads."""
        if not _DNS_LOOKUP_SLOTS.acquire(timeout=self.timeout_seconds):
            raise TimeoutError("DNS lookup capacity is exhausted")
        result_queue: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                result_queue.put((True, self._resolver(host, port, type=socket.SOCK_STREAM)))
            except BaseException as exc:  # Propagate resolver errors back to caller.
                result_queue.put((False, exc))
            finally:
                _DNS_LOOKUP_SLOTS.release()

        threading.Thread(target=resolve, name="uti-dns-lookup", daemon=True).start()
        try:
            succeeded, value = result_queue.get(timeout=self.timeout_seconds)
        except queue.Empty as exc:
            raise TimeoutError(f"DNS lookup exceeded {self.timeout_seconds:g} seconds") from exc
        if not succeeded:
            raise value  # type: ignore[misc]
        return value

    def _same_origin_target(self, original: _Target, url: str) -> _Target:
        parsed = urlsplit(url)
        return _Target(url, original.scheme, original.host, original.port, parsed.path or "/", original.family, original.socktype, original.proto, original.sockaddr)

    def _request_pinned(self, target: _Target, url: str, max_bytes: int, timeout: float) -> HTTPResponseData:
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection: http.client.HTTPConnection
        if target.scheme == "https":
            connection = _PinnedHTTPSConnection(target, timeout)
        else:
            connection = _PinnedHTTPConnection(target, timeout)
        try:
            connection.request("GET", path, headers={
                "User-Agent": "Unified-UTI-Research/1.0",
                "Accept": "text/html, application/xhtml+xml, text/plain;q=0.5",
                "Connection": "close",
            })
            response = connection.getresponse()
            headers = {name.casefold(): value for name, value in response.getheaders()}
            content_length = headers.get("content-length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise PublicPageFetchError("response declared a body larger than the configured size limit")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise PublicPageFetchError("response body exceeded the configured size limit")
            return HTTPResponseData(response.status, headers, body)
        finally:
            connection.close()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: _Target, timeout: float) -> None:
        super().__init__(target.host, target.port, timeout=timeout)
        self.target = target

    def connect(self) -> None:
        sock = socket.socket(self.target.family, self.target.socktype, self.target.proto)
        sock.settimeout(self.timeout)
        sock.connect(self.target.sockaddr)
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: _Target, timeout: float) -> None:
        super().__init__(target.host, target.port, timeout=timeout, context=ssl.create_default_context())
        self.target = target

    def connect(self) -> None:
        raw = socket.socket(self.target.family, self.target.socktype, self.target.proto)
        raw.settimeout(self.timeout)
        raw.connect(self.target.sockaddr)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.target.host)


class _PageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.emails: list[str] = []
        self.phones: list[str] = []
        self.websites: list[str] = []
        self.visible: list[str] = []
        self.explicit_profile_names: list[str] = []
        self._profile_name_depth = 0
        self._profile_name_parts: list[str] = []
        self._title_depth = 0
        self._skip_depth = 0
        self._jsonld_depth = 0
        self._jsonld_parts: list[str] = []
        self.jsonld_documents: list[object] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        tag = tag.casefold()
        profile_classes = set(values.get("class", "").casefold().split())
        is_explicit_profile_name = (
            bool(profile_classes & {"p-name", "vcard-fullname"})
            or (
                "name" in values.get("itemprop", "").casefold().split()
                and "schema.org/person" in values.get("itemtype", "").casefold()
            )
        )
        if self._profile_name_depth and tag not in _VOID_TAGS:
            self._profile_name_depth += 1
        elif not self._profile_name_depth and is_explicit_profile_name and tag not in _VOID_TAGS:
            self._profile_name_depth = 1
            self._profile_name_parts = []
        if tag in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1
        if tag == "title":
            self._title_depth += 1
        if tag == "meta":
            key = (values.get("property") or values.get("name") or "").casefold()
            content = values.get("content", "").strip()
            if key and content:
                self.meta.setdefault(key, []).append(content)
        if tag == "script" and values.get("type", "").casefold().split(";", 1)[0].strip() == "application/ld+json":
            self._jsonld_depth += 1
        if tag == "a":
            href = values.get("href", "").strip()
            if href.casefold().startswith("mailto:"):
                self.emails.append(href[7:].split("?", 1)[0])
            elif href.casefold().startswith("tel:"):
                self.phones.append(href[4:].split("?", 1)[0])
            elif href.casefold().startswith(("https://", "http://")) and "me" in values.get("rel", "").casefold().split():
                self.websites.append(href)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "script" and self._jsonld_depth:
            self._jsonld_depth -= 1
            raw = "".join(self._jsonld_parts).strip()
            self._jsonld_parts = []
            if raw:
                try:
                    self.jsonld_documents.append(json.loads(raw))
                except (json.JSONDecodeError, RecursionError):
                    pass
        if self._profile_name_depth:
            self._profile_name_depth -= 1
            if self._profile_name_depth == 0:
                explicit_name = _WHITESPACE_RE.sub(" ", " ".join(self._profile_name_parts)).strip()
                if explicit_name:
                    self.explicit_profile_names.append(explicit_name)
                self._profile_name_parts = []
        if tag in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title" and self._title_depth:
            self._title_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._jsonld_depth:
            self._jsonld_parts.append(data)
        if self._profile_name_depth and data.strip():
            self._profile_name_parts.append(data.strip())
        if self._skip_depth == 0 and data.strip():
            self.visible.append(data.strip())
        if self._title_depth and self._skip_depth == 0 and data.strip():
            self.meta.setdefault("document:title", []).append(data.strip())


class PublicPageIdentityCollector:
    """Fetch safe web profiles from supported discovery collectors and optional URLs."""

    name = "public_page"

    def __init__(
        self,
        fetcher: PublicPageFetcher | None = None,
        *,
        supported_discovery_collectors: tuple[str, ...] = ("sherlock", "maigret"),
    ) -> None:
        self.fetcher = fetcher or PublicPageFetcher()
        self.supported_discovery_collectors = frozenset(
            item.strip().casefold() for item in supported_discovery_collectors if item.strip()
        )

    def collect(self, request: IdentityCollectionRequest) -> IdentityCollectionResult:
        from uti.identity.url_verification import URLVerificationService

        original_urls: dict[str, list[str]] = {}
        for canonical_url, original_url in request.original_profile_urls:
            try:
                canonical = canonical_profile_url(canonical_url)
            except ValueError:
                continue
            original_urls.setdefault(canonical, []).append(original_url)
        tasks: list[tuple[str, str, str, tuple[str, ...], tuple[str, ...], bool]] = [
            (request.username, "Investigator supplied URL", url, (url,), ("investigator",), True)
            for url in request.public_urls
        ]
        if request.include_profile_findings:
            for finding in request.profile_findings:
                canonical = canonical_profile_url(finding.profile_url)
                raw_values = tuple(dict.fromkeys(original_urls.get(canonical, (finding.profile_url,))))
                tasks.append((
                    finding.username, finding.platform, finding.profile_url,
                    raw_values, finding.source_tools,
                    finding.profile_check_status is ValidationStatus.VALID,
                ))
        diagnostics: list[IdentityDiagnostic] = []
        attributes: list[IdentityAttribute] = []
        audits: list[ProfileURLCollectionAudit] = []
        verification_results = []
        verification_service = URLVerificationService(self.fetcher)
        finding_by_url = {canonical_profile_url(item.profile_url): item for item in request.profile_findings}
        seen: set[str] = set()
        attempted_urls = 0
        limit_reported = False
        for task_index, (username, platform, request_url, raw_values, discovered_by, positive_check) in enumerate(tasks, start=1):
            if request.progress_callback is not None:
                request.progress_callback("URL verification", f"Checking candidate {task_index} of {len(tasks)}")
            original_url = raw_values[0] if raw_values else request_url
            try:
                request_key = canonical_profile_url(request_url.strip())
            except ValueError:
                request_key = ""
            source_finding = finding_by_url.get(request_key)
            lineage = source_finding.source_lineage if source_finding else (SourceLineage("investigator", None, "investigator-supplied URL"),)
            if not request_url.strip():
                audits.append(ProfileURLCollectionAudit(
                    username, platform, "(empty URL)", discovered_by, False,
                    ProfileURLCollectionStatus.SKIPPED, datetime.now(timezone.utc),
                    error_or_warning="empty profile URL",
                    reason_skipped="source provided no profile URL",
                    original_profile_urls=raw_values,
                ))
                diagnostics.append(IdentityDiagnostic(self.name, "empty profile URL was skipped"))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url or "(empty URL)", discovered_by, lineage,
                    skipped_reason="source provided no profile URL",
                ))
                continue
            try:
                canonical = canonical_profile_url(request_url.strip())
            except ValueError as exc:
                message = f"invalid profile URL: {exc}"
                diagnostics.append(IdentityDiagnostic(self.name, message))
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, False,
                    ProfileURLCollectionStatus.SKIPPED, datetime.now(timezone.utc),
                    error_or_warning=message,
                    reason_skipped="URL failed strict HTTP(S) validation",
                    original_profile_urls=raw_values,
                ))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage, error=exc,
                ))
                continue
            if not positive_check:
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, False,
                    ProfileURLCollectionStatus.SKIPPED, datetime.now(timezone.utc),
                    canonical_profile_url=canonical,
                    reason_skipped="discovery collector did not report a positive profile check",
                    original_profile_urls=raw_values,
                ))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage,
                    skipped_reason="discovery collector did not report a positive profile check",
                ))
                continue
            if discovered_by != ("investigator",) and not (
                {item.casefold() for item in discovered_by} & self.supported_discovery_collectors
            ):
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, False,
                    ProfileURLCollectionStatus.UNSUPPORTED, datetime.now(timezone.utc),
                    canonical_profile_url=canonical,
                    reason_skipped="profile was reported by an unsupported discovery collector",
                    original_profile_urls=raw_values,
                ))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage,
                    skipped_reason="profile was reported by an unsupported discovery collector",
                ))
                continue
            if canonical in seen:
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, False,
                    ProfileURLCollectionStatus.SKIPPED, datetime.now(timezone.utc),
                    canonical_profile_url=canonical,
                    reason_skipped="canonical page URL was already attempted in this investigation",
                    original_profile_urls=raw_values,
                ))
                continue
            # The cap applies to actual unique, eligible fetches. Invalid,
            # duplicate, unsupported, and negative results must not consume it.
            if attempted_urls >= self.fetcher.max_urls:
                if not limit_reported:
                    diagnostics.append(IdentityDiagnostic(
                        self.name,
                        f"URL limit reached; at most {self.fetcher.max_urls} eligible pages were fetched",
                    ))
                    limit_reported = True
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url or "(empty URL)", discovered_by, False,
                    ProfileURLCollectionStatus.SKIPPED, datetime.now(timezone.utc),
                    canonical_profile_url=canonical,
                    reason_skipped="configured maximum eligible URL count was reached",
                    original_profile_urls=raw_values,
                ))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage,
                    skipped_reason="configured maximum eligible URL count was reached",
                ))
                continue
            seen.add(canonical)
            attempted_urls += 1
            attempted_at = datetime.now(timezone.utc)
            try:
                page = self.fetcher.fetch(request_url)
                verified = verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage, page=page,
                )
                verification_results.append(verified)
                if request.progress_callback is not None:
                    request.progress_callback(
                        "OSINT enrichment",
                        "extracting supported fields from profile-specific content" if verified.profile_specific else "page is generic; no identity attributes extracted",
                    )
                extracted = _extract_attributes(page, username) if verified.profile_specific else ()
                attributes.extend(extracted)
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, True,
                    ProfileURLCollectionStatus.FETCHED, attempted_at,
                    extracted_attribute_count=len(extracted), canonical_profile_url=canonical,
                    http_status=page.status,
                    original_profile_urls=raw_values,
                ))
            except Exception as exc:
                status_code = getattr(exc, "status_code", None)
                message = str(exc)
                if "unsupported page content type" in message.casefold():
                    fetch_status = ProfileURLCollectionStatus.UNSUPPORTED
                    skipped_reason = "response content type is not supported by the HTML identity collector"
                elif "robots.txt disallows" in message.casefold() or "non-public" in message.casefold() or "not allowed" in message.casefold():
                    fetch_status = ProfileURLCollectionStatus.SKIPPED
                    skipped_reason = "public-page safety or robots policy prevented collection"
                else:
                    fetch_status = ProfileURLCollectionStatus.FAILED
                    skipped_reason = None
                diagnostics.append(IdentityDiagnostic(
                    self.name, message, DiagnosticLevel.WARNING, source_url=request_url,
                ))
                verification_results.append(verification_service.evaluate(
                    username, platform, original_url, discovered_by, lineage, error=exc,
                ))
                audits.append(ProfileURLCollectionAudit(
                    username, platform, original_url, discovered_by, True,
                    fetch_status, attempted_at,
                    canonical_profile_url=canonical, http_status=status_code,
                    error_or_warning=message,
                    reason_skipped=skipped_reason,
                    original_profile_urls=raw_values,
                ))
        return IdentityCollectionResult(
            self.name, tuple(attributes), tuple(diagnostics), tuple(audits), tuple(verification_results),
        )


def _extract_attributes(page: PublicPage, associated_username: str | None) -> tuple[IdentityAttribute, ...]:
    parser = _PageMetadataParser()
    parser.feed(page.body.decode("utf-8", errors="replace"))
    parser.close()
    structured = tuple(record for document in parser.jsonld_documents for record in _flatten_jsonld(document))
    is_profile_page = (
        any(value.casefold() == "profile" for value in parser.meta.get("og:type", []))
        or any(
            kind.casefold() in {"person", "profilepage"}
            for item in structured
            for kind in ((item.get("@type"),) if isinstance(item.get("@type"), str) else item.get("@type", ()))
            if isinstance(kind, str)
        )
    )
    profile_name_parts = parser.meta.get("profile:first_name", []) + parser.meta.get("profile:last_name", [])
    title_values = (
        parser.meta.get("og:title", []) + parser.meta.get("twitter:title", []) + parser.meta.get("document:title", [])
    ) if is_profile_page and not parser.explicit_profile_names else []
    descriptions = (parser.meta.get("og:description", []) + parser.meta.get("description", []) + parser.meta.get("twitter:description", [])) if is_profile_page else []
    raw_emails = list(parser.emails)
    raw_emails.extend(match.group(0) for match in _EMAIL_RE.finditer(" ".join(parser.visible)))
    lineage = SourceLineage("public_page", None, "robots-permitted bounded HTML GET; validated redirects; no JavaScript or link following")
    association = AssociationStatus.POTENTIAL_ASSOCIATION if associated_username else AssociationStatus.UNKNOWN
    attrs: list[IdentityAttribute] = []

    def add(kind: IdentityAttributeType, value: str, evidence: str, evidence_type: str) -> None:
        value = value.strip()
        if not value:
            return
        provenance = EvidenceProvenance(evidence, evidence_type, lineage, page.final_url or page.url)
        attrs.append(normalize_identity_attribute({
            "attribute_type": kind.value,
            "value": value,
            "source_tool": "public_page",
            "source_url": page.url,
            "collected_at": datetime.now(timezone.utc),
            "evidence": evidence,
            "evidence_type": evidence_type,
            "source_lineage": lineage,
            "evidence_provenance": (provenance,),
            "verification_status": "format_valid" if kind in {IdentityAttributeType.EMAIL, IdentityAttributeType.WEBSITE, IdentityAttributeType.DOMAIN} else "source_reported",
            "association_status": association.value,
            "sensitivity": "public_personal" if kind in {IdentityAttributeType.EMAIL, IdentityAttributeType.PHONE} else "public",
            "associated_username": associated_username,
        }))

    if profile_name_parts:
        name = " ".join(value.strip() for value in profile_name_parts if value.strip())
        add(IdentityAttributeType.PUBLICLY_STATED_NAME, name, f"Profile metadata name: {name}", "public_profile_name_metadata")
    for name in dict.fromkeys(parser.explicit_profile_names):
        add(IdentityAttributeType.DISPLAY_NAME, name, f"Explicit profile name element: {name}", "public_profile_name_element")
    for key in ("profile:alias", "profile:username"):
        for alias in dict.fromkeys(parser.meta.get(key, [])):
            add(IdentityAttributeType.ALIAS, alias, f"Public profile metadata {key}: {alias}", "public_profile_alias_metadata")
    for key in ("profile:organization", "organization", "affiliation"):
        for organization in dict.fromkeys(parser.meta.get(key, [])):
            add(IdentityAttributeType.ORGANIZATION, organization, f"Explicit organization metadata {key}: {organization}", "public_organization_metadata")
    for location in dict.fromkeys(parser.meta.get("profile:location", [])):
        add(IdentityAttributeType.COARSE_LOCATION, location, f"Explicit profile location metadata: {location}", "public_profile_location_metadata")
    for value in dict.fromkeys(title_values):
        add(IdentityAttributeType.DISPLAY_NAME, value, f"Profile page title metadata: {value}", "public_page_title")
    for value in dict.fromkeys(descriptions):
        add(IdentityAttributeType.BIO, value, f"Page description metadata: {value}", "public_page_description")
        for match in _PUBLIC_URL_RE.finditer(value):
            url_value = match.group(0).rstrip(".,;:!?)]")
            try:
                add(IdentityAttributeType.WEBSITE, url_value, f"Public profile description explicitly contains URL: {url_value}", "profile_description_url")
            except ValueError:
                continue
    if is_profile_page:
        for value in dict.fromkeys(parser.meta.get("og:image", [])):
            try:
                add(IdentityAttributeType.PROFILE_IMAGE_URL, value, f"Profile page image metadata: {value}", "public_profile_image_metadata")
            except ValueError:
                continue
    for record in structured if is_profile_page else ():
        types = record.get("@type", ())
        types = (types,) if isinstance(types, str) else types if isinstance(types, list) else ()
        if not any(isinstance(kind, str) and kind.casefold() in {"person", "profilepage"} for kind in types):
            continue
        for field, attribute_type in (
            ("name", IdentityAttributeType.PUBLICLY_STATED_NAME),
            ("alternateName", IdentityAttributeType.SECONDARY_USERNAME),
            ("email", IdentityAttributeType.EMAIL),
            ("telephone", IdentityAttributeType.PHONE),
            ("jobTitle", IdentityAttributeType.JOB_TITLE),
            ("description", IdentityAttributeType.BIO),
            ("image", IdentityAttributeType.PROFILE_IMAGE_URL),
            ("knowsAbout", IdentityAttributeType.SKILL),
            ("skills", IdentityAttributeType.SKILL),
        ):
            for value in _json_values(record.get(field)):
                try:
                    add(attribute_type, value, f"JSON-LD {field} explicitly reported: {value}", f"jsonld_{field}")
                except ValueError:
                    continue
        for field in ("sameAs", "url"):
            for value in _json_values(record.get(field)):
                if value.startswith(("https://", "http://")):
                    try:
                        link_type = IdentityAttributeType.WEBSITE if field == "url" else IdentityAttributeType.SOCIAL_PROFILE
                        add(link_type, value, f"JSON-LD {field} link explicitly published: {value}", f"jsonld_{field}_link")
                        if field == "url":
                            host = urlsplit(canonical_profile_url(value)).hostname
                            if host:
                                add(IdentityAttributeType.DOMAIN, host, f"Domain derived from JSON-LD url link: {host}", "jsonld_url_domain")
                    except ValueError:
                        continue
        organization = record.get("worksFor") or record.get("affiliation")
        for value in _json_values(organization.get("name") if isinstance(organization, dict) else organization):
            add(IdentityAttributeType.PROFESSIONAL_AFFILIATION, value, f"JSON-LD professional affiliation explicitly reported: {value}", "jsonld_professional_affiliation")
        address = record.get("address")
        for value in _json_values(address.get("addressLocality") if isinstance(address, dict) else None):
            add(IdentityAttributeType.COARSE_LOCATION, value, f"JSON-LD coarse location explicitly reported: {value}", "jsonld_address_locality")
        for technology in _technology_terms(" ".join(_json_values(record.get("description")) + _json_values(record.get("knowsAbout")) + _json_values(record.get("skills")))):
            add(IdentityAttributeType.TECHNOLOGY, technology, f"Technology keyword explicitly present in structured profile text: {technology}", "structured_technology_keyword")
    for key in ("profile:job_title", "job:title"):
        for value in dict.fromkeys(parser.meta.get(key, [])):
            add(IdentityAttributeType.JOB_TITLE, value, f"Explicit job title metadata {key}: {value}", "public_job_title_metadata")
    for key in ("profile:skills", "keywords", "technology"):
        for value in dict.fromkeys(parser.meta.get(key, [])):
            for skill in _split_explicit_values(value):
                add(IdentityAttributeType.SKILL, skill, f"Explicit profile metadata {key}: {skill}", "public_skill_metadata")
            for technology in _technology_terms(value):
                add(IdentityAttributeType.TECHNOLOGY, technology, f"Technology keyword explicitly present in {key} metadata: {technology}", "public_technology_metadata")
    for email in dict.fromkeys(raw_emails):
        try:
            add(IdentityAttributeType.EMAIL, email, f"Email was explicitly published in page text or a mailto link: {email}", "public_page_email")
        except ValueError:
            continue
    for phone in dict.fromkeys(parser.phones):
        try:
            add(IdentityAttributeType.PHONE, phone, f"Phone was explicitly published in a tel link: {phone}", "public_page_tel_link")
        except ValueError:
            continue
    for website in dict.fromkeys(parser.websites):
        try:
            add(IdentityAttributeType.WEBSITE, website, f"Website was explicitly linked with rel=me: {website}", "public_page_rel_me_link")
            host = urlsplit(canonical_profile_url(website)).hostname
            if host:
                add(IdentityAttributeType.DOMAIN, host, f"Domain was parsed from an explicitly linked rel=me website: {host}", "public_page_domain")
        except ValueError:
            continue
    # Technology extraction is limited to exact terms from the visible,
    # source-published text; it does not infer vulnerabilities or skills.
    for technology in _technology_terms(" ".join(parser.visible)):
        add(IdentityAttributeType.TECHNOLOGY, technology, f"Technology keyword explicitly present in public page text: {technology}", "public_technology_keyword")
    return tuple(attrs)


def _flatten_jsonld(value: object) -> tuple[dict, ...]:
    records: list[dict] = []
    if isinstance(value, dict):
        records.append(value)
        for nested in value.values():
            records.extend(_flatten_jsonld(nested))
    elif isinstance(value, list):
        for nested in value:
            records.extend(_flatten_jsonld(nested))
    return tuple(records)


def _json_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [item for nested in value for item in _json_values(nested)]
    if isinstance(value, dict):
        return _json_values(value.get("name") or value.get("url") or value.get("@id"))
    return []


def _technology_terms(text: str) -> tuple[str, ...]:
    folded = text.casefold()
    return tuple(_TECH_LABELS[term.casefold()] for term in _TECH_TERMS if re.search(rf"(?<![\w]){re.escape(term.casefold())}(?![\w])", folded))


def _split_explicit_values(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(part.strip() for part in re.split(r"[,;|]", value) if part.strip()))


def _authority(host: str, port: int, scheme: str) -> str:
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    host_part = f"[{host}]" if ":" in host else host
    return host_part if default_port else f"{host_part}:{port}"


def _header(headers: dict[str, str], name: str) -> str:
    return next((value for key, value in headers.items() if key.casefold() == name.casefold()), "")

