"""Explainable verification of safe public profile-page responses.

An accessible HTTP response is not account ownership evidence. A profile is
classified as accessible only when the returned HTML contains explicit
profile-shaped metadata; generic, login, and bot pages remain inconclusive or
restricted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
import json
from typing import Iterable, Callable

from uti.identity.collectors.public_page import PublicPage, PublicPageFetchError, PublicPageFetcher
from uti.models import Finding, SourceLineage, ValidationStatus
from uti.utils.urls import canonical_profile_url


class URLVerificationStatus(str, Enum):
    VERIFIED_ACCESSIBLE = "verified_accessible"
    NOT_FOUND = "not_found"
    REDIRECTED = "redirected"
    ACCESS_RESTRICTED = "access_restricted"
    INCONCLUSIVE = "inconclusive"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class URLVerificationResult:
    username: str
    platform: str
    original_url: str
    final_url: str | None
    discovering_collectors: tuple[str, ...]
    status: URLVerificationStatus
    http_status: int | None
    page_title: str | None
    page_metadata: tuple[tuple[str, str], ...]
    profile_specific: bool
    verified_at: datetime
    source_lineage: tuple[SourceLineage, ...]
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.status, URLVerificationStatus):
            object.__setattr__(self, "status", URLVerificationStatus(self.status))
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() is None:
            raise ValueError("verified_at must be timezone-aware")
        object.__setattr__(self, "verified_at", self.verified_at.astimezone(timezone.utc))
        object.__setattr__(self, "discovering_collectors", tuple(dict.fromkeys(self.discovering_collectors)))
        object.__setattr__(self, "page_metadata", tuple(self.page_metadata))
        object.__setattr__(self, "source_lineage", tuple(self.source_lineage))


class _VerificationHTMLParser(HTMLParser):
    """Extract a small amount of page evidence without executing page code."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.meta: list[tuple[str, str]] = []
        self.text_parts: list[str] = []
        self.profile_markers: list[str] = []
        self.login_form = False
        self._title_depth = 0
        self._in_form = 0
        self._jsonld = False
        self._json_parts: list[str] = []
        self.json_profile = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        tag = tag.casefold()
        if tag == "title":
            self._title_depth += 1
        if tag == "meta":
            key = (values.get("property") or values.get("name") or "").casefold()
            value = values.get("content", "").strip()
            if key and value:
                self.meta.append((key, value))
                if key.startswith("profile:") or (key == "og:type" and value.casefold() == "profile"):
                    self.profile_markers.append(key)
        if tag == "form":
            self._in_form += 1
        if tag == "script" and values.get("type", "").casefold().split(";", 1)[0].strip() == "application/ld+json":
            self._jsonld = True
        if tag == "input" and values.get("type", "").casefold() == "password":
            self.login_form = True
        classes = set(values.get("class", "").casefold().split())
        person_itemtype = "schema.org/person" in values.get("itemtype", "").casefold()
        if "p-name" in classes or "vcard-fullname" in classes or (person_itemtype and "name" in values.get("itemprop", "").casefold().split()):
            self.profile_markers.append("explicit_profile_name")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "title" and self._title_depth:
            self._title_depth -= 1
        if tag.casefold() == "form" and self._in_form:
            self._in_form -= 1
        if tag.casefold() == "script" and self._jsonld:
            self._jsonld = False
            try:
                document = json.loads("".join(self._json_parts))
                self.json_profile = self.json_profile or _jsonld_person(document)
            except (json.JSONDecodeError, RecursionError):
                pass
            self._json_parts.clear()

    def handle_data(self, data: str) -> None:
        if self._jsonld:
            self._json_parts.append(data)
        if data.strip():
            self.text_parts.append(data.strip())
            if self._title_depth:
                self.title_parts.append(data.strip())


class URLVerificationService:
    """Classify a fetched candidate page without claiming ownership."""

    def __init__(self, fetcher: PublicPageFetcher | None = None) -> None:
        self.fetcher = fetcher or PublicPageFetcher()

    def verify(
        self,
        findings: Iterable[Finding],
        *,
        progress_callback: Callable[[str, str], None] | None = None,
    ) -> tuple[URLVerificationResult, ...]:
        """Fetch eligible, unique findings using the shared safe fetcher."""
        results: list[URLVerificationResult] = []
        seen: set[str] = set()
        attempted = 0
        records = tuple(findings)
        for index, finding in enumerate(records, start=1):
            if progress_callback is not None:
                progress_callback("URL verification", f"Reviewing candidate {index} of {len(records)}")
            key = canonical_profile_url(finding.profile_url)
            if key in seen:
                continue
            seen.add(key)
            if finding.profile_check_status is not ValidationStatus.VALID or not ({tool.casefold() for tool in finding.source_tools} & {"sherlock", "maigret"}):
                results.append(self.evaluate(
                    finding.username, finding.platform, finding.profile_url,
                    finding.source_tools, finding.source_lineage,
                    skipped_reason="only positive Sherlock/Maigret candidate URLs are eligible for page verification",
                ))
                continue
            if attempted >= self.fetcher.max_urls:
                results.append(self.evaluate(
                    finding.username, finding.platform, finding.profile_url,
                    finding.source_tools, finding.source_lineage,
                    skipped_reason="configured maximum eligible URL count was reached",
                ))
                continue
            attempted += 1
            try:
                page = self.fetcher.fetch(finding.profile_url, allow_http_errors=True)
                results.append(self.evaluate(
                    finding.username, finding.platform, finding.profile_url,
                    finding.source_tools, finding.source_lineage, page=page,
                ))
            except Exception as exc:
                results.append(self.evaluate(
                    finding.username, finding.platform, finding.profile_url,
                    finding.source_tools, finding.source_lineage, error=exc,
                ))
        return tuple(results)

    def evaluate(
        self,
        username: str,
        platform: str,
        original_url: str,
        collectors: tuple[str, ...],
        lineage: tuple[SourceLineage, ...],
        *,
        page: PublicPage | None = None,
        error: Exception | None = None,
        skipped_reason: str | None = None,
    ) -> URLVerificationResult:
        """Create an outcome from one already-fetched page or fetch error."""
        now = datetime.now(timezone.utc)
        verification_lineage = tuple(dict.fromkeys(lineage + (
            SourceLineage("url_verification", None, "bounded public HTTP(S) request; validated redirects; DNS-pinned destination"),
        )))
        if skipped_reason is not None:
            return URLVerificationResult(username, platform, original_url, None, collectors, URLVerificationStatus.SKIPPED, None, None, (), False, now, verification_lineage, skipped_reason)
        if error is not None:
            message = str(error)
            code = getattr(error, "status_code", None)
            if isinstance(error, TimeoutError) or "timed out" in message.casefold() or "timeout" in type(error).__name__.casefold() or ("lookup exceeded" in message.casefold() and "seconds" in message.casefold()):
                status, reason = URLVerificationStatus.TIMEOUT, "The safe request timed out."
            elif code in {401, 403, 407, 429} or any(term in message.casefold() for term in ("robots.txt disallows", "access denied", "rate limit")):
                status, reason = URLVerificationStatus.ACCESS_RESTRICTED, "Access was restricted by the remote response or robots policy."
            elif code in {404, 410}:
                status, reason = URLVerificationStatus.NOT_FOUND, f"The remote server returned HTTP {code}."
            elif any(term in message.casefold() for term in ("unsafe", "non-public", "localhost", "internal", "invalid public url", "default http and https ports", "maximum redirect", "redirect loop")):
                status, reason = URLVerificationStatus.SKIPPED, "URL safety or redirect validation prevented the request."
            elif "unsupported page content type" in message.casefold():
                status, reason = URLVerificationStatus.INCONCLUSIVE, "The response was not supported HTML and could not be assessed as a profile."
            else:
                status, reason = URLVerificationStatus.ERROR, f"Safe page verification failed: {message}"
            return URLVerificationResult(username, platform, original_url, None, collectors, status, code, None, (), False, now, verification_lineage, reason)

        assert page is not None
        title, metadata, profile_specific, login_form, text = _inspect(page)
        if page.status in {404, 410}:
            status, reason = URLVerificationStatus.NOT_FOUND, f"The page returned HTTP {page.status}."
        elif page.status in {401, 403, 407, 429}:
            status, reason = URLVerificationStatus.ACCESS_RESTRICTED, f"The page returned HTTP {page.status}."
        elif page.status >= 500 or page.status >= 400:
            status, reason = URLVerificationStatus.ERROR, f"The page returned HTTP {page.status}; the response does not establish profile availability."
        elif login_form or any(term in text for term in ("sign in to continue", "log in to continue", "please log in")):
            status, reason = URLVerificationStatus.ACCESS_RESTRICTED, "The returned page appears to require authentication."
        elif page.redirect_count:
            status = URLVerificationStatus.REDIRECTED
            reason = "The URL redirected through validated public destinations; profile relevance is assessed separately."
        elif page.status == 200 and profile_specific:
            status, reason = URLVerificationStatus.VERIFIED_ACCESSIBLE, "HTTP page response contains explicit profile-specific metadata. This does not verify ownership."
        else:
            status, reason = URLVerificationStatus.INCONCLUSIVE, "The page was reachable, but no reliable profile-specific indicator was found."
        return URLVerificationResult(
            username, platform, original_url, page.final_url or page.url, collectors,
            status, page.status, title, metadata, profile_specific, now, verification_lineage, reason,
        )


def _inspect(page: PublicPage) -> tuple[str | None, tuple[tuple[str, str], ...], bool, bool, str]:
    parser = _VerificationHTMLParser()
    parser.feed(page.body.decode("utf-8", errors="replace"))
    parser.close()
    title = (" ".join(parser.title_parts).strip() or None)
    if title is not None:
        title = title[:300]
    metadata = tuple((key[:100], value[:500]) for key, value in parser.meta[:100])
    text = " ".join(parser.text_parts).casefold()
    profile_specific = bool(parser.profile_markers or parser.json_profile)
    login_form = parser.login_form or any(term in text for term in ("verify you are human", "unusual traffic", "captcha"))
    return title, metadata, profile_specific, login_form, text


def _jsonld_person(value: object) -> bool:
    if isinstance(value, dict):
        kind = value.get("@type", ())
        kinds = (kind,) if isinstance(kind, str) else tuple(kind) if isinstance(kind, list) else ()
        if any(isinstance(item, str) and item.casefold() in {"person", "profilepage"} for item in kinds):
            return True
        return any(_jsonld_person(item) for item in value.values())
    if isinstance(value, list):
        return any(_jsonld_person(item) for item in value)
    return False


__all__ = ["URLVerificationResult", "URLVerificationService", "URLVerificationStatus"]
