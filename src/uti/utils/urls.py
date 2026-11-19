"""URL helpers shared by deduplication and correlation."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def _canonical_hostname(hostname: str) -> str:
    """Validate and normalize an IPv4, IPv6, or DNS hostname."""
    if ":" in hostname:
        try:
            return ipaddress.IPv6Address(hostname).compressed.lower()
        except ipaddress.AddressValueError as exc:
            raise ValueError("profile URL contains an invalid IPv6 host") from exc

    if hostname.endswith("."):
        hostname = hostname[:-1]
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("profile URL contains an invalid hostname") from exc
    labels = ascii_hostname.split(".")
    if not ascii_hostname or len(ascii_hostname) > 253 or any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        raise ValueError("profile URL contains an invalid hostname")
    return ascii_hostname


def canonical_profile_url(url: str) -> str:
    """Canonicalize URL parts commonly varied by source formatting.

    Only scheme and hostname casing and default ports are normalized. Path
    casing, trailing slashes, query parameters, and fragments are preserved:
    their meaning can vary by platform, including on client-side profile URLs.
    """
    if not isinstance(url, str) or any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise ValueError("profile URL must be a whitespace-free string")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    if scheme not in {"http", "https"} or not hostname:
        raise ValueError(f"not an absolute URL: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("profile URLs must not contain embedded credentials")
    try:
        port = parsed.port
        hostname = _canonical_hostname(hostname)
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"profile URL contains an invalid host or port: {exc}") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_part if port is None or default_port else f"{host_part}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment))
