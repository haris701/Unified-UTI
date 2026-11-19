# URL verification

`uti.identity.url_verification.URLVerificationService` classifies safe HTTP page responses separately from Sherlock/Maigret profile checks and separately from account ownership. The current dashboard runs this stage only when identity/public-page collection is explicitly enabled. Its fetch is reused for enrichment, so one profile URL is not fetched twice in the same stage.

## Outcomes

- `VERIFIED_ACCESSIBLE`: successful HTML response with explicit profile-shaped evidence such as `og:type=profile`, explicit profile name markup, or JSON-LD `Person`/`ProfilePage`.
- `REDIRECTED`: one or more validated redirects reached a response. `profile_specific` separately says whether the final content has profile markers.
- `NOT_FOUND`: HTTP 404 or 410.
- `ACCESS_RESTRICTED`: authentication, robots policy, or an HTTP 401/403/407/429 response prevented access.
- `INCONCLUSIVE`: page responded, but its HTML did not establish profile-specific content, or content type was unsupported.
- `TIMEOUT`, `ERROR`, `SKIPPED`: bounded request timeout, other retrieval failure, or URL eligibility/safety/cap prevented a request.

An HTTP 200 alone is never a positive profile result. Generic homepages, login pages, bot-check pages, and error pages are not treated as verified accessible profiles. `VERIFIED_ACCESSIBLE` means profile-specific page evidence was observed; it does not verify profile ownership or identify the operator.

## Request protections

The existing `PublicPageFetcher` is shared with identity extraction. It permits HTTP(S) on default ports, resolves all DNS answers and rejects any non-global address, pins the connection to a validated address, uses TLS certificate validation, checks robots.txt at each redirect origin, follows at most five redirects, detects loops, applies connection/read and DNS lookup timeouts, caps response bytes, and accepts only supported HTML for extraction. Redirect destinations are parsed, DNS-validated, and pinned independently before use. It sends no cookies, does not use proxy environment settings, does not execute JavaScript, and does not follow page links. Authentication, CAPTCHAs, paywalls, and other controls are not bypassed.

Every result retains original/final URL, HTTP status, title, a bounded set of metadata, profile-specific flag, timestamp, discovering collectors, verification lineage, and an explanation. Cross-origin redirects are re-checked against the destination's robots.txt. Redirects from robots.txt itself fail closed.

No platform-specific profile verifier is currently configured. The general profile markers are conservative content indicators, not proof that a platform account exists. An explicit allowlist of safe, platform-specific rules may be added after synthetic fixture tests and review.
