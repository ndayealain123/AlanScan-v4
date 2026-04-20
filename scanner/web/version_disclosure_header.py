"""
Gatekeeping for "Information Disclosure (Header)" version findings.

Reports only when the header value contains a credible version token
(e.g. Apache/2.4.49, PHP/8.2.0) and the value does not appear to echo
URL query or fragment input (reflected-payload false positives).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote_plus, urlparse

# Product / major.minor[.patch…] (Apache/2.4.49, Microsoft-IIS/10.0, nginx/1.22.1, PHP/8.2.12)
_PRODUCT_SLASH_VERSION_RE = re.compile(
    r"(?i)(?<![\w/])[a-z][\w.-]{0,50}/\d+(?:\.\d+)+(?:[\w.-]+)?"
)

# X-AspNet-Version, X-AspNetMvc-Version: 4.0.30319
_ASPNET_NUMERIC_VERSION_RE = re.compile(r"^\s*\d+\.\d+(?:\.\d+)*\s*$")

_HEADERS_PRODUCT_SLASH = frozenset({"server", "x-powered-by"})
_HEADERS_ASPNET_STYLE = frozenset({"x-aspnet-version", "x-aspnetmvc-version"})

_REFLECT_MIN_LEN = 5


def looks_like_reflected_header_value(value: str, request_url: str) -> bool:
    """True if the header value likely echoes query or fragment data from the request URL."""
    if not value or not request_url:
        return False
    v_fold = value.casefold()
    parsed = urlparse(request_url)

    candidates: list[str] = []
    if parsed.query:
        for vals in parse_qs(parsed.query, keep_blank_values=True).values():
            for raw in vals:
                s = unquote_plus(raw).strip()
                if len(s) >= _REFLECT_MIN_LEN:
                    candidates.append(s.casefold())
    if parsed.fragment:
        frag = unquote_plus(parsed.fragment).strip()
        if len(frag) >= _REFLECT_MIN_LEN:
            candidates.append(frag.casefold())

    return any(c and c in v_fold for c in candidates)


def is_reportable_version_disclosure_header(
    header_name_lower: str,
    value: str,
    request_url: str,
) -> bool:
    """
    Whether this disclosure header should produce a version-disclosure finding.

    header_name_lower must already be lowercased.
    """
    if not value or not str(value).strip():
        return False
    if looks_like_reflected_header_value(value, request_url):
        return False

    if header_name_lower in _HEADERS_PRODUCT_SLASH:
        return bool(_PRODUCT_SLASH_VERSION_RE.search(value))
    if header_name_lower in _HEADERS_ASPNET_STYLE:
        return bool(_ASPNET_NUMERIC_VERSION_RE.match(value.strip()))
    return False
