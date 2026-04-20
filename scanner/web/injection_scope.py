"""
Shared URL filtering for injection scanners.

Skip obvious static assets so GET-based SQLi/CMDi probes do not hit
stylesheets, scripts, images, or fonts (common false-positive sources).
"""

from __future__ import annotations

from urllib.parse import urlparse

_STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".mjs",
    ".cjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".map",
    ".bmp",
    ".avif",
)


def is_static_asset_url(url: str) -> bool:
    """True if path looks like a static resource (not an app endpoint)."""
    if not url or not isinstance(url, str):
        return True
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return True
    if not path or path.endswith("/"):
        return False
    return any(path.endswith(suf) for suf in _STATIC_SUFFIXES)
