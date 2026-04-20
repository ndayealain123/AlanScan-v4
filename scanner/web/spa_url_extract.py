"""
Extract HTTP/API and client-route candidates from JavaScript for SPA crawling.

Used by ``Crawler`` after collecting ``<script src>`` URLs and when scanning
inline ``<script>`` blocks. Resolves relative paths against the bundle or page
URL, instantiates common dynamic segments (``:id``, ``{id}``), and returns
absolute http(s) URLs suitable for in-scope filtering.
"""

from __future__ import annotations

import re
from urllib.parse import urldefrag, urljoin, urlparse

# ---------------------------------------------------------------------------
# Regex: fetch(), axios, XHR, jQuery, common string literals
# ---------------------------------------------------------------------------

_RE_FETCH_DQ = re.compile(
    r"""fetch\s*\(\s*(["'])((?:\\.|(?!\1).){1,4096}?)\1""",
    re.IGNORECASE | re.DOTALL,
)
_RE_FETCH_BT = re.compile(
    r"fetch\s*\(\s*`([^`]{1,8192})`",
    re.IGNORECASE,
)

_RE_AXIOS_METHOD = re.compile(
    r"""axios\.(?:get|post|put|patch|delete|head|options|request)\s*\(\s*
        (["'])((?:\\.|(?!\1).){1,4096}?)\1""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_RE_AXIOS_URL_KEY = re.compile(
    r"""url\s*:\s*(["'])((?:\\.|(?!\1).){1,4096}?)\1""",
    re.IGNORECASE | re.DOTALL,
)

_RE_OPENXHR = re.compile(
    r"""\.open\s*\(\s*["'][A-Z]{3,10}["']\s*,\s*
        (["'])((?:\\.|(?!\1).){1,4096}?)\1""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_RE_JQUERY_SHORT = re.compile(
    r"""\$\.(?:get|post|getJSON)\s*\(\s*(["'])((?:\\.|(?!\1).){1,4096}?)\1""",
    re.IGNORECASE | re.DOTALL,
)

# Paths in quotes that look like API or versioned routes (minified bundles)
_RE_ABS_PATH_LITERAL = re.compile(
    r"""(["'])(/[/a-zA-Z0-9_\-.,~%!$&'()*+;=:@?#]{2,2048}?)\1""",
)

_RE_GRAPHQL = re.compile(
    r"""(["'])(/graphql[^"'\\]{0,512})\1""",
    re.IGNORECASE,
)

# React Router / Vue Router style
_RE_ROUTE_PATH = re.compile(
    r"""path\s*:\s*(["'])((?:\\.|(?!\1).){1,1024}?)\1""",
    re.IGNORECASE | re.DOTALL,
)

_RE_LINK_TO = re.compile(
    r"""(?:to|href)\s*=\s*\{\s*(["'])((?:\\.|(?!\1).){1,1024}?)\1\s*\}""",
    re.IGNORECASE | re.DOTALL,
)

_RE_NAVIGATE = re.compile(
    r"""navigate\s*\(\s*(["'])((?:\\.|(?!\1).){1,1024}?)\1""",
    re.IGNORECASE | re.DOTALL,
)

_DYNAMIC_COLON = re.compile(r"/:[A-Za-z_][A-Za-z0-9_]*")
_DYNAMIC_BRACE = re.compile(r"/\{[A-Za-z_][A-Za-z0-9_]*\}")

_NOISE_PREFIXES = (
    "webpack",
    "__webpack",
    "chunk",
    "static/js/",
    "data:image",
    "module.exports",
    "import(",
    "require(",
)


def _unescape_js_string(s: str) -> str:
    """Best-effort undo common JS escapes for URL extraction."""
    if not s:
        return ""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in r"\"'":
                out.append(n)
                i += 2
                continue
            if n == "n":
                out.append("\n")
                i += 2
                continue
            if n == "t":
                out.append("\t")
                i += 2
                continue
            if n == "u" and i + 5 < len(s):
                try:
                    out.append(chr(int(s[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(n)
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _strip_template_expr(s: str) -> str:
    """Keep static prefix of template literals before ``${``."""
    if "${" in s:
        s = s.split("${", 1)[0]
    return s.strip().rstrip("/")


def _instantiate_dynamic_path(path: str) -> str:
    """Turn ``/users/:id`` / ``/x/{id}`` into probeable paths."""
    p = path.strip()
    if not p:
        return p
    p = _DYNAMIC_COLON.sub("/1", p)
    p = _DYNAMIC_BRACE.sub("/1", p)
    return p


def _looks_like_endpoint(s: str) -> bool:
    t = s.strip()
    if not t or len(t) < 2:
        return False
    tl = t.lower()
    if tl.startswith(("data:", "javascript:", "blob:", "about:", "#")):
        return False
    if any(tl.startswith(p) for p in _NOISE_PREFIXES):
        return False
    if t.startswith("/") and not t.startswith("//"):
        return True
    if t.startswith(("http://", "https://")):
        return True
    if t.startswith(("./", "../")):
        return True
    # relative single segment often false positive — require slash or api-like
    if "/" in t and " " not in t and not t.startswith("{"):
        return True
    return False


def _resolve_candidate(raw: str, origin: str, referer: str) -> str | None:
    """Return normalized absolute URL, or None if not http(s) in-scope resolvable."""
    s = _strip_template_expr(raw)
    s = _unescape_js_string(s)
    s = s.strip().strip(",)")
    if not s:
        return None
    if "?" in s:
        s = urldefrag(s)[0]
    if s.startswith("//"):
        try:
            scheme = urlparse(origin).scheme or "https"
        except Exception:
            scheme = "https"
        s = f"{scheme}:{s}"
    if s.startswith(("http://", "https://")):
        try:
            return urldefrag(s)[0]
        except Exception:
            return None
    inst = _instantiate_dynamic_path(s)
    if not inst:
        return None
    try:
        base = referer if referer else origin
        joined = urljoin(base if base.endswith("/") else base + "/", inst.lstrip("/"))
        if not joined.startswith(("http://", "https://")):
            joined = urljoin(origin.rstrip("/") + "/", inst.lstrip("/"))
        return urldefrag(joined)[0]
    except Exception:
        return None


def _run_patterns(js: str, patterns: list[re.Pattern], group_index: int) -> set[str]:
    found: set[str] = set()
    for rx in patterns:
        for m in rx.finditer(js):
            try:
                g = m.group(group_index)
            except IndexError:
                continue
            if g:
                found.add(g.strip())
    return found


def extract_urls_from_javascript(
    js_source: str,
    *,
    origin: str,
    referer: str,
) -> list[str]:
    """
    Pull URL-like strings from JS (fetch/axios/XHR, literals, router paths).

    Parameters
    ----------
    js_source
        JavaScript source text.
    origin
        Site origin ``scheme://host[:port]`` for resolving ``/api/...``.
    referer
        URL of the script or HTML page (for relative resolution).
    """
    if not js_source or not origin:
        return []

    js = js_source[:3_000_000]
    raw_strings: set[str] = set()

    raw_strings |= _run_patterns(js, [_RE_FETCH_DQ], 2)
    raw_strings |= _run_patterns(js, [_RE_FETCH_BT], 1)
    raw_strings |= _run_patterns(js, [_RE_AXIOS_METHOD], 2)
    raw_strings |= _run_patterns(js, [_RE_JQUERY_SHORT], 2)
    raw_strings |= _run_patterns(js, [_RE_OPENXHR], 2)

    for m in _RE_AXIOS_URL_KEY.finditer(js):
        raw_strings.add(m.group(2).strip())

    for m in _RE_ABS_PATH_LITERAL.finditer(js):
        p = m.group(2).strip()
        if len(p) >= 2 and (
            p.startswith("/api")
            or p.startswith("/v")
            or "/graphql" in p.lower()
            or re.match(r"^/v\d+/", p)
        ):
            raw_strings.add(p)

    raw_strings |= _run_patterns(js, [_RE_GRAPHQL], 2)
    raw_strings |= _run_patterns(js, [_RE_ROUTE_PATH], 2)
    raw_strings |= _run_patterns(js, [_RE_LINK_TO], 2)
    raw_strings |= _run_patterns(js, [_RE_NAVIGATE], 2)

    out: list[str] = []
    seen: set[str] = set()
    for r in raw_strings:
        if not _looks_like_endpoint(r):
            continue
        abs_u = _resolve_candidate(r, origin, referer)
        if not abs_u:
            continue
        k = abs_u.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(abs_u)

    return out
