"""
Unified scan targets from crawl output + optional HTML refetch.

``build_scan_targets(crawl_out)`` produces GET targets from ``url_query_params``
(and URL query fallback) plus POST targets from ``forms``. The controller calls
``prepare_scan_targets`` to merge refetched POST forms; SQLi/XSS consume only
``context.scan_targets``.

When the crawl and HTML refetch produce **no GET targets** (no discovered query
parameters), ``prepare_scan_targets`` adds **synthetic GET probes**: common
parameter names (``id``, ``q``, ``search``) on the site origin and typical API
path prefixes (``/api/``, ``/rest/``, ``/v1/``, …) so injection modules still
have surfaces to test.

Execution order (after dedupe): POST form targets first, then GET targets with query
parameters (dynamic paths before static HTML documents). Crawled ``urls`` passed into
``prepare_scan_targets`` should already be ordered via ``url_scan_queue_rank`` from the
controller so HTML refetch walks high-value pages first.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urldefrag, urlparse, urljoin, urlunparse

import requests
from bs4 import BeautifulSoup

from ..scan_logger import logger
from .base import normalize_url
from .base_module import finalize_post_target, lookup_url_query_params
from .crawler import CrawlResult
from .http_retry import request_with_retries
from .injection_scope import is_static_asset_url

# Heuristic: treat method="" as POST candidate when action/page hints at submission.
_POST_HINT_KEYWORDS = (
    "login",
    "signin",
    "search",
    "subscribe",
    "feedback",
    "register",
    "query",
    "submit",
    "comment",
    "post",
    "message",
)

_STATIC_PATH_EXTS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".woff",
    ".ttf",
)

_STATIC_DOCUMENT_SUFFIXES = (".html", ".htm", ".xhtml", ".shtml")

_DYNAMIC_APP_SUFFIXES = (
    ".php",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".cgi",
    ".pl",
    ".do",
    ".action",
    ".json",
)


def _static_document_path(path: str) -> bool:
    pl = (path or "").lower()
    return any(pl.endswith(s) for s in _STATIC_DOCUMENT_SUFFIXES)


def _dynamic_app_path(path: str) -> bool:
    """True for extensionless paths, trailing slash, or common server-generated extensions."""
    pl = (path or "").lower()
    if not pl or pl.endswith("/"):
        return True
    last = pl.rsplit("/", 1)[-1]
    if "." not in last:
        return True
    ext = "." + last.rsplit(".", 1)[-1]
    if ext in _STATIC_DOCUMENT_SUFFIXES:
        return False
    if ext in _DYNAMIC_APP_SUFFIXES:
        return True
    return False


def url_scan_queue_rank(
    url: str,
    *,
    post_form_action_keys: set[str] | None = None,
) -> tuple[int, int, str]:
    """
    Sort key for scan execution order (lower sorts earlier).

    Tiers: POST form actions → parameterized URLs → dynamic endpoints → static documents
    → obvious static assets.
    """
    u = str(url or "").strip()
    ul = u.lower()
    if not u:
        return (9, 9, "")

    if is_static_asset_url(u):
        return (4, 0, ul)

    try:
        p = urlparse(u)
        path = (p.path or "").lower()
        has_query = bool(p.query)
    except Exception:
        return (3, 2, ul)

    keys = post_form_action_keys or set()
    try:
        nk = normalize_url(u).lower().rstrip("/")
    except Exception:
        nk = ul.rstrip("/")

    _HIGH = (
        "login",
        "signin",
        "admin",
        "dashboard",
        "panel",
        "auth",
        "account",
        "register",
        "checkout",
        "payment",
        "upload",
        "submit",
        "post",
        "api",
        "graphql",
    )
    high_hint = 0 if any(kw in ul for kw in _HIGH) else 1

    if nk in keys:
        return (0, high_hint, ul)

    if has_query:
        return (1, high_hint, ul)

    if _static_document_path(path):
        return (3, 0, ul)

    if _dynamic_app_path(path):
        return (2, high_hint, ul)

    if any(
        seg in path
        for seg in ("/static/", "/assets/", "/dist/", "/build/", "/vendor/")
    ):
        return (3, 2, ul)

    return (3, 1, ul)


def build_scan_targets(crawl_out: CrawlResult) -> list[dict[str, Any]]:
    """
    Build scan targets from crawler output only.

    Each item:
    ``{url, method: GET|POST, params, field_details, source: query|form}``

    - GET: ``params`` is parse_qs-shaped ``dict[str, list[str]]``; ``field_details`` is [].
    - POST: ``params`` is flat ``dict[str, str]`` (body fields); ``field_details`` from crawl.
    """
    urls = list(crawl_out.urls or [])
    uqp = crawl_out.url_query_params or {}
    out: list[dict[str, Any]] = []

    seen_get: set[tuple[str, tuple[str, ...]]] = set()
    for u in urls:
        us = str(u).strip()
        if not us or is_static_asset_url(us):
            continue
        params = lookup_url_query_params(uqp, us)
        if not params or not any(params.keys()):
            if "?" not in us:
                continue
            params = parse_qs(urlparse(us).query, keep_blank_values=True)
            if not params or not any(params.keys()):
                continue
        nk = normalize_url(us).lower()
        gkey = (nk, tuple(sorted(params.keys())))
        if gkey in seen_get:
            continue
        seen_get.add(gkey)
        path = urlparse(us).path or "/"
        logger.info(
            "  [GET TARGET] %s | params=%s",
            path,
            ",".join(sorted(params.keys())),
        )
        out.append(
            {
                "url": us,
                "method": "GET",
                "params": {k: list(v) for k, v in params.items()},
                "field_details": [],
                "source": "query",
            },
        )

    seen_post: set[tuple[str, tuple[str, ...]]] = set()
    for form in crawl_out.forms or []:
        if str(form.get("method", "get")).lower().strip() != "post":
            continue
        action = (form.get("action") or form.get("action_url") or "").strip()
        if not action:
            continue
        t = finalize_post_target(
            {
                "url": action,
                "fields": form.get("fields") or {},
                "field_details": form.get("field_details"),
            },
        )
        if not t:
            continue
        flds = t["fields"]
        pkey = (normalize_url(t["url"]).lower(), tuple(sorted(flds.keys())))
        if pkey in seen_post:
            continue
        seen_post.add(pkey)
        out.append(
            {
                "url": t["url"],
                "method": "POST",
                "params": dict(flds),
                "field_details": list(t.get("field_details") or []),
                "source": "form",
            },
        )

    return out


def _base_pages_from_urls(urls: list[str]) -> set[str]:
    base_urls: set[str] = set()
    for u in urls or []:
        p = urlparse(str(u))
        path = p.path.lower()
        if any(path.endswith(ext) for ext in _STATIC_PATH_EXTS):
            continue
        base = urlunparse(p._replace(query="", fragment=""))
        base_urls.add(base.rstrip("/"))
    return base_urls


def _ordered_base_pages_for_refetch(urls: list[str]) -> list[str]:
    """
    Unique base pages (no query) in the order they first appear in ``urls``,
    then any remaining bases lexicographically. Respects prioritized crawl URL order.
    """
    bases_set = _base_pages_from_urls(urls)
    if not bases_set:
        return []
    ordered: list[str] = []
    seen: set[str] = set()
    for u in urls or []:
        p = urlparse(str(u))
        path = p.path.lower()
        if any(path.endswith(ext) for ext in _STATIC_PATH_EXTS):
            continue
        base = urlunparse(p._replace(query="", fragment="")).rstrip("/")
        if base in bases_set and base not in seen:
            seen.add(base)
            ordered.append(base)
    for b in sorted(bases_set - seen):
        ordered.append(b)
    return ordered


def refetch_post_scan_targets(
    urls: list[str],
    session: requests.Session,
    *,
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """
    Discover POST forms by fetching unique base pages (same logic as former module refetch).
    """
    targets: list[dict[str, Any]] = []
    seen_forms: set[str] = set()
    fetch_timeout = max(int(timeout or 10), 8)
    base_urls = _ordered_base_pages_for_refetch(urls)

    logger.info("  [*] Refetch POST forms from %s page(s)…", len(base_urls))

    for page_url in base_urls:
        try:
            resp = request_with_retries(
                session,
                "GET",
                page_url,
                timeout=fetch_timeout,
                max_attempts=3,
                allow_redirects=True,
            )
            if resp is None:
                continue
            ct = resp.headers.get("Content-Type", "")
            if "text/html" not in ct:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method", "") or "get").strip().lower()
                if method not in ("post", ""):
                    continue
                if method == "" and not any(
                    kw in (form.get("action", "") or page_url).lower()
                    for kw in _POST_HINT_KEYWORDS
                ):
                    continue
                action = form.get("action", "") or page_url
                form_url = urljoin(resp.url, action).rstrip("/")
                if form_url in seen_forms:
                    continue
                seen_forms.add(form_url)
                fields: dict[str, str] = {}
                details: list[dict[str, Any]] = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = (inp.get("name", "") or "").strip()
                    if not name:
                        continue
                    if inp.name == "textarea":
                        itype = "textarea"
                        raw_v = inp.get_text() or inp.get("value") or ""
                        value = raw_v.strip()
                    elif inp.name == "select":
                        itype = (
                            "select-multiple"
                            if inp.has_attr("multiple")
                            else "select-one"
                        )
                        opt = inp.find("option", selected=True) or inp.find("option")
                        if opt is not None:
                            ov = opt.get("value")
                            value = (
                                (ov if ov is not None else opt.get_text(strip=True)) or ""
                            )
                        else:
                            value = ""
                        value = str(value).strip()
                    else:
                        itype = (inp.get("type", "text") or "text").lower()
                        value = (inp.get("value", "") or "").strip()
                    if itype in ("submit", "button", "image", "reset"):
                        continue
                    if itype == "file":
                        details.append(
                            {
                                "name": name,
                                "value": "",
                                "type": "file",
                                "tag": "input",
                            },
                        )
                        continue
                    if itype == "hidden":
                        fields[name] = value
                    else:
                        fields[name] = value if value else "test"
                    details.append(
                        {
                            "name": name,
                            "value": fields[name],
                            "type": itype,
                            "tag": inp.name,
                        },
                    )
                if not fields:
                    continue
                t = finalize_post_target(
                    {"url": form_url, "fields": fields, "field_details": details},
                )
                if not t:
                    continue
                targets.append(
                    {
                        "url": t["url"],
                        "method": "POST",
                        "params": dict(t["fields"]),
                        "field_details": list(t.get("field_details") or []),
                        "source": "form",
                    },
                )
                logger.info(
                    "  [+] POST form (refetch) → %s fields=%s",
                    t["url"],
                    list(t["fields"].keys()),
                )
        except Exception as e:
            if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                logger.warning("  [!] Timeout fetching %s", page_url)
            continue

    if not targets:
        logger.info("  [i] No additional POST forms from HTML refetch")
    return targets


def dedupe_scan_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """First occurrence wins (crawl-built targets beat refetch duplicates)."""
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    out: list[dict[str, Any]] = []
    for t in targets or []:
        method = str(t.get("method", "")).upper().strip()
        url = str(t.get("url", "")).strip()
        params = t.get("params") or {}
        if method not in ("GET", "POST") or not url:
            continue
        if not isinstance(params, dict) or not params:
            continue
        pkey = tuple(sorted(params.keys()))
        key = (method, normalize_url(url).lower(), pkey)
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def post_form_action_keys_from_forms(
    crawl_forms: list[dict[str, Any]] | None,
) -> set[str]:
    """Normalized POST form action URLs for queue prioritization."""
    keys: set[str] = set()
    for f in crawl_forms or []:
        if str(f.get("method", "get")).lower().strip() != "post":
            continue
        a = (f.get("action") or "").strip()
        if not a:
            continue
        try:
            keys.add(normalize_url(a).lower().rstrip("/"))
        except Exception:
            keys.add(a.lower().rstrip("/"))
    return keys


def prioritize_scan_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Order injection targets: POST first, then GET; among GET, non-static-document
    paths before ``.html``/``.htm``-style URLs. Preserves stable order within ties.
    """
    if not targets:
        return []

    def _tkey(t: dict[str, Any]) -> tuple[int, int, str]:
        method = str(t.get("method", "")).upper().strip()
        url = str(t.get("url", "")).strip()
        path = urlparse(url).path.lower()
        ul = url.lower()
        if method == "POST":
            return (0, 0, ul)
        if method == "GET":
            doc = 1 if _static_document_path(path) else 0
            return (1, doc, ul)
        return (1, 2, ul)

    enumerated = list(enumerate(targets))
    enumerated.sort(key=lambda ie: (_tkey(ie[1]), ie[0]))
    return [ie[1] for ie in enumerated]


# Synthetic GET targets when crawls find no query-parameter surfaces.
_SYNTH_COMMON_PARAMS: dict[str, list[str]] = {
    "id": ["1"],
    "q": ["test"],
    "search": ["test"],
}

_SYNTH_API_PATH_SEGMENTS: tuple[str, ...] = (
    "api",
    "api/v1",
    "api/v2",
    "rest",
    "rest/api",
    "rest/v1",
    "v1",
    "v2",
    "graphql",
)

_MAX_SYNTH_ORIGINS = 5
_MAX_SYNTH_TOTAL_TARGETS = 42
_MAX_SYNTH_API_PATHS_PER_ORIGIN = 7


def _collect_unique_origins(seed_url: str, scoped_urls: list[str], *, limit: int) -> list[str]:
    """``scheme://netloc`` strings, first-seen order, deduped by hostname."""
    origins: list[str] = []
    seen_hosts: set[str] = set()
    for raw in [seed_url] + list(scoped_urls or []):
        u = str(raw or "").strip()
        if not u:
            continue
        try:
            p = urlparse(u)
            if not p.scheme or not p.netloc:
                continue
            host = (p.hostname or "").lower().rstrip(".")
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            origins.append(f"{p.scheme}://{p.netloc}")
        except Exception:
            continue
        if len(origins) >= limit:
            break
    return origins


def build_synthetic_injection_get_targets(
    seed_url: str,
    scoped_urls: list[str],
) -> list[dict[str, Any]]:
    """
    Build GET scan targets using common parameter names and typical API path
    prefixes. Used when the crawler did not surface any real query strings.

    Each target has ``source: synthetic_fallback`` for logging and reporting.
    """
    origins = _collect_unique_origins(
        seed_url,
        scoped_urls,
        limit=_MAX_SYNTH_ORIGINS,
    )
    if not origins:
        return []

    targets: list[dict[str, Any]] = []
    api_subset = _SYNTH_API_PATH_SEGMENTS[:_MAX_SYNTH_API_PATHS_PER_ORIGIN]

    for origin in origins:
        if len(targets) >= _MAX_SYNTH_TOTAL_TARGETS:
            break
        root = urljoin(origin.rstrip("/") + "/", "/")
        root = normalize_url(urldefrag(root)[0])
        if root and not is_static_asset_url(root):
            targets.append(
                {
                    "url": root,
                    "method": "GET",
                    "params": {k: list(v) for k, v in _SYNTH_COMMON_PARAMS.items()},
                    "field_details": [],
                    "source": "synthetic_fallback",
                },
            )

        for seg in api_subset:
            if len(targets) >= _MAX_SYNTH_TOTAL_TARGETS:
                break
            probe = urljoin(origin.rstrip("/") + "/", seg)
            probe = normalize_url(urldefrag(probe)[0])
            if not probe or is_static_asset_url(probe):
                continue
            targets.append(
                {
                    "url": probe,
                    "method": "GET",
                    "params": {k: list(v) for k, v in _SYNTH_COMMON_PARAMS.items()},
                    "field_details": [],
                    "source": "synthetic_fallback",
                },
            )

    return targets


def prepare_scan_targets(
    crawl_out: CrawlResult,
    urls: list[str],
    session: requests.Session,
    *,
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Crawl targets + HTML refetch POST forms, deduplicated and priority-ordered."""
    acc = build_scan_targets(crawl_out)
    acc.extend(refetch_post_scan_targets(urls, session, timeout=timeout))
    merged = dedupe_scan_targets(acc)
    merged = prioritize_scan_targets(merged)
    n_get = sum(1 for t in merged if t.get("method") == "GET")
    n_post = sum(1 for t in merged if t.get("method") == "POST")

    if n_get == 0:
        scope_list = list(urls or []) + list(getattr(crawl_out, "urls", None) or [])
        seed = (scope_list[0] if scope_list else "") or ""
        synth = build_synthetic_injection_get_targets(seed, scope_list)
        if synth:
            logger.info(
                "  [*] No crawl/refetch GET query targets — injecting %s synthetic "
                "GET probe(s) (params id,q,search + /api/, /rest/, /v1/, …)",
                len(synth),
            )
            merged = dedupe_scan_targets(merged + synth)
            merged = prioritize_scan_targets(merged)
            n_get = sum(1 for t in merged if t.get("method") == "GET")

    logger.info(
        "  [*] Unified scan targets: %s total (GET=%s POST=%s)",
        len(merged),
        n_get,
        n_post,
    )
    return merged
