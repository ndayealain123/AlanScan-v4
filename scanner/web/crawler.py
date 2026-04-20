"""
scanner/web/crawler.py
======================
Recursive web crawler — discovers reachable URLs on the **same site** (hostname,
parent/subdomain, or shared **registrable suffix** like ``*.vulnweb.com``).

Link extraction (resolved with ``<base href>`` when present, ``urljoin`` for
relative/absolute targets): ``<a href>``, ``<area href>``, ``<form action>``,
``<script src>``, ``<link href>``, ``<iframe src>``, ``<frame src>``. In-page
links are deduplicated in document order; the crawl queue deduplicates by
normalized URL before enqueue. Depth limits how far to **fetch**; URLs found
one level past the limit are still **surfaced** into the final URL list.

**SPA / modern apps:** Inline ``<script>`` bodies and (cap-limited) same-origin
``.js`` / ``.mjs`` bundles are scanned for ``fetch()``, ``axios.*``, XHR
``.open()``, ``$.get/post``, quoted ``/api/…`` / ``/v1/…`` literals, and common
client-router ``path:`` / ``to=`` patterns. Extracted URLs are merged into the
crawl result as additional scan targets.
GET forms yield probe URLs with query parameters. Each ``<form>`` is stored with
``method``, ``action``, ``fields`` (name→value for scanners), and
``field_details`` (name, value, type, tag) including hidden, checkbox, radio,
select, textarea, and named submit buttons. Returns ``CrawlResult`` with ``urls``,
``forms``, per-URL ``url_query_params`` (parse_qs), and ``stats``.

Uses one **Session** (cookies preserved) with polite rate limiting and retries.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urldefrag, urlencode, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..scan_logger import logger
from .base import make_session, normalize_url
from .http_retry import request_with_retries
from .spa_url_extract import extract_urls_from_javascript
import config

_STATIC_EXT = frozenset(
    (
        ".css",
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
        ".map",
        ".pdf",
        ".zip",
        ".mp4",
        ".mp3",
        ".rar",
    )
)

_POLITE_MIN_INTERVAL_SEC = 0.08
_MAX_DROP_LOG = 48


def _registrable_suffix(hostname: str) -> str:
    """Last two DNS labels (e.g. ``vulnweb.com``); single-label hosts unchanged."""
    h = (hostname or "").lower().rstrip(".")
    parts = [p for p in h.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


@dataclass
class CrawlResult:
    """Structured crawler output for the controller and ScanContext."""

    urls: list[str]
    forms: list[dict] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    # Normalized URL string -> parse_qs mapping (only URLs with a query component)
    url_query_params: dict[str, dict[str, list[str]]] = field(default_factory=dict)


class Crawler:
    """
    Breadth-first crawler with domain scoping and form extraction.

    ``crawl()`` returns a ``CrawlResult`` (URLs + forms with method/action/fields).
    """

    def __init__(
        self,
        base_url: str,
        depth: int = 3,
        threads: int = 10,
        timeout: int | None = None,
        proxy: str | None = None,
        scan_intensity: str | None = None,
        max_requests: int | None = None,
        **_kwargs: Any,
    ) -> None:
        self.base_url = normalize_url(base_url)
        self.depth = depth
        self.threads = threads
        self.timeout = int(
            timeout if timeout is not None else getattr(config, "TIMEOUT", 15),
        )
        self.session = make_session(proxy, self.timeout)
        self.scan_intensity = str(
            scan_intensity or getattr(config, "SCAN_INTENSITY_DEFAULT", "medium"),
        ).lower()
        if self.scan_intensity not in ("light", "medium", "aggressive"):
            self.scan_intensity = "medium"

        cfg_cap = int(getattr(config, "MAX_URLS", 300))
        cfg_cap = max(1, cfg_cap)
        try:
            self.max_requests = int(max_requests) if max_requests is not None else cfg_cap
        except (TypeError, ValueError):
            self.max_requests = cfg_cap
        self.max_requests = max(1, self.max_requests)
        self.crawl_url_limit = min(self.max_requests, cfg_cap)

        parsed = urlparse(self.base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self._seed_host = (parsed.hostname or "").lower().rstrip(".")
        self._seed_suffix = _registrable_suffix(self._seed_host)

        self._session_lock = threading.Lock()
        self._last_request_mono = 0.0
        self._dropped_urls: list[tuple[str, str]] = []
        self._discovery_log_keys: set[str] = set()
        self._discovery_lock = threading.Lock()
        self._js_asset_urls: set[str] = set()
        self._spa_inline_discovered: int = 0

    def _url_key(self, url: str) -> str:
        """Stable key for deduplication (fragment stripped, normalized path, lowercased)."""
        return normalize_url((url or "").strip()).lower()

    def _record_drop(self, url: str, reason: str) -> None:
        if len(self._dropped_urls) < _MAX_DROP_LOG:
            self._dropped_urls.append((url[:512], reason))

    def _polite_gap(self) -> None:
        gap = time.monotonic() - self._last_request_mono
        if gap < _POLITE_MIN_INTERVAL_SEC:
            time.sleep(_POLITE_MIN_INTERVAL_SEC - gap)

    def _fetch_page_response(self, url: str) -> Optional[requests.Response]:
        with self._session_lock:
            self._polite_gap()
            try:
                resp = request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    allow_redirects=True,
                )
                self._last_request_mono = time.monotonic()
                if resp is None:
                    logger.info("  [i] Crawl fetch gave up after retries: %s", url)
                return resp
            except Exception as e:
                self._last_request_mono = time.monotonic()
                logger.info("  [i] Crawl fetch failed: %s (%s)", url, e)
                return None

    def _log_discovered_url(self, url: str, kind: str = "link") -> None:
        """Log each unique URL once at INFO when first scheduled or surfaced."""
        k = self._url_key(url)
        with self._discovery_lock:
            if k in self._discovery_log_keys:
                return
            self._discovery_log_keys.add(k)
        logger.info("  [~] discovered (%s): %s", kind, url)

    def _allowed_domain(self, url: str) -> bool:
        """Same host, parent/subdomain, or same registrable suffix (e.g. *.vulnweb.com)."""
        try:
            host = (urlparse(url).hostname or "").lower().rstrip(".")
        except Exception:
            return False
        if not host or not self._seed_host:
            return False
        if host == self._seed_host:
            return True
        if host.endswith("." + self._seed_host):
            return True
        if self._seed_host.endswith("." + host):
            return True
        suf = _registrable_suffix(host)
        if (
            len(suf) >= 4
            and suf == self._seed_suffix
            and "." in suf
        ):
            return True
        return False

    def crawl(self) -> CrawlResult:
        self._dropped_urls.clear()
        self._discovery_log_keys.clear()
        self._js_asset_urls.clear()
        self._spa_inline_discovered = 0
        all_forms: list[dict] = []

        try:
            probe = self._fetch_page_response(self.base_url)
            if probe is not None:
                final_url = normalize_url(probe.url)
                parsed_final = urlparse(final_url)
                real_origin = f"{parsed_final.scheme}://{parsed_final.netloc}"
                new_host = (parsed_final.hostname or "").lower().rstrip(".")
                if new_host:
                    self._seed_host = new_host
                    self._seed_suffix = _registrable_suffix(new_host)
                if real_origin != self.origin:
                    logger.info("  [i] Redirect detected: %s → %s", self.origin, real_origin)
                self.origin = real_origin
                self.base_url = final_url
        except Exception:
            pass

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(self.base_url, 0)]
        form_urls: set[str] = set()
        scheduled_keys: set[str] = {self._url_key(self.base_url)}
        surface_urls: list[str] = []
        self._log_discovered_url(self.base_url, "seed")

        while queue and len(visited) < self.crawl_url_limit:
            batch, queue = queue[: self.threads * 2], queue[self.threads * 2 :]

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._fetch_page, url, depth): (url, depth)
                    for url, depth in batch
                    if url not in visited
                }
                for future in as_completed(futures):
                    url, depth = futures[future]
                    try:
                        new_links, new_form_urls, page_forms = future.result()
                        visited.add(url)
                        form_urls.update(new_form_urls)
                        all_forms.extend(page_forms)
                        for link in new_links:
                            lk = self._url_key(link)
                            if lk in scheduled_keys:
                                continue
                            scheduled_keys.add(lk)
                            self._log_discovered_url(link, "link")
                            if depth + 1 >= self.depth:
                                u0 = normalize_url(urldefrag(link)[0])
                                if u0 and self._allowed_domain(u0) and not self._is_static_noise(
                                    u0,
                                ):
                                    surface_urls.append(u0)
                                continue
                            queue.append((link, depth + 1))
                        logger.info("  [+] %s", url)
                    except Exception:
                        visited.add(url)

        spa_surface, spa_stats = self._collect_spa_discovered_urls()
        merged = list(visited) + list(form_urls) + surface_urls + spa_surface
        filtered = self._dedupe_and_filter_urls(merged)
        cap_map = getattr(config, "CRAWLER_URL_CAP_BY_INTENSITY", {})
        cap = int(cap_map.get(self.scan_intensity, config.MAX_URLS))
        cap = min(cap, int(getattr(config, "MAX_URLS", 300)))
        cap = min(cap, self.crawl_url_limit)
        if len(filtered) > cap:
            filtered = filtered[:cap]
            logger.info(
                "  [i] Crawl URL cap (%s intensity): kept %s of %s URLs",
                self.scan_intensity,
                cap,
                len(merged),
            )

        # Ensure seed remains discoverable for modules
        seed_n = normalize_url(self.base_url)
        if seed_n and not any(seed_n.lower() == u.lower() for u in filtered):
            filtered.insert(0, seed_n)

        n_with_q = sum(1 for u in filtered if "?" in u)
        n_get = sum(1 for f in all_forms if str(f.get("method", "get")).lower() == "get")
        n_post = sum(1 for f in all_forms if str(f.get("method", "get")).lower() == "post")

        if self._dropped_urls:
            sample = self._dropped_urls[:12]
            logger.info(
                "  [i] Crawl domain filter: dropped %s URL(s) (sample: %s)",
                len(self._dropped_urls),
                "; ".join(f"{u[:60]}… ({r})" for u, r in sample),
            )

        logger.info(
            "  [*] Crawl summary: pages=%s unique_urls=%s with_query=%s forms=%s (GET=%s POST=%s)",
            len(visited),
            len(filtered),
            n_with_q,
            len(all_forms),
            n_get,
            n_post,
        )
        if spa_stats.get("spa_js_fetched", 0) or spa_stats.get("spa_urls_from_inline", 0):
            logger.info(
                "  [*] SPA extraction: JS bundles fetched=%s | URLs from bundles=%s | "
                "from inline scripts=%s",
                spa_stats.get("spa_js_fetched", 0),
                spa_stats.get("spa_urls_from_bundles", 0),
                spa_stats.get("spa_urls_from_inline", 0),
            )

        if form_urls:
            logger.info(
                "  [+] %s form-based probe URL(s) for parameter discovery",
                len(form_urls),
            )

        url_query_params: dict[str, dict[str, list[str]]] = {}
        for u in filtered:
            if "?" not in u:
                continue
            try:
                q = urlparse(u).query
                if not q:
                    continue
                url_query_params[u] = parse_qs(q, keep_blank_values=True)
            except Exception:
                continue

        stats = {
            "pages_fetched": len(visited),
            "unique_urls": len(filtered),
            "urls_with_query": n_with_q,
            "urls_surface_only": len(surface_urls),
            "urls_discovery_logged": len(self._discovery_log_keys),
            "urls_query_param_maps": len(url_query_params),
            "forms_total": len(all_forms),
            "forms_get": n_get,
            "forms_post": n_post,
            "dropped_external": len(self._dropped_urls),
            **spa_stats,
        }
        return CrawlResult(
            urls=filtered,
            forms=all_forms,
            stats=stats,
            url_query_params=url_query_params,
        )

    def _resolve_href(self, page_url: str, base_href: str | None, raw: str) -> str:
        base = base_href if base_href else page_url
        return normalize_url(urljoin(base, raw))

    @staticmethod
    def _field_detail(
        name: str,
        value: str,
        html_type: str,
        tag: str,
    ) -> dict[str, Any]:
        return {
            "name": name,
            "value": value,
            "type": html_type,
            "tag": tag,
        }

    def _parse_form_fields(self, form: Any) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """
        Build ``fields`` (for POST/GET scanners) and ``field_details`` metadata.
        Skips disabled controls and non-submitting buttons; ``file`` inputs are
        recorded in details but omitted from ``fields`` (avoid bogus multipart).
        """
        fields: dict[str, str] = {}
        details: list[dict[str, Any]] = []
        radios_by_name: dict[str, list[Any]] = {}

        def add_field(name: str, value: str, html_type: str, tag: str) -> None:
            details.append(self._field_detail(name, value, html_type, tag))
            fields[name] = value

        for el in form.find_all(["input", "select", "textarea", "button"]):
            if el.has_attr("disabled"):
                continue

            if el.name == "button":
                btype = (el.get("type") or "submit").lower()
                if btype not in ("submit",):
                    continue
                name = (el.get("name") or "").strip()
                if not name:
                    continue
                val = (el.get("value") or el.get_text(strip=True) or "submit").strip()
                add_field(name, val or "submit", "submit", "button")
                continue

            if el.name == "textarea":
                name = (el.get("name") or "").strip()
                if not name:
                    continue
                txt = el.get_text() or ""
                val = txt.strip() if txt.strip() else (el.get("value") or "test")
                add_field(name, val or "test", "textarea", "textarea")
                continue

            if el.name == "select":
                name = (el.get("name") or "").strip()
                if not name:
                    continue
                if el.has_attr("multiple"):
                    picked = el.find_all("option", selected=True)
                    if not picked:
                        picked = el.find_all("option")[:1]
                    vals: list[str] = []
                    for opt in picked:
                        v = opt.get("value")
                        vals.append(
                            v if v is not None else (opt.get_text(strip=True) or ""),
                        )
                    combined = "|".join(vals) if vals else "test"
                    primary = vals[0] if vals else "test"
                    details.append(
                        self._field_detail(name, combined, "select-multiple", "select"),
                    )
                    fields[name] = primary
                else:
                    opt = el.find("option", selected=True) or el.find("option")
                    if opt is not None:
                        v = opt.get("value")
                        val = (
                            v
                            if v is not None
                            else (opt.get_text(strip=True) or "test")
                        )
                    else:
                        val = "test"
                    add_field(name, val, "select-one", "select")
                continue

            if el.name != "input":
                continue

            name = (el.get("name") or "").strip()
            itype = (el.get("type") or "text").lower()

            if itype == "radio":
                if not name:
                    continue
                radios_by_name.setdefault(name, []).append(el)
                continue

            if not name:
                continue

            if itype == "file":
                details.append(self._field_detail(name, "", "file", "input"))
                continue

            if itype in ("submit", "button", "image"):
                val = el.get("value") or ("submit" if itype != "image" else "submit")
                add_field(name, val, itype, "input")
                continue

            if itype == "reset":
                continue

            if itype == "hidden":
                add_field(name, el.get("value", ""), "hidden", "input")
                continue

            if itype == "checkbox":
                raw_val = el.get("value", "on")
                if el.has_attr("checked"):
                    add_field(name, raw_val if raw_val is not None else "on", "checkbox", "input")
                else:
                    details.append(
                        self._field_detail(
                            name,
                            "",
                            "checkbox-unchecked",
                            "input",
                        ),
                    )
                    fields[name] = ""
                continue

            val = el.get("value", "test")
            add_field(name, val if val is not None else "test", itype, "input")

        for name, rlist in radios_by_name.items():
            chosen: Any | None = None
            for r in rlist:
                if r.has_attr("checked"):
                    chosen = r
                    break
            pick = chosen or rlist[0]
            val = pick.get("value", "on")
            add_field(name, val if val is not None else "on", "radio", "input")

        return fields, details

    def _collect_spa_discovered_urls(self) -> tuple[list[str], dict[str, Any]]:
        """
        Fetch capped same-origin JS bundles and extract API / route URLs.
        Inline script extraction is counted separately (feeds the normal link list).
        """
        cap_map = getattr(config, "CRAWLER_SPA_JS_FETCH_MAX_BY_INTENSITY", {})
        cap = int(cap_map.get(self.scan_intensity, 45))
        stats: dict[str, Any] = {
            "spa_js_candidates": len(self._js_asset_urls),
            "spa_js_fetch_cap": cap,
            "spa_js_fetched": 0,
            "spa_urls_from_bundles": 0,
            "spa_urls_from_inline": self._spa_inline_discovered,
        }
        if cap <= 0:
            return [], stats

        out: list[str] = []
        seen: set[str] = set()
        candidates = sorted(self._js_asset_urls)

        for js_url in candidates[:cap]:
            resp = self._fetch_page_response(js_url)
            if resp is None:
                continue
            path_low = js_url.lower().split("?", 1)[0]
            ct = (resp.headers.get("Content-Type") or "").lower()
            if not path_low.endswith((".js", ".mjs", ".cjs")):
                if not any(
                    x in ct
                    for x in (
                        "javascript",
                        "ecmascript",
                        "jscript",
                        "text/plain",
                    )
                ):
                    continue
            stats["spa_js_fetched"] += 1
            text = resp.text or ""
            if len(text) > 2_500_000:
                text = text[:2_500_000]
            found = extract_urls_from_javascript(
                text,
                origin=self.origin,
                referer=js_url,
            )
            for u in found:
                u0 = normalize_url(urldefrag(u)[0])
                if not u0 or not self._allowed_domain(u0) or self._is_static_noise(u0):
                    continue
                lk = u0.lower()
                if lk in seen:
                    continue
                seen.add(lk)
                stats["spa_urls_from_bundles"] += 1
                self._log_discovered_url(u0, "spa-js")
                out.append(u0)

        return out, stats

    def _fetch_page(self, url: str, current_depth: int) -> tuple[list, list, list]:
        if current_depth >= self.depth:
            return [], [], []

        resp = self._fetch_page_response(url)
        if resp is None:
            return [], [], []
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return [], [], []

        soup = BeautifulSoup(resp.text, "html.parser")
        base_tag = soup.find("base", href=True)
        base_href: str | None = None
        if base_tag:
            base_href = self._resolve_href(url, None, base_tag["href"].strip())

        links: list[str] = []
        form_urls: list[str] = []
        page_forms: list[dict] = []

        seen_link_keys: set[str] = set()

        # Inline <script>: extract fetch/axios/XHR/router paths (SPA bootstrap).
        for el in soup.find_all("script"):
            src_raw = el.get("src")
            if src_raw:
                raw_s = str(src_raw).strip()
                if raw_s and not raw_s.startswith(
                    ("mailto:", "tel:", "javascript:", "#"),
                ):
                    full_js = self._resolve_href(url, base_href, raw_s)
                    if self._allowed_domain(full_js):
                        pl = full_js.lower().split("?", 1)[0]
                        if pl.endswith((".js", ".mjs", ".cjs")):
                            with self._discovery_lock:
                                self._js_asset_urls.add(full_js)
                continue
            inline = el.string
            if inline is None:
                inline = el.get_text() or ""
            if not inline or len(inline) > 800_000:
                continue
            for u in extract_urls_from_javascript(
                inline,
                origin=self.origin,
                referer=url,
            ):
                full = normalize_url(urldefrag(u)[0])
                if not full or not self._allowed_domain(full):
                    continue
                if self._is_static_noise(full):
                    continue
                lk = self._url_key(full)
                if lk in seen_link_keys:
                    continue
                seen_link_keys.add(lk)
                links.append(full)
                self._log_discovered_url(full, "spa-inline")
                with self._discovery_lock:
                    self._spa_inline_discovered += 1

        # <a href>, <form action> (below), <script src>, <link href>, plus frames.
        link_specs = [
            ("a", "href"),
            ("area", "href"),
            ("script", "src"),
            ("link", "href"),
            ("iframe", "src"),
            ("frame", "src"),
        ]
        for tag, attr in link_specs:
            for el in soup.find_all(tag, **{attr: True}):
                raw = el.get(attr, "")
                if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                full = self._resolve_href(url, base_href, raw)
                if self._is_static_noise(full):
                    continue
                if self._allowed_domain(full):
                    lk = self._url_key(full)
                    if lk not in seen_link_keys:
                        seen_link_keys.add(lk)
                        links.append(full)
                    if tag == "script" and attr == "src":
                        pl = full.lower().split("?", 1)[0]
                        if pl.endswith((".js", ".mjs", ".cjs")):
                            with self._discovery_lock:
                                self._js_asset_urls.add(full)
                else:
                    self._record_drop(full, "off-domain")

        for form in soup.find_all("form"):
            # Empty action = submit to current document URL (HTML); "" is falsy → use page URL.
            action = form.get("action")
            if action is None:
                action = url
            else:
                action = action.strip() or url
            method = (form.get("method") or "get").strip().lower()
            action_url = self._resolve_href(url, base_href, action)

            if not self._allowed_domain(action_url):
                self._record_drop(action_url, "form action off-domain")
                continue

            params, field_details = self._parse_form_fields(form)
            enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip()
            form_nid = (form.get("id") or "").strip() or None
            form_nname = (form.get("name") or "").strip() or None

            page_forms.append(
                {
                    "method": method,
                    "action": action_url,
                    "fields": dict(params),
                    "field_details": field_details,
                    "source_url": url,
                    "enctype": enctype,
                    "form_id": form_nid,
                    "form_name": form_nname,
                },
            )

            summary = ", ".join(
                f"{d['name']}:{d['type']}" for d in field_details[:28]
            )
            if len(field_details) > 28:
                summary += ", …"
            logger.info(
                "  [form] %s %s | enctype=%s | fields=%s | %s",
                method.upper(),
                action_url,
                enctype,
                len(field_details),
                summary or "(no named fields)",
            )

            if not params:
                ak = self._url_key(action_url)
                if ak not in seen_link_keys and not self._is_static_noise(action_url):
                    seen_link_keys.add(ak)
                    links.append(action_url)
                continue

            param_url = f"{action_url}?{urlencode(params)}"
            form_urls.append(param_url)
            self._log_discovered_url(param_url, "form-probe")

            ak = self._url_key(action_url)
            if ak not in seen_link_keys and not self._is_static_noise(action_url):
                seen_link_keys.add(ak)
                links.append(action_url)

        return links, form_urls, page_forms

    def _is_static_noise(self, url: str) -> bool:
        try:
            path = urlparse(urldefrag(url)[0]).path.lower()
        except Exception:
            return False
        return any(path.endswith(ext) for ext in _STATIC_EXT)

    def _dedupe_and_filter_urls(self, urls: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            if not u:
                continue
            u0 = normalize_url(str(u).strip())
            if not u0 or self._is_static_noise(u0):
                if u0:
                    self._record_drop(u0, "static asset")
                continue
            if not self._allowed_domain(u0):
                self._record_drop(u0, "off-domain")
                continue
            key = u0.lower()  # same as _url_key(u)
            if key in seen:
                continue
            seen.add(key)
            out.append(u0)
        return out


def count_query_parameters(urls: list[str]) -> dict[str, Any]:
    """Aggregate query keys across URL list (for logging / metrics)."""
    keys: set[str] = set()
    for u in urls or []:
        if "?" not in u:
            continue
        try:
            q = urlparse(u).query
            for k in parse_qs(q, keep_blank_values=True).keys():
                if k:
                    keys.add(k)
        except Exception:
            continue
    return {"unique_query_keys": len(keys), "keys_sample": sorted(keys)[:40]}
