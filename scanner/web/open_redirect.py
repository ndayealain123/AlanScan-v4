"""
scanner/web/open_redirect.py  v1.0.0
======================================
Open Redirect Vulnerability Scanner.

Checks URL parameters that commonly accept redirect targets and tests
whether the application reflects payloads to external destinations.

Detection approach:
- Identifies candidate parameters using a hint list
- Tests payloads that redirect to evil.com
- Confirms by checking Location header or meta-refresh in body
- Handles both HTTP 3xx redirect responses and JS/meta-refresh redirects

Non-destructive: only sends GET/HEAD requests with crafted parameters.
"""

from __future__ import annotations

from ..scan_logger import logger
import re
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base_scanner import BaseScanner
from .base_module import ScanContext
import config

EVIL_HOST = "evil-scanner-test.com"
EVIL_URL  = f"https://{EVIL_HOST}/"

# Patterns that confirm an open redirect was followed
REDIRECT_CONFIRM_PATTERNS = [
    re.compile(rf"location:\s*https?://{re.escape(EVIL_HOST)}", re.IGNORECASE),
    re.compile(rf"window\.location\s*=\s*['\"]https?://{re.escape(EVIL_HOST)}", re.IGNORECASE),
    re.compile(rf'meta[^>]+http-equiv=["\']refresh["\'][^>]+url=https?://{re.escape(EVIL_HOST)}', re.IGNORECASE),
]


class OpenRedirectScanner(BaseScanner):
    """Scan for open redirect vulnerabilities in URL parameters."""

    name = "redirect"

    def __init__(self, urls: list[str], timeout: int = 10,
                 proxy: str | None = None, threads: int = 10, **kwargs):
        super().__init__(urls, timeout=timeout, proxy=proxy, threads=threads, **kwargs)

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        # For modules taking singular 'url', use context.target
        self.url = context.target
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self) -> list[dict]:
        findings: list[dict] = []

        # Collect candidate (url, param, payloads) triples
        candidates = self._collect_candidates()
        if not candidates:
            logger.info(
                "  [*] Open redirect: no redirect-like parameters found in crawled URLs"
            )
            return []

        logger.info(
            "  [*] Open redirect checks: %s candidate parameter(s)",
            len(candidates),
        )

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {
                ex.submit(self._test_candidate, url, param, payload): (url, param, payload)
                for url, param, payload in candidates
            }
            for fut in as_completed(futs):
                try:
                    result = fut.result()
                    if result:
                        findings.append(result)
                except Exception:
                    pass

        # Deduplicate by (url_base, param)
        seen, out = set(), []
        for f in findings:
            key = (f.get("url", "").split("?")[0], f.get("parameter", ""))
            if key not in seen:
                seen.add(key)
                out.append(f)

        return out

    def _collect_candidates(self) -> list[tuple[str, str, str]]:
        """Return (url, param, payload) tuples for redirect-like params."""
        candidates = []
        seen_params: set[tuple[str, str]] = set()

        for url in self.urls:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                continue

            for param in qs:
                if param.lower() in [h.lower() for h in config.OPEN_REDIRECT_PARAM_HINTS]:
                    base = urlunparse(parsed._replace(query=""))
                    key = (base, param)
                    if key in seen_params:
                        continue
                    seen_params.add(key)

                    for payload in config.OPEN_REDIRECT_PAYLOADS[:3]:  # top 3 payloads
                        candidates.append((url, param, payload))
                        break  # one payload per unique (url, param) initially

        # Also inject redirect params into URLs without them
        for url in self.urls[:20]:  # limit extra probes
            for hint in config.OPEN_REDIRECT_PARAM_HINTS[:5]:
                try:
                    parsed = urlparse(url)
                    if hint in parse_qs(parsed.query, keep_blank_values=True):
                        continue
                    base = urlunparse(parsed._replace(query=""))
                    key = (base, hint)
                    if key in seen_params:
                        continue
                    seen_params.add(key)
                    candidates.append((url, hint, EVIL_URL))
                except Exception:
                    continue

        return candidates

    def _test_candidate(self, url: str, param: str, payload: str) -> dict | None:
        """Test a single (url, param, payload) for open redirect."""
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            resp = self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False,   # don't follow — we need to see the Location header
            )

            # Check Location header
            location = resp.headers.get("Location", "")
            if EVIL_HOST in location:
                return {
                    "type": "Open Redirect",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "MEDIUM",
                    "evidence": (
                        f"HTTP {resp.status_code} — Location header redirects to external host: {location[:100]}"
                    ),
                }

            # Check body for meta-refresh or JS redirect
            if resp.status_code == 200:
                body = (resp.text or "")[:2000]
                for pattern in REDIRECT_CONFIRM_PATTERNS:
                    if pattern.search(body):
                        return {
                            "type": "Open Redirect",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "MEDIUM",
                            "evidence": (
                                f"HTTP 200 — JavaScript/meta-refresh redirect to {EVIL_HOST} found in response body."
                            ),
                        }
        except Exception:
            pass

        return None
