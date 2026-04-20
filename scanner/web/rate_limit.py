"""
scanner/web/rate_limit.py
=========================
Basic rate limiting / brute-force protection heuristics.

Non-destructive: performs a short burst of GET requests against a small set
of representative endpoints and looks for 429 / blocking behavior.
"""

from __future__ import annotations

from ..scan_logger import logger
import time
from urllib.parse import urlparse, urlunparse

from ..base_scanner import BaseScanner
from .base_module import ScanContext

class RateLimitScanner(BaseScanner):
    name = "rate"

    def __init__(self, urls: list[str], timeout: int = 10, proxy: str | None = None, **kwargs):
        super().__init__(urls, timeout=timeout, proxy=proxy, **kwargs)

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        # For modules taking singular 'url', use context.target
        self.url = context.target
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self) -> list[dict]:
        # Pick a few stable endpoints (strip query)
        uniq = []
        seen = set()
        for u in self.urls:
            try:
                p = urlparse(u)
                base = urlunparse(p._replace(query="", fragment=""))
            except Exception:
                base = u
            if base in seen:
                continue
            seen.add(base)
            uniq.append(base)
            if len(uniq) >= 5:
                break

        if not uniq:
            return []

        logger.info("  [*] Rate limit heuristic on %s endpoint(s)", len(uniq))
        findings: list[dict] = []
        for url in uniq:
            codes = []
            start = time.perf_counter()
            for _ in range(12):
                try:
                    time.sleep(0.5)  # Reduce pressure / user fix for stability
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                    codes.append(r.status_code)
                    if r.status_code in (429, 403):
                        break
                except Exception:
                    break
            elapsed = time.perf_counter() - start
            if 429 in codes:
                findings.append({
                    "type": "Rate Limiting — Detected",
                    "url": url,
                    "parameter": "N/A",
                    "payload": "Burst of GET requests",
                    "severity": "INFO",
                    "evidence": f"HTTP 429 observed during burst testing (elapsed {elapsed:.2f}s).",
                })
            else:
                # If never throttled, report as LOW only if endpoint looks sensitive
                if any(k in url.lower() for k in ["login", "signin", "auth", "token", "otp"]):
                    findings.append({
                        "type": "Rate Limiting — Not Observed (Heuristic)",
                        "url": url,
                        "parameter": "N/A",
                        "payload": "Burst of GET requests",
                        "severity": "LOW",
                        "evidence": "No throttling detected during a short burst. If this endpoint accepts credential attempts, implement rate limiting and lockouts.",
                    })
        return findings

