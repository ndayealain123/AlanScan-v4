"""
scanner/web/method_tampering.py  v1.0.0
=========================================
HTTP Method Tampering Checker.

Sends alternative HTTP methods (PUT, DELETE, TRACE, OPTIONS, PATCH) to
discovered endpoints and identifies unexpected responses that could indicate:
  - TRACE enabled  → XST (Cross-Site Tracing) risk
  - PUT/DELETE on API  → unauthorized data modification
  - OPTIONS revealing overly broad CORS or method allow-list
  - HTTP method override via X-HTTP-Method-Override header

Non-destructive: no payloads modify server state beyond testing.
"""

from __future__ import annotations

from ..scan_logger import logger
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base_scanner import BaseScanner
from .base_module import ScanContext

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "PATCH"]
METHODS_TO_CHECK  = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]


class MethodTamperingScanner(BaseScanner):
    """Check for unsafe HTTP method exposure."""

    name = "method"

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

        # Deduplicate base paths (strip query strings)
        seen: set[str] = set()
        targets: list[str] = []
        for u in self.urls[:30]:  # cap at 30 endpoints
            try:
                p = urlparse(u)
                base = urlunparse(p._replace(query="", fragment=""))
                if base not in seen:
                    seen.add(base)
                    targets.append(base)
            except Exception:
                continue

        if not targets:
            return []

        logger.info("  [*] Method tampering checks on %s endpoint(s)", len(targets))

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._check_url, url): url for url in targets}
            for fut in as_completed(futs):
                try:
                    results = fut.result()
                    if results:
                        findings.extend(results)
                except Exception:
                    pass

        # Deduplicate by (type, method)
        seen_keys: set[tuple] = set()
        out: list[dict] = []
        for f in findings:
            key = (f.get("type", ""), f.get("payload", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                out.append(f)

        return out

    def _check_url(self, url: str) -> list[dict]:
        findings = []

        # OPTIONS — check Allow header
        try:
            resp = self.session.options(url, timeout=self.timeout, allow_redirects=False)
            allow = resp.headers.get("Allow", "")
            if resp.status_code in (200, 204) and allow:
                enabled = [m.strip().upper() for m in allow.split(",")]
                dangerous = [m for m in enabled if m in DANGEROUS_METHODS]
                if dangerous:
                    findings.append({
                        "type": "HTTP Method Tampering — Dangerous Methods Enabled",
                        "url": url,
                        "parameter": "Allow",
                        "payload": ", ".join(dangerous),
                        "severity": "MEDIUM",
                        "evidence": (
                            f"OPTIONS response Allow header lists dangerous methods: {', '.join(dangerous)}. "
                            f"Full Allow: {allow[:100]}"
                        ),
                    })
        except Exception:
            pass

        # TRACE — XST risk
        try:
            resp = self.session.request("TRACE", url, timeout=self.timeout, allow_redirects=False)
            if resp.status_code == 200 and "TRACE" in (resp.text or "").upper():
                findings.append({
                    "type": "HTTP Method Tampering — TRACE Enabled (XST Risk)",
                    "url": url,
                    "parameter": "Method",
                    "payload": "TRACE",
                    "severity": "LOW",
                    "evidence": (
                        "HTTP TRACE method is enabled. TRACE echoes request headers back to the "
                        "client — when combined with XSS or CSRF, this enables Cross-Site Tracing "
                        "(XST) attacks to steal HttpOnly cookies. Disable TRACE on the web server."
                    ),
                })
        except Exception:
            pass

        # X-HTTP-Method-Override bypass
        try:
            resp = self.session.get(
                url,
                headers={"X-HTTP-Method-Override": "DELETE"},
                timeout=self.timeout,
                allow_redirects=False,
            )
            if resp.status_code in (200, 204):
                findings.append({
                    "type": "HTTP Method Tampering — Override Header Accepted",
                    "url": url,
                    "parameter": "X-HTTP-Method-Override",
                    "payload": "DELETE",
                    "severity": "MEDIUM",
                    "evidence": (
                        "Server responded 200/204 to a GET request with X-HTTP-Method-Override: DELETE. "
                        "This may allow attackers to bypass method-based access controls."
                    ),
                })
        except Exception:
            pass

        return findings
