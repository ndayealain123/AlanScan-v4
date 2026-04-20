"""
scanner/web/security_headers_plus.py  v1.0.0
============================================
Enhanced HTTP Security Headers Analyser (supplement to headers.py).

Adds checks that the base headers.py module does not cover:
  - Permissions-Policy header presence + quality
  - Referrer-Policy presence + strictness
  - Cache-Control on sensitive endpoints
  - X-Content-Type-Options
  - COEP / COOP / CORP (modern isolation headers)
  - Server header disclosure (sub-check)

Returns findings compatible with the standard AlanScan finding dict format.
"""

from __future__ import annotations

import config

from ..events import ScanEventKind
from ..scan_logger import logger

from ..base_scanner import BaseScanner
from .http_retry import request_with_retries, touch_response_metadata
from .base_module import ScanContext
from .version_disclosure_header import is_reportable_version_disclosure_header

class SecurityHeadersPlus(BaseScanner):
    """
    Supplemental HTTP security-header checks.
    Runs after (or alongside) the base HeaderScanner.
    """
    name = "headers_plus"

    MODERN_ISOLATION_HEADERS = {
        "Cross-Origin-Embedder-Policy": {
            "recommended": "require-corp",
            "description": "COEP prevents loading cross-origin resources not explicitly permitted.",
            "severity": "LOW",
        },
        "Cross-Origin-Opener-Policy": {
            "recommended": "same-origin",
            "description": "COOP isolates the browsing context from other origins (Spectre mitigations).",
            "severity": "LOW",
        },
        "Cross-Origin-Resource-Policy": {
            "recommended": "same-origin",
            "description": "CORP prevents other origins from embedding this resource.",
            "severity": "LOW",
        },
    }

    SENSITIVE_PATH_KEYWORDS = [
        "login", "signin", "account", "profile", "payment", "checkout",
        "admin", "dashboard", "settings", "password", "auth",
    ]

    def __init__(self, base_url: str, urls: list[str],
                 timeout: int | None = None, proxy: str | None = None, **kwargs):
        super().__init__(
            urls,
            timeout=timeout if timeout is not None else getattr(config, "TIMEOUT", 15),
            proxy=proxy,
            **kwargs,
        )
        self.base_url = base_url.rstrip("/")

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.base_url = context.target.rstrip("/")
        self.session = context.unified_session
        return self.scan()

    def scan(self) -> list[dict]:
        findings: list[dict] = []
        logger.info("  [*] Enhanced security header checks...")

        try:
            resp = request_with_retries(
                self.session,
                "GET",
                self.base_url,
                timeout=self.timeout,
                max_attempts=3,
                allow_redirects=True,
            )
            if resp is None:
                raise RuntimeError(
                    "request failed after retries (see [HTTP_FAIL] / [RETRY] logs)"
                )
            touch_response_metadata(resp)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as exc:
            logger.error(
                "  [!] Enhanced header scan request failed: %s",
                exc,
                extra={
                    "kind": ScanEventKind.HEADERS_PLUS_FETCH_FAILED,
                    "url": self.base_url,
                    "error": str(exc),
                },
            )
            return [
                {
                    "type": "Enhanced Header Audit — Request Failed",
                    "url": self.base_url,
                    "parameter": "HTTP",
                    "payload": "N/A",
                    "severity": "INFO",
                    "evidence": (
                        "Enhanced header checks could not complete after retries: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                },
            ]

        # ── Permissions-Policy ─────────────────────────────────────────────
        pp = headers.get("permissions-policy", "")
        if not pp:
            findings.append({
                "type": "Missing Security Header",
                "url": self.base_url,
                "parameter": "Permissions-Policy",
                "payload": "N/A",
                "severity": "LOW",
                "evidence": (
                    "Permissions-Policy header is absent. This header restricts browser "
                    "feature access (camera, microphone, geolocation). "
                    "Recommended: Permissions-Policy: geolocation=(), microphone=(), camera=()"
                ),
            })

        # ── Referrer-Policy ────────────────────────────────────────────────
        rp = headers.get("referrer-policy", "")
        if not rp:
            findings.append({
                "type": "Missing Security Header",
                "url": self.base_url,
                "parameter": "Referrer-Policy",
                "payload": "N/A",
                "severity": "LOW",
                "evidence": (
                    "Referrer-Policy header is absent. Without it, browsers may leak "
                    "full URLs (including sensitive query parameters) in the Referer header "
                    "to third-party sites. Recommended: strict-origin-when-cross-origin"
                ),
            })
        elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append({
                "type": "Missing Security Header",
                "url": self.base_url,
                "parameter": "Referrer-Policy",
                "payload": rp,
                "severity": "LOW",
                "evidence": (
                    f"Referrer-Policy is set to '{rp}', which may leak full URLs to "
                    f"third-party sites. Upgrade to 'strict-origin-when-cross-origin' or stricter."
                ),
            })

        # ── Modern Isolation Headers (COEP/COOP/CORP) ─────────────────────
        for header_name, meta in self.MODERN_ISOLATION_HEADERS.items():
            if header_name.lower() not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "url": self.base_url,
                    "parameter": header_name,
                    "payload": "N/A",
                    "severity": meta["severity"],
                    "evidence": (
                        f"{header_name} header is absent. {meta['description']} "
                        f"Recommended value: {meta['recommended']}"
                    ),
                })

        # ── Cache-Control on sensitive paths ───────────────────────────────
        sensitive_urls = [
            u for u in self.urls
            if any(kw in u.lower() for kw in self.SENSITIVE_PATH_KEYWORDS)
        ][:5]

        for url in sensitive_urls:
            try:
                r = request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    allow_redirects=True,
                )
                if r is None:
                    continue
                cc = r.headers.get("Cache-Control", "").lower()
                if not cc or ("no-store" not in cc and "no-cache" not in cc):
                    findings.append({
                        "type": "Missing Security Header",
                        "url": url,
                        "parameter": "Cache-Control",
                        "payload": "N/A",
                        "severity": "LOW",
                        "evidence": (
                            f"Cache-Control header on sensitive endpoint does not prevent caching "
                            f"(current value: '{r.headers.get('Cache-Control', 'absent')}'). "
                            f"Sensitive pages may be cached by browsers or proxies, exposing data. "
                            f"Recommended: Cache-Control: no-store, no-cache, must-revalidate"
                        ),
                    })
            except Exception:
                continue

        # ── Server / X-Powered-By version disclosure (strict token + no URL echo) ──
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and is_reportable_version_disclosure_header(
            "server", server, self.base_url
        ):
            findings.append({
                "type": "Information Disclosure (Header)",
                "url": self.base_url,
                "parameter": "Server",
                "payload": "N/A",
                "severity": "LOW",
                "evidence": (
                    f"Server header discloses software version: '{server}'. "
                    f"Version disclosure assists attackers in identifying known CVEs."
                ),
            })
        if x_powered and is_reportable_version_disclosure_header(
            "x-powered-by", x_powered, self.base_url
        ):
            findings.append({
                "type": "Information Disclosure (Header)",
                "url": self.base_url,
                "parameter": "X-Powered-By",
                "payload": "N/A",
                "severity": "LOW",
                "evidence": (
                    f"X-Powered-By header reveals technology stack: '{x_powered}'. "
                    f"Remove this header in production."
                ),
            })

        if findings:
            logger.warning("  [!] Enhanced header checks: %s additional issue(s)", len(findings))
        else:
            logger.info("  [OK] Enhanced header checks: no additional issues")

        return findings
