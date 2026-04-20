"""
scanner/web/headers.py
======================
HTTP Security Response Header Auditor.

Why Headers Matter
------------------
Security headers are the browser-side last line of defence against a wide class
of attacks.  Missing or misconfigured headers are consistently listed in the
OWASP Top 10 and are trivially exploitable.

Headers Audited
---------------
- Strict-Transport-Security (HSTS)  – Forces HTTPS, prevents SSL stripping
- X-Frame-Options                   – Prevents clickjacking via <iframe>
- X-Content-Type-Options            – Stops MIME-sniffing attacks
- Content-Security-Policy (CSP)     – Controls resource origins; XSS mitigation
- Referrer-Policy                   – Limits referrer leakage
- Permissions-Policy                – Disables dangerous browser APIs
- X-XSS-Protection                  – Legacy browser XSS filter
- Cross-Origin-Embedder-Policy      – Required for SharedArrayBuffer
- Cross-Origin-Opener-Policy        – Isolates the browsing context
- Cross-Origin-Resource-Policy      – Prevents spectre-style side-channel

Additionally, the scanner checks for:
- Server header disclosure (exposes software version)
- X-Powered-By header disclosure (exposes framework version)

OWASP Reference: A05:2021 – Security Misconfiguration
"""

from ..events import ScanEventKind
from ..scan_logger import logger

from ..base_scanner import BaseScanner
from .base_module import ScanContext
from .http_retry import request_with_retries, touch_response_metadata
from .version_disclosure_header import is_reportable_version_disclosure_header
import config

class HeaderScanner(BaseScanner):
    """
    Audits HTTP response headers for security best practices.

    Parameters
    ----------
    url : str
        Target URL (only the base URL needs to be checked for headers).
    timeout : int
        Request timeout.
    proxy : str | None
        Optional proxy URL.
    threads : int
        Unused by this module (single-request check) but accepted for API
        consistency with the controller.
    """

    name = "headers"

    def __init__(self, url: str, timeout: int | None = None,
                 proxy: str | None = None, threads: int = 10, **kwargs):
        super().__init__(
            url,
            timeout=timeout if timeout is not None else getattr(config, "TIMEOUT", 15),
            proxy=proxy,
            threads=threads,
            **kwargs,
        )
        self.url = url

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        # For modules taking singular 'url', use context.target
        self.url = context.target
        self.session = context.unified_session
        return self.scan()

    def scan(self) -> list[dict]:
        """
        Perform the header audit.

        Returns
        -------
        list[dict]
            One finding dict per missing or misconfigured header.
        """
        findings: list[dict] = []

        try:
            resp = request_with_retries(
                self.session,
                "GET",
                self.url,
                timeout=self.timeout,
                max_attempts=3,
                allow_redirects=True,
            )
            if resp is None:
                raise RuntimeError("request failed after retries (see [HTTP_FAIL] / [RETRY] logs)")
        except Exception as exc:
            logger.error(
                "Could not fetch target for header audit: %s",
                exc,
                extra={
                    "kind": ScanEventKind.HEADERS_FETCH_FAILED,
                    "url": self.url,
                    "error": str(exc),
                },
            )
            findings.append(
                {
                    "type": "Security Header Audit — Request Failed",
                    "url": self.url,
                    "parameter": "HTTP",
                    "payload": "N/A",
                    "severity": "INFO",
                    "confidence": "INFO",
                    "evidence": (
                        "Header audit could not complete after retries: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                },
            )
            return findings

        touch_response_metadata(resp)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # ── Missing Security Headers (grouped) ────────────────────────────
        missing = []
        for header, description in config.SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                missing.append({"header": header, "description": description})

        if missing:
            # Enterprise default: missing headers are usually LOW/MEDIUM (not HIGH),
            # unless the application is strictly HTTPS-only and HSTS is missing.
            missing_names = [m["header"] for m in missing]
            severity = self._missing_headers_severity(missing_names, self.url)
            logger.warning(
                "Missing security headers",
                extra={
                    "kind": ScanEventKind.HEADERS_MISSING_GROUP,
                    "severity": severity,
                    "header_names": ", ".join(missing_names),
                    "url": self.url,
                },
            )
            findings.append({
                "type": "Missing Security Headers",
                "url": self.url,
                "parameter": "response_headers",
                "payload": "N/A",
                "severity": severity,
                "confidence": "INFO",
                "evidence": (
                    "Missing recommended response headers: "
                    + ", ".join(f"{m['header']} ({m['description']})" for m in missing)
                ),
                "details": {
                    "missing_headers": missing_names,
                }
            })

        # ── Information Disclosure Headers ────────────────────────────────
        for disclosure_header in ["server", "x-powered-by", "x-aspnet-version",
                                   "x-aspnetmvc-version"]:
            if disclosure_header in headers_lower:
                value = headers_lower[disclosure_header]
                if not is_reportable_version_disclosure_header(
                    disclosure_header, value, self.url
                ):
                    continue
                finding = {
                    "type":      "Information Disclosure (Header)",
                    "url":       self.url,
                    "parameter": disclosure_header,
                    "payload":   "N/A",
                    "severity":  "LOW",
                    "evidence":  f"Header '{disclosure_header}: {value}' reveals software version",
                }
                logger.info(
                    "Version disclosure via response header",
                    extra={
                        "kind": ScanEventKind.HEADERS_VERSION_DISCLOSURE,
                        "header": disclosure_header,
                        "value": value,
                        "url": self.url,
                    },
                )
                findings.append(finding)

        # ── CSP Quality Check ─────────────────────────────────────────────
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            findings.extend(self._audit_csp(csp))

        # ── HSTS Quality Check ────────────────────────────────────────────
        hsts = headers_lower.get("strict-transport-security", "")
        if hsts and "max-age" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:  # Less than 1 year
                    findings.append({
                        "type":      "Weak HSTS Configuration",
                        "url":       self.url,
                        "parameter": "Strict-Transport-Security",
                        "payload":   "N/A",
                        "severity":  "MEDIUM",
                        "evidence":  f"HSTS max-age={max_age}s is below recommended 31536000s (1 year)",
                    })
            except (ValueError, IndexError):
                pass

        return findings

    # ── Private Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _missing_headers_severity(missing_headers: list[str], url: str) -> str:
        """
        Enterprise-aligned severity:
        - Missing headers are typically LOW (OWASP A05).
        - Following user request: HSTS and other missing headers are LOW.
        """
        return "LOW"

    def _audit_csp(self, csp: str) -> list[dict]:
        """
        Check the Content-Security-Policy for common dangerous misconfigurations.

        Known weak directives
        ---------------------
        - ``unsafe-inline``  – Allows inline <script> / <style>; negates XSS protection
        - ``unsafe-eval``    – Allows eval(); enables many XSS exploitation paths
        - ``*`` as a source  – Wildcard allows loading from any domain
        """
        issues: list[dict] = []
        csp_lower = csp.lower()

        if "unsafe-inline" in csp_lower:
            issues.append(self._csp_finding(
                "'unsafe-inline' present",
                "Inline scripts/styles allowed; XSS protection significantly weakened"
            ))
        if "unsafe-eval" in csp_lower:
            issues.append(self._csp_finding(
                "'unsafe-eval' present",
                "eval() calls allowed; code injection risk increased"
            ))
        if " * " in csp_lower or csp_lower.endswith("*"):
            issues.append(self._csp_finding(
                "Wildcard source (*)",
                "Resources loadable from any origin; CSP effectively bypassed"
            ))

        return issues

    def _csp_finding(self, issue: str, detail: str) -> dict:
        """Construct a CSP misconfiguration finding dict."""
        logger.warning(
            "CSP misconfiguration",
            extra={
                "kind": ScanEventKind.HEADERS_CSP_ISSUE,
                "issue": issue,
                "url": self.url,
            },
        )
        return {
            "type":      "CSP Misconfiguration",
            "url":       self.url,
            "parameter": "Content-Security-Policy",
            "payload":   "N/A",
            "severity":  "MEDIUM",
            "evidence":  f"{issue} – {detail}",
        }
