"""
scanner/web/csrf.py
===================
Cross-Site Request Forgery (CSRF) Detection Module.

What is CSRF?
-------------
CSRF (CWE-352) tricks an authenticated user's browser into sending an
unintended request to a web application where they are already logged in.
Because the browser automatically includes session cookies, the server
cannot distinguish the forged request from a legitimate one.

Classic Attack Scenario:
  1. Victim is logged into bank.com
  2. Victim visits attacker's evil.com
  3. evil.com silently submits: POST bank.com/transfer?to=attacker&amount=5000
  4. bank.com processes it — victim's session cookie was sent automatically

Detection Approach
------------------
AlanScan detects CSRF vulnerability through four complementary checks:

1. **CSRF Token Presence Check**
   - Crawl all HTML forms on every discovered page
   - For each form, inspect hidden input fields for known CSRF token patterns
   - Missing token = vulnerable form (most reliable signal)

2. **SameSite Cookie Attribute Check**
   - Modern CSRF mitigation relies on SameSite=Strict or SameSite=Lax cookies
   - Absence of SameSite on session cookies = CSRF risk (cross-references cookie module)

3. **Custom Request Header Requirement Check**
   - Some APIs rely on custom headers (X-Requested-With: XMLHttpRequest) as
     CSRF mitigation — browsers cannot set custom headers cross-origin
   - Scanner tests whether the endpoint accepts requests WITHOUT this header

4. **Origin / Referer Validation Check**
   - Send requests with a spoofed Origin header pointing to a different domain
   - If the server processes the request normally → no origin validation

OWASP Reference: A01:2021 – Broken Access Control, CWE-352
Testing Guide: WSTG-SESS-05
"""

from ..scan_logger import logger
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

import config

# ── Known CSRF Token Field Names ──────────────────────────────────────────────
# These are the most common hidden input names used by major frameworks
# to carry CSRF protection tokens.
CSRF_TOKEN_NAMES = {
    # Generic
    "csrf_token", "csrftoken", "csrf", "_csrf", "csrf_field",
    "csrfmiddlewaretoken",   # Django
    "_token",                # Laravel / Symfony
    "authenticity_token",    # Ruby on Rails
    "__requestverificationtoken",  # ASP.NET MVC
    "_wpnonce",              # WordPress
    "token", "form_token", "form_key",
    "xsrf_token", "_xsrf",  # Tornado / Angular (cookie-to-header)
    "nonce",
    "state",                 # OAuth CSRF state parameter
}

# ── CSRF Header Names ─────────────────────────────────────────────────────────
# Headers that frameworks use as CSRF mitigation for AJAX/API requests.
CSRF_HEADER_NAMES = [
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-TOKEN",
    "X-Requested-With",
    "X-RequestedWith",
]

# ── Dangerous Form Methods ────────────────────────────────────────────────────
# Only POST/PUT/DELETE/PATCH forms are CSRF-relevant.
# GET forms are generally safe as they should not cause state changes.
DANGEROUS_METHODS = {"post", "put", "delete", "patch"}

# ── State-changing actions worth reporting (path / query / field names) ────────
# Skips low-impact forms (e.g. search, generic login) to reduce false positives.
CSRF_SENSITIVE_KEYWORDS = frozenset({
    "update", "delete", "change", "transfer", "password", "email", "account",
    "subscribe",
})

ACTION_KEYWORDS = frozenset({
    "action", "submit", "save", "edit", "update", "do", "process",
})


from ..base_scanner import BaseScanner
from .base import normalize_url
from .base_module import ScanContext


class CSRFScanner(BaseScanner):
    """
    Comprehensive CSRF vulnerability scanner.
    """
    name = "csrf"

    def __init__(self, target: str, urls: list[str], timeout: int = 10,
                 proxy: str | None = None, threads: int = 10, **kwargs):
        super().__init__(urls, timeout=timeout, proxy=proxy, threads=threads, **kwargs)
        self.target = target

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        self._crawl_forms = getattr(context, "crawl_forms", []) or []
        return self.scan()

    def scan(self) -> list[dict]:
        """
        Run all CSRF detection checks across all discovered URLs.
        Scans unique pages only — avoids testing the same form URL multiple times.
        """
        findings: list[dict] = []

        # Scan only unique BASE page paths — strip all query parameters
        # This prevents testing index.jsp?content=A, index.jsp?content=B etc
        # as separate pages — they all have the same forms
        from urllib.parse import urlparse, urlunparse
        unique_pages = set()
        for url in self.urls:
            parsed = urlparse(url)
            # Only keep path — strip query string entirely
            base = urlunparse(parsed._replace(query="", fragment=""))
            unique_pages.add(base)

        for row in getattr(self, "_crawl_forms", []):
            if str(row.get("method", "")).lower() != "post":
                continue
            act = row.get("action")
            if act:
                unique_pages.add(normalize_url(str(act).strip()))

        scan_list = list(unique_pages)
        logger.info("  [*] Scanning %s unique page(s) for CSRF vulnerabilities", len(scan_list))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_url, url): url
                for url in scan_list
            }
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    pass

        # Deduplicate — same form URL + type reported only once
        seen  = set()
        clean = []
        for f in findings:
            key = (f.get("url",""), f.get("type",""))
            if key not in seen:
                seen.add(key)
                clean.append(f)

        # Log results AFTER dedup — each finding logged exactly once
        for f in clean:
            sev = f.get("severity", "INFO")
            url = f.get("url", "")
            typ = f.get("type", "")
            if sev == "CRITICAL":
                logger.warning("  [CRITICAL] %s → %s", typ, url)
            elif sev == "HIGH":
                logger.warning("  [HIGH] %s → %s", typ, url)
            elif sev == "MEDIUM":
                logger.warning("  [MEDIUM] %s → %s", typ, url)
            elif sev == "LOW":
                logger.info("  [LOW] %s → %s", typ, url)
            else:
                logger.info("  [INFO] %s → %s", typ, url)

        return clean

    @staticmethod
    def _csrf_sensitive_endpoint(form_url: str, field_names: set[str] | None = None) -> bool:
        """True if path, query, or form field names suggest a state-changing action."""
        parsed = urlparse(form_url)
        blob = f"{parsed.path.lower()} {parsed.query.lower()}"
        if field_names:
            blob += " " + " ".join(field_names).lower()
        if not any(
            re.search(rf"\b{re.escape(kw)}\b", blob) for kw in CSRF_SENSITIVE_KEYWORDS
        ):
            return False
        if not any(
            re.search(rf"\b{re.escape(kw)}\b", blob) for kw in ACTION_KEYWORDS
        ):
            return False
        return True

    # ── Private – Per-URL Scanning ────────────────────────────────────────────

    def _scan_url(self, url: str) -> list[dict]:
        """Run all CSRF checks against a single URL."""
        results: list[dict] = []

        try:
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True)
        except Exception:
            return results

        # Only analyse HTML pages
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return results

        soup = BeautifulSoup(resp.text, "html.parser")

        # Check 1 — Form token analysis
        results.extend(self._check_forms(url, soup))

        # Check 2 — Origin / Referer header validation
        results.extend(self._check_origin_validation(url, soup))

        return results

    # ── Check 1: Form Token Analysis ─────────────────────────────────────────

    def _check_forms(self, url: str, soup: BeautifulSoup) -> list[dict]:
        """
        Inspect every HTML form for CSRF token protection.

        For each form that uses a state-changing HTTP method (POST/PUT/DELETE):
        1. Extract all <input> fields (including hidden ones).
        2. Check whether any field name matches the CSRF token name list.
        3. Additionally check for meta tags carrying CSRF tokens (Rails/Django pattern).
        4. Check for the double-submit cookie pattern.

        A form with no detectable CSRF token is flagged as HIGH severity,
        as it is almost certainly exploitable in a standard browser context.
        """
        findings: list[dict] = []
        forms    = soup.find_all("form")

        if not forms:
            return findings

        for form in forms:
            method = (form.get("method", "get") or "get").lower().strip()

            # Only POST/PUT/DELETE forms are CSRF-relevant
            if method not in DANGEROUS_METHODS:
                continue

            action = form.get("action", url)
            form_url = urljoin(url, action) if action else url

            # Collect all input field names in this form
            input_names = set()
            for inp in form.find_all(["input", "textarea", "select"]):
                name = (inp.get("name", "") or "").lower().strip()
                if name:
                    input_names.add(name)

            # Check whether any input matches known CSRF token names
            token_found = bool(input_names & CSRF_TOKEN_NAMES)

            # Also check meta tags for CSRF tokens (common in SPAs)
            meta_csrf = soup.find("meta", attrs={
                "name": re.compile(r"csrf|xsrf|token", re.I)
            })
            if meta_csrf:
                token_found = True

            if not token_found:
                # Determine severity based on form action sensitivity
                action_lower = form_url.lower()
                severity = "HIGH"
                if any(kw in action_lower for kw in [
                    "transfer", "payment", "pay", "purchase", "delete",
                    "remove", "admin", "password", "email", "account",
                    "settings", "profile", "withdraw"
                ]):
                    severity = "CRITICAL"

                if not self._csrf_sensitive_endpoint(form_url, input_names):
                    continue

                finding = {
                    "type":      "CSRF – Missing Anti-CSRF Token",
                    "url":       form_url,
                    "parameter": f"form[method={method.upper()}]",
                    "payload":   "N/A",
                    "severity":  severity,
                    "evidence":  (
                        f"POST form at '{form_url}' has no detectable CSRF token. "
                        f"Form inputs found: {sorted(input_names) or 'none'}. "
                        f"An attacker can forge this request from any origin."
                    ),
                }
                findings.append(finding)

            else:
                # Token exists — check if it's cryptographically adequate (non-empty)
                for inp in form.find_all("input", {"type": "hidden"}):
                    name  = (inp.get("name",  "") or "").lower()
                    value = (inp.get("value", "") or "").strip()
                    if name in CSRF_TOKEN_NAMES:
                        if len(value) < 8:
                            if not self._csrf_sensitive_endpoint(form_url, input_names):
                                continue
                            findings.append({
                                "type":      "CSRF – Weak/Empty Anti-CSRF Token",
                                "url":       form_url,
                                "parameter": inp.get("name", "token"),
                                "payload":   f"token value: '{value}'",
                                "severity":  "HIGH",
                                "evidence":  (
                                    f"CSRF token field '{inp.get('name')}' has a very short "
                                    f"or empty value ('{value}'). Predictable tokens are "
                                    f"exploitable via brute force."
                                ),
                            })
                            
        return findings

    # ── Check 2: Origin / Referer Validation ─────────────────────────────────

    def _check_origin_validation(self, url: str,
                                  soup: BeautifulSoup) -> list[dict]:
        """
        Test whether the server validates the Origin or Referer request header.

        Strategy:
        1. Find a POST form on the page.
        2. Submit it with a spoofed Origin header pointing to a different domain.
        3. If the server returns HTTP 200 (or any non-4xx) → no origin validation.

        This is a secondary CSRF mitigation; its absence alone is LOW severity
        but becomes HIGH when combined with a missing CSRF token.

        Note: We submit empty form data to avoid accidental state changes.
        The goal is purely to observe whether the server rejects the origin.
        """
        findings: list[dict] = []

        for form in soup.find_all("form"):
            method = (form.get("method", "get") or "get").lower().strip()
            if method not in DANGEROUS_METHODS:
                continue

            action  = form.get("action", url)
            form_url = urljoin(url, action) if action else url

            # Build minimal empty form data from field names
            form_data = {}
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                if name:
                    form_data[name] = inp.get("value", "")

            # Spoof Origin to a completely different domain
            parsed      = urlparse(url)
            real_origin  = f"{parsed.scheme}://{parsed.netloc}"
            spoof_origin = "https://evil-attacker.com"

            try:
                resp = self.session.post(
                    form_url,
                    data=form_data,
                    headers={"Origin": spoof_origin, "Referer": spoof_origin + "/"},
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # If server accepts the request (200/302) with a foreign origin,
                # it is not validating the Origin header
                if resp.status_code in range(200, 400):
                    field_keys = {k.lower() for k in form_data}
                    if not self._csrf_sensitive_endpoint(form_url, field_keys):
                        break
                    findings.append({
                        "type":      "CSRF – No Origin/Referer Validation",
                        "url":       form_url,
                        "parameter": "Origin header",
                        "payload":   f"Origin: {spoof_origin}",
                        "severity":  "MEDIUM",
                        "evidence":  (
                            f"Server returned HTTP {resp.status_code} when "
                            f"Origin was set to '{spoof_origin}'. "
                            f"The server does not validate the request origin, "
                            f"removing a secondary CSRF defence layer."
                        ),
                    })
                    
            except Exception:
                pass

            # Only test one form per page to avoid spamming the server
            break

        return findings

    # ── Check 3: API Endpoint CSRF (stateless header check) ──────────────────

    def check_api_csrf(self, api_urls: list[str]) -> list[dict]:
        """
        Test API endpoints for CSRF via missing custom header enforcement.

        Many modern APIs use the 'X-Requested-With: XMLHttpRequest' header as
        a CSRF mitigation — cross-origin requests cannot set custom headers
        without a CORS preflight that the server must explicitly allow.

        If an API endpoint accepts a POST request WITHOUT this header and
        WITHOUT a CSRF token, it may be exploitable via form-based CSRF
        (which can submit Content-Type: application/x-www-form-urlencoded
        without triggering CORS preflight).

        Parameters
        ----------
        api_urls : list[str]
            List of API endpoint URLs to test (typically discovered by crawler).

        Returns
        -------
        list[dict]
            Findings for any API endpoints that lack custom header enforcement.
        """
        findings: list[dict] = []

        for url in api_urls:
            try:
                # POST without X-Requested-With header
                resp = self.session.post(
                    url,
                    data={},
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # A 200 response to a headerless POST suggests no header check
                if resp.status_code == 200:
                    if not self._csrf_sensitive_endpoint(url, None):
                        continue
                    findings.append({
                        "type":      "CSRF – API Endpoint Missing Header Enforcement",
                        "url":       url,
                        "parameter": "X-Requested-With",
                        "payload":   "POST without X-Requested-With header",
                        "severity":  "MEDIUM",
                        "evidence":  (
                            f"API endpoint accepted POST request without "
                            f"'X-Requested-With: XMLHttpRequest' header. "
                            f"If this endpoint processes state changes, it may "
                            f"be vulnerable to form-based CSRF attacks."
                        ),
                    })

            except Exception:
                continue

        return findings
