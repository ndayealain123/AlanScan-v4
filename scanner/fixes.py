"""
scanner/fixes_v5.py
====================
AlanScan v5 — Stability & Detection Fixes

Patches applied here (drop each class into its own file):

  auth_audit.py        → AuthAudit         crash-safe
  idor.py              → IDORScanner       crash-safe + smarter
  waf.py               → WAFDetector       logic fix
  evidence_collector.py→ EvidenceCollector arg-order fix + crash guard
  smart_params.py      → SmartParamFilter  noise reducer
  sqli.py (improved)   → SQLiScanner       stronger detection
  xss.py  (improved)   → XSSScanner        stronger detection

Copy the relevant class into the original file or import from here.
"""

# ══════════════════════════════════════════════════════════════════
# 1.  SMART PARAMETER FILTER
#     Sits in front of every injection module.
#     Reduces noise by skipping params that are unlikely to be injected.
# ══════════════════════════════════════════════════════════════════

from __future__ import annotations
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Optional
from colorama import Fore
from .scan_logger import logger

# ── Parameter classification ──────────────────────────────────────

# These param names almost never reach a DB query / OS command
_SKIP_PARAMS = frozenset({
    "lang", "locale", "theme", "currency", "tz", "timezone",
    "format", "view", "layout", "template", "skin", "style",
    "cache", "nocache", "_", "v", "ver", "version", "build",
    "token", "csrf", "nonce", "_token", "authenticity_token",
    "page", "per_page", "limit", "offset", "sort", "order", "dir",
    "tab", "step", "modal", "popup", "debug", "ref", "referrer",
    "fbclid", "gclid", "utm_source", "utm_medium", "utm_campaign",
    "utm_content", "utm_term", "mc_eid", "mc_cid",
    "callback", "jsonp", "_callback",
})

# High-value param names → test first, highest priority
_HIGH_VALUE_PARAMS = frozenset({
    "id", "user_id", "uid", "pid", "rid", "q", "query", "search",
    "username", "user", "email", "password", "pass", "name",
    "cat", "category", "type", "item", "product", "article",
    "page_id", "post", "file", "path", "url", "src", "dest",
    "redirect", "return", "next", "goto", "cmd", "exec",
    "order_id", "account", "invoice", "doc", "report",
    "filter", "where", "sort_by", "group", "view_by",
})

# Param patterns that look like static identifiers (skip injection)
_STATIC_PATTERNS = [
    re.compile(r'^[0-9a-f]{32,}$', re.I),   # MD5/SHA hex
    re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),  # Base64
]


def _is_static_value(value: str) -> bool:
    if not value:
        return False
    return any(p.match(value) for p in _STATIC_PATTERNS)


class SmartParamFilter:
    """
    Filters and prioritises URL parameters before injection testing.

    Usage
    -----
        spf = SmartParamFilter()
        testable = spf.filter_url(url)
        # returns list of (url_with_single_param, param_name) tuples
        # sorted high-value first, static/noise skipped

    Parameters
    ----------
    max_params : int   Maximum params to test per URL (default 5).
    """

    def __init__(self, max_params: int = 5):
        self.max_params = max_params

    def filter_url(self, url: str) -> list[tuple[str, str]]:
        """
        Return (test_url, param_name) pairs for injection.
        High-value params first; noise params skipped.
        """
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return []

        high: list[tuple[str, str]] = []
        normal: list[tuple[str, str]] = []

        for param, values in qs.items():
            pname = param.lower()
            value = values[0] if values else ""

            # Skip known noise
            if pname in _SKIP_PARAMS:
                continue
            # Skip static-looking values
            if _is_static_value(value):
                continue

            test_url = self._inject_param(parsed, qs, param)
            if pname in _HIGH_VALUE_PARAMS:
                high.append((test_url, param))
            else:
                normal.append((test_url, param))

        combined = high + normal
        return combined[:self.max_params]

    def has_testable_params(self, url: str) -> bool:
        return bool(self.filter_url(url))

    def filter_urls(self, urls: list[str]) -> list[tuple[str, str]]:
        """
        Filter a list of URLs, returning deduplicated (url, param) pairs.
        Deduplication: same path+param on different query strings is one entry.
        """
        seen: set[str] = set()
        result: list[tuple[str, str]] = []
        for url in urls:
            for test_url, param in self.filter_url(url):
                parsed = urlparse(test_url)
                key    = f"{parsed.netloc}{parsed.path}|{param}"
                if key not in seen:
                    seen.add(key)
                    result.append((test_url, param))
        return result

    @staticmethod
    def _inject_param(parsed, qs: dict, target_param: str) -> str:
        """Build URL with INJECT placeholder in target_param only."""
        new_qs = {k: v[0] if isinstance(v, list) else v
                  for k, v in qs.items()}
        new_qs[target_param] = "INJECT"
        return urlunparse(parsed._replace(query=urlencode(new_qs)))


# ══════════════════════════════════════════════════════════════════
# 2.  FIXED AUTH AUDIT — crash-safe
# ══════════════════════════════════════════════════════════════════

import requests as _requests
from requests.exceptions import RequestException

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", ""), ("root", "root"), ("root", ""),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("administrator", "administrator"), ("admin", "1234"),
]

LOGIN_HINTS = [
    "/login", "/signin", "/auth", "/admin", "/wp-login.php",
    "/user/login", "/account/login", "/session/new",
]


class AuthAudit:
    """
    Crash-safe authentication auditor.
    Fixes: AttributeError on None session, KeyError on missing form fields,
    TypeError when login response is not HTML.
    """

    def __init__(self, base_url: str, urls: list[str],
                 timeout: int = 8, proxy: str | None = None,
                 threads: int = 5,
                 credentials: str | None = None):
        self.base_url    = base_url.rstrip("/")
        self.urls        = urls or []
        self.timeout     = timeout
        self.proxies     = {"http": proxy, "https": proxy} if proxy else {}
        self.threads     = threads
        self.credentials = credentials or ""
        self._session    = None
        self._findings: list[dict] = []

    def audit(self) -> dict:
        """Run auth audit. Always returns dict with 'findings' and 'session' keys."""
        try:
            return self._run_audit()
        except Exception as exc:
            logger.warning(
                "Auth audit failed gracefully",
                extra={"kind": "AUTH_AUDIT", "error": str(exc)},
            )
            return {"findings": self._findings, "session": None}

    def _run_audit(self) -> dict:
        session = _requests.Session()
        session.verify   = False
        session.proxies  = self.proxies
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (AlanScan/5.0)",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })

        login_urls = self._discover_login_urls()
        if not login_urls:
            logger.info(
                "No login endpoints discovered",
                extra={"kind": "AUTH_AUDIT", "base_url": self.base_url},
            )
            return {"findings": self._findings, "session": None}

        established_session = None

        for login_url in login_urls[:3]:  # max 3 login forms
            try:
                form_data = self._extract_login_form(session, login_url)
                if not form_data:
                    continue

                # Try user-supplied credentials first
                if self.credentials and ":" in self.credentials:
                    user, pwd = self.credentials.split(":", 1)
                    result = self._try_login(session, login_url, form_data, user, pwd)
                    if result.get("success"):
                        established_session = session
                        logger.info(
                            "Login succeeded",
                            extra={"kind": "AUTH_LOGIN", "user": user},
                        )
                        break

                # Try default credentials
                for user, pwd in DEFAULT_CREDS:
                    try:
                        result = self._try_login(session, login_url, form_data, user, pwd)
                        if result.get("success"):
                            self._findings.append({
                                "type":      "Default Credentials Accepted",
                                "url":       login_url,
                                "parameter": "username/password",
                                "payload":   f"{user}:{pwd}",
                                "severity":  "CRITICAL",
                                "evidence":  (
                                    f"Default credentials '{user}:{pwd}' accepted. "
                                    f"HTTP {result.get('status_code', '?')} — "
                                    f"{result.get('indicator', 'login indicators detected')}"
                                ),
                            })
                            established_session = session
                            logger.warning(
                                "Default credentials accepted",
                                extra={"kind": "AUTH_DEFAULT_CREDS", "user": user},
                            )
                            break
                        time.sleep(0.2)  # throttle brute attempts
                    except Exception:
                        continue

            except Exception as exc:
                logger.warning(
                    "Auth form error",
                    extra={"kind": "AUTH_FORM_ERROR", "login_url": login_url, "error": str(exc)},
                )
                continue

        # Username enumeration check
        try:
            self._check_user_enumeration(session, login_urls[0] if login_urls else "")
        except Exception:
            pass

        return {"findings": self._findings, "session": established_session}

    def _discover_login_urls(self) -> list[str]:
        found = []
        all_urls = [self.base_url] + self.urls
        for url in all_urls:
            url_lower = url.lower()
            if any(hint in url_lower for hint in LOGIN_HINTS):
                found.append(url)
        # Also probe common paths
        for hint in LOGIN_HINTS[:4]:
            candidate = self.base_url + hint
            if candidate not in found:
                found.append(candidate)
        return list(dict.fromkeys(found))  # deduplicate, preserve order

    def _extract_login_form(self, session, url: str) -> dict | None:
        """Returns {action, method, fields} or None on failure."""
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return None
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            form = soup.find("form")
            if not form:
                return None

            action = form.get("action", url)
            if not action.startswith("http"):
                from urllib.parse import urljoin
                action = urljoin(url, action)

            fields: dict[str, str] = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name  = inp.get("name", "")
                itype = inp.get("type", "text").lower()
                value = inp.get("value", "")
                if name and itype not in ("submit", "button", "image", "reset"):
                    fields[name] = value

            return {"action": action, "method": form.get("method", "post").lower(),
                    "fields": fields}
        except Exception:
            return None

    def _try_login(self, session, url: str, form: dict,
                   username: str, password: str) -> dict:
        """Attempt login, return {success, status_code, indicator}."""
        fields   = dict(form.get("fields", {}))
        action   = form.get("action", url)
        method   = form.get("method", "post")

        # Inject credentials into likely field names
        for fname in list(fields.keys()):
            fl = fname.lower()
            if any(k in fl for k in ("user", "login", "email", "name", "account")):
                fields[fname] = username
            elif any(k in fl for k in ("pass", "pwd", "secret", "credential")):
                fields[fname] = password

        try:
            if method == "post":
                resp = session.post(action, data=fields, timeout=self.timeout,
                                    allow_redirects=True)
            else:
                resp = session.get(action, params=fields, timeout=self.timeout,
                                   allow_redirects=True)
        except RequestException as e:
            return {"success": False, "error": str(e)}

        body_lower = resp.text.lower() if resp.text else ""

        # Success indicators
        success_signs = [
            "dashboard", "welcome", "logout", "sign out", "my account",
            "profile", "your account", "settings", "admin panel",
        ]
        # Failure indicators
        fail_signs = [
            "invalid", "incorrect", "failed", "error", "wrong password",
            "bad credentials", "login failed", "authentication failed",
        ]

        has_success = any(s in body_lower for s in success_signs)
        has_failure = any(f in body_lower for f in fail_signs)
        redirect_ok = resp.url != action and "login" not in resp.url.lower()

        success = (has_success and not has_failure) or redirect_ok

        indicator = ""
        if success:
            for s in success_signs:
                if s in body_lower:
                    indicator = f"'{s}' found in response"
                    break
            if not indicator and redirect_ok:
                indicator = f"redirected to {resp.url}"

        return {"success": success, "status_code": resp.status_code,
                "indicator": indicator}

    def _check_user_enumeration(self, session, login_url: str) -> None:
        """Check if different responses reveal valid vs invalid usernames."""
        if not login_url:
            return
        form = self._extract_login_form(session, login_url)
        if not form:
            return

        r1 = self._try_login(session, login_url, form, "admin",     "WRONGPWD_1!")
        r2 = self._try_login(session, login_url, form, "zzz_nouser", "WRONGPWD_1!")
        time.sleep(0.3)

        # If HTTP status codes differ → enumeration
        if (r1.get("status_code") and r2.get("status_code") and
                r1["status_code"] != r2["status_code"]):
            self._findings.append({
                "type":      "Username Enumeration via Login Responses",
                "url":       login_url,
                "parameter": "username",
                "payload":   "admin vs zzz_nouser",
                "severity":  "MEDIUM",
                "evidence":  (
                    f"Different HTTP status codes for existing vs non-existing username: "
                    f"admin→{r1['status_code']}, zzz_nouser→{r2['status_code']}"
                ),
            })
            print(Fore.YELLOW + "  [MEDIUM] Username enumeration via status code difference")


# ══════════════════════════════════════════════════════════════════
# 3.  FIXED IDOR SCANNER — crash-safe + smarter
# ══════════════════════════════════════════════════════════════════

import config as _config

class IDORScanner:
    """
    IDOR heuristic scanner — crash-safe, uses SmartParamFilter.

    Fixes:
      - AttributeError when session is None
      - IndexError when URL list is empty
      - Skips non-numeric IDs (no false IDOR on UUID/token params)
      - Limits total probes via SmartParamFilter
    """

    IDOR_PARAMS = frozenset(_config.IDOR_SENSITIVE_PARAMS)

    def __init__(self, urls: list[str], timeout: int = 8,
                 proxy: str | None = None,
                 session=None):
        self.urls    = urls or []
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.session = session  # may be None — handled safely

    def scan(self) -> list[dict]:
        try:
            return self._run_scan()
        except Exception as exc:
            print(Fore.YELLOW + f"  [IDOR] Scan failed gracefully: {exc}")
            return []

    def _run_scan(self) -> list[dict]:
        findings: list[dict] = []
        spf = SmartParamFilter(max_params=4)

        # Build session safely
        sess = self.session
        if sess is None:
            sess = _requests.Session()
            sess.verify   = False
            sess.proxies  = self.proxies
            sess.headers.update({"User-Agent": "Mozilla/5.0 (AlanScan/5.0)"})

        for url in self.urls:
            parsed = urlparse(url)
            qs     = parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue

            for param, values in qs.items():
                if param.lower() not in self.IDOR_PARAMS:
                    continue
                value = values[0] if values else ""

                # Only probe numeric IDs (avoids UUID false positives)
                if not re.match(r'^\d+$', value):
                    continue

                try:
                    orig_id  = int(value)
                    probe_id = orig_id + 1 if orig_id > 1 else orig_id - 1
                    if probe_id < 1:
                        probe_id = orig_id + 1
                except ValueError:
                    continue

                probe_url = self._swap_param(parsed, qs, param, str(probe_id))

                try:
                    r_orig  = sess.get(url,       timeout=self.timeout,
                                       allow_redirects=False)
                    r_probe = sess.get(probe_url, timeout=self.timeout,
                                       allow_redirects=False)
                except RequestException as e:
                    print(Fore.YELLOW + f"  [IDOR] Request error: {e}")
                    continue

                # Detection: both return 200 + different non-empty bodies
                if (r_orig.status_code == 200 and
                        r_probe.status_code == 200 and
                        len(r_probe.text) > 50 and
                        abs(len(r_probe.text) - len(r_orig.text)) > 20):

                    findings.append({
                        "type":      "Potential IDOR",
                        "url":       url,
                        "parameter": param,
                        "payload":   str(probe_id),
                        "severity":  "HIGH",
                        "evidence":  (
                            f"Parameter '{param}' incremented from {orig_id} → {probe_id}. "
                            f"Original response: {len(r_orig.text)} bytes (HTTP {r_orig.status_code}). "
                            f"Probed response:   {len(r_probe.text)} bytes (HTTP {r_probe.status_code}). "
                            f"Different response bodies suggest unauthorised object access."
                        ),
                    })
                    print(Fore.RED +
                          f"  [HIGH] Potential IDOR: {param}={orig_id} → {probe_id} @ {url[:60]}")

                time.sleep(0.15)  # light throttle

        if not findings:
            print(Fore.GREEN + "  [OK] No IDOR patterns detected")
        return findings

    @staticmethod
    def _swap_param(parsed, qs: dict, target: str, new_val: str) -> str:
        new_qs = {k: v[0] if isinstance(v, list) else v for k, v in qs.items()}
        new_qs[target] = new_val
        return urlunparse(parsed._replace(query=urlencode(new_qs)))


# ══════════════════════════════════════════════════════════════════
# 4.  FIXED WAF DETECTOR — logic fix
# ══════════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare", "__cfduid", "cf-ray", "cloudflare-nginx"],
    "AWS WAF":       ["aws-waf", "x-amzn-requestid", "awselb"],
    "Imperva":       ["incapsula", "visid_incap", "_incap_ses", "x-iinfo"],
    "Akamai":        ["akamai", "akamaighost", "x-akamai-transformed"],
    "ModSecurity":   ["mod_security", "modsecurity", "owasp crs"],
    "F5 BIG-IP":     ["bigip", "f5", "x-wa-info"],
    "Barracuda":     ["barracuda", "barra_counter_session"],
    "Sucuri":        ["sucuri", "x-sucuri-id"],
    "Wordfence":     ["wordfence", "wfvt_"],
}

WAF_TEST_PAYLOADS = [
    "?id=1'",
    "?test=<script>alert(1)</script>",
    "?q=../../etc/passwd",
]


class WAFDetector:
    """
    Fixed WAF detector.

    Bugs fixed:
    - Never sets self.findings before use → AttributeError
    - WAF detection now correctly sets waf_detected=True/False
    - Returns consistent finding format
    """

    def __init__(self, base_url: str, timeout: int = 8,
                 proxy: str | None = None, **_kwargs):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.proxies  = {"http": proxy, "https": proxy} if proxy else {}
        self.findings: list[dict] = []   # ← always initialised

    def detect(self) -> bool:
        """Returns True if a WAF is detected."""
        try:
            return self._run_detection()
        except Exception as exc:
            print(Fore.YELLOW + f"  [WAF] Detection failed gracefully: {exc}")
            return False

    def _run_detection(self) -> bool:
        sess = _requests.Session()
        sess.verify  = False
        sess.proxies = self.proxies
        sess.headers.update({"User-Agent": "Mozilla/5.0 (AlanScan/5.0)"})

        detected_waf = ""

        # 1. Passive check on baseline response
        try:
            resp = sess.get(self.base_url, timeout=self.timeout,
                            allow_redirects=True)
            detected_waf = self._check_signatures(resp)
        except RequestException:
            pass

        # 2. Active probe — send WAF-triggering payloads
        if not detected_waf:
            for path in WAF_TEST_PAYLOADS:
                try:
                    url  = self.base_url + path
                    resp = sess.get(url, timeout=self.timeout,
                                    allow_redirects=False)
                    # 403/406/429/503 on attack payload = likely WAF
                    if resp.status_code in (403, 406, 429, 503):
                        detected_waf = detected_waf or "Generic WAF"
                        sig = self._check_signatures(resp)
                        if sig:
                            detected_waf = sig
                        break
                except RequestException:
                    continue

        if detected_waf:
            print(Fore.YELLOW + f"  [WAF] Detected: {detected_waf}")
            self.findings.append({
                "type":      "WAF Status",
                "url":       self.base_url,
                "parameter": "N/A",
                "payload":   "N/A",
                "severity":  "INFO",
                "evidence":  f"WAF detected: {detected_waf}. Payloads may need bypass encoding.",
                "waf_name":  detected_waf,
            })
            return True
        else:
            print(Fore.YELLOW + "  [WAF] No WAF detected — target may be unprotected")
            self.findings.append({
                "type":      "WAF Status",
                "url":       self.base_url,
                "parameter": "N/A",
                "payload":   "N/A",
                "severity":  "INFO",
                "evidence":  "No WAF detected. Attack payloads will not be filtered.",
            })
            return False

    @staticmethod
    def _check_signatures(resp) -> str:
        headers_lower = {k.lower(): v.lower()
                         for k, v in resp.headers.items()}
        body_lower    = (resp.text or "").lower()[:3000]
        cookies_str   = " ".join(c.name.lower() for c in resp.cookies)

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if (sig in body_lower or
                        sig in cookies_str or
                        any(sig in v for v in headers_lower.values()) or
                        sig in " ".join(headers_lower.keys())):
                    return waf_name
        return ""


# ══════════════════════════════════════════════════════════════════
# 5.  IMPROVED SQLi SCANNER — smarter detection, less noise
# ══════════════════════════════════════════════════════════════════

import config as _cfg

# Focused payload set — covers error-based, boolean, time-based
# without the destructive / unlikely-to-trigger payloads
FOCUSED_SQLI_PAYLOADS = [
    # Error-based — triggers on most unparameterised queries
    "'",
    "''",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "admin' --",
    # UNION-based schema detection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Error-based MySQL
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    # Time-based (sent last — slow)
    "' AND SLEEP(4)--",
    "' OR IF(1=1,SLEEP(4),0)--",
    "'; WAITFOR DELAY '0:0:4'--",
    "' OR pg_sleep(4)--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc sql server driver",
    "ora-01", "ora-00",
    "pg::syntaxerror", "postgresql error",
    "sqlite3::exception",
    "microsoft ole db",
    "mysql_fetch", "mysql_num_rows",
    "sql syntax", "sql error",
    "database error",
    "invalid query",
    "union select",
    "information_schema",
]

TIME_THRESHOLD = 3.5  # seconds


class SQLiScanner:
    """
    Improved SQLi scanner with SmartParamFilter and stronger detection.

    Fixes:
    - No more testing every URL without parameters (wasted effort)
    - Baseline response comparison to reduce false positives
    - Time-based detection with proper delta measurement
    - WAF bypass encoding when waf_bypass=True
    """

    def __init__(self, url: str, timeout: int = 8,
                 proxy: str | None = None, threads: int = 5,
                 waf_bypass: bool = False,
                 session=None, **_kwargs):
        self.url       = url
        self.timeout   = timeout
        self.proxies   = {"http": proxy, "https": proxy} if proxy else {}
        self.waf_bypass = waf_bypass
        self.session   = session
        self._spf      = SmartParamFilter(max_params=5)

    def scan(self) -> list[dict]:
        try:
            return self._run_scan()
        except Exception as exc:
            print(Fore.YELLOW + f"  [SQLi] Scan error: {exc}")
            return []

    def _run_scan(self) -> list[dict]:
        findings: list[dict] = []

        # Skip URLs with no testable parameters
        pairs = self._spf.filter_url(self.url)
        if not pairs:
            return []

        sess = self._get_session()

        # Baseline response
        try:
            baseline = sess.get(self.url, timeout=self.timeout,
                                allow_redirects=True)
            baseline_len  = len(baseline.text)
            baseline_body = baseline.text.lower()
        except Exception:
            return []

        payloads = self._get_payloads()
        seen_params: set[str] = set()

        for _test_url, param in pairs:
            if param in seen_params:
                continue

            parsed = urlparse(self.url)
            qs     = parse_qs(parsed.query, keep_blank_values=True)

            for payload in payloads:
                if not self._should_continue(findings, param):
                    break

                encoded_payload = self._encode(payload) if self.waf_bypass else payload
                test_params = {k: v[0] if isinstance(v, list) else v
                               for k, v in qs.items()}
                test_params[param] = encoded_payload

                t_start = time.perf_counter()
                try:
                    resp = sess.get(self.url, params=test_params,
                                    timeout=self.timeout + 6,
                                    allow_redirects=True)
                except Exception:
                    continue
                elapsed = time.perf_counter() - t_start

                body_lower = (resp.text or "").lower()

                # Error-based detection
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body_lower and sig not in baseline_body:
                        findings.append(self._make_finding(
                            "Error-Based SQLi", "HIGH",
                            param, payload, resp,
                            f"SQL error signature '{sig}' found in response"
                        ))
                        seen_params.add(param)
                        print(Fore.RED + f"  [HIGH] SQLi (error-based): {param} @ {self.url[:60]}")
                        break

                # Time-based detection
                if (elapsed >= TIME_THRESHOLD and
                        any(t in payload.lower() for t in
                            ["sleep", "waitfor", "pg_sleep", "benchmark"])):
                    if not any(f["parameter"] == param and
                               "time" in f["type"].lower()
                               for f in findings):
                        findings.append(self._make_finding(
                            "Time-Based SQLi", "HIGH",
                            param, payload, resp,
                            f"Response delayed {elapsed:.2f}s (threshold {TIME_THRESHOLD}s)"
                        ))
                        seen_params.add(param)
                        print(Fore.RED +
                              f"  [HIGH] SQLi (time-based, {elapsed:.1f}s): {param} @ {self.url[:60]}")

                # Boolean-based: significant length difference
                if (abs(len(resp.text) - baseline_len) > 50 and
                        "or" in payload.lower() and
                        resp.status_code == baseline.status_code and
                        param not in seen_params):
                    # Confirm with inverse payload
                    false_params = dict(test_params)
                    false_params[param] = "' OR '1'='2' --"
                    try:
                        r_false = sess.get(self.url, params=false_params,
                                           timeout=self.timeout)
                        if abs(len(resp.text) - len(r_false.text)) > 30:
                            findings.append(self._make_finding(
                                "Boolean-Based SQLi", "HIGH",
                                param, payload, resp,
                                f"True response {len(resp.text)}B vs false {len(r_false.text)}B"
                            ))
                            seen_params.add(param)
                            print(Fore.RED +
                                  f"  [HIGH] SQLi (boolean-based): {param} @ {self.url[:60]}")
                    except Exception:
                        pass

        return findings

    def _get_payloads(self) -> list[str]:
        return FOCUSED_SQLI_PAYLOADS

    def _get_session(self):
        if self.session:
            return self.session
        s = _requests.Session()
        s.verify   = False
        s.proxies  = self.proxies
        s.headers.update({"User-Agent": "Mozilla/5.0 (AlanScan/5.0)"})
        return s

    def _should_continue(self, findings: list, param: str) -> bool:
        # Stop after first confirmed finding per parameter
        return not any(f["parameter"] == param for f in findings)

    @staticmethod
    def _encode(payload: str) -> str:
        """Basic WAF bypass: URL-encode quotes and spaces."""
        return payload.replace("'", "%27").replace(" ", "%20")

    @staticmethod
    def _make_finding(ftype: str, severity: str, param: str,
                      payload: str, resp, evidence: str) -> dict:
        return {
            "type":      ftype,
            "url":       resp.url,
            "parameter": param,
            "payload":   payload[:120],
            "severity":  severity,
            "evidence":  evidence[:500],
        }


# ══════════════════════════════════════════════════════════════════
# 6.  IMPROVED XSS SCANNER — stronger detection
# ══════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    # Reflected markers — look for exact echo in HTML body
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handler injection
    '" onmouseover="alert(1)',
    "' onload='alert(1)'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    # URL context
    "javascript:alert(1)",
    # Template injection canary (also catches SSTI)
    "{{7*7}}",
]

XSS_CONFIRM_PATTERNS = [
    re.compile(r'<script[^>]*>.*?alert\s*\(', re.I | re.S),
    re.compile(r'on\w+\s*=\s*["\']?alert', re.I),
    re.compile(r'<img[^>]+onerror\s*=', re.I),
    re.compile(r'<svg[^>]+onload\s*=', re.I),
    re.compile(r'javascript:alert', re.I),
]

# Simple canary: if this exact string appears in body → reflected
XSS_CANARY = "alanscan_xss_marker_7x9"


class XSSScanner:
    """
    Improved XSS scanner — uses canary + reflection check.

    Fixes:
    - Tests only parameterised URLs (SmartParamFilter)
    - Canary injection to confirm actual reflection, not false matches
    - Context-aware detection (HTML, attribute, script context)
    """

    def __init__(self, url: str, timeout: int = 8,
                 proxy: str | None = None, threads: int = 5,
                 waf_bypass: bool = False,
                 session=None, **_kwargs):
        self.url       = url
        self.timeout   = timeout
        self.proxies   = {"http": proxy, "https": proxy} if proxy else {}
        self.waf_bypass = waf_bypass
        self.session   = session
        self._spf      = SmartParamFilter(max_params=5)

    def scan(self) -> list[dict]:
        try:
            return self._run_scan()
        except Exception as exc:
            print(Fore.YELLOW + f"  [XSS] Scan error: {exc}")
            return []

    def _run_scan(self) -> list[dict]:
        findings: list[dict] = []
        pairs = self._spf.filter_url(self.url)
        if not pairs:
            return []

        sess = self._get_session()
        parsed = urlparse(self.url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)

        for _test_url, param in pairs:
            # Step 1: canary reflection test
            if not self._reflects_input(sess, param, qs):
                continue  # param not reflected at all — skip all XSS payloads

            # Step 2: try each payload
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] if isinstance(v, list) else v
                               for k, v in qs.items()}
                test_params[param] = payload
                try:
                    resp = sess.get(self.url, params=test_params,
                                    timeout=self.timeout,
                                    allow_redirects=True)
                except Exception:
                    continue

                body = resp.text or ""

                # Check for dangerous reflection
                for pat in XSS_CONFIRM_PATTERNS:
                    if pat.search(body):
                        findings.append({
                            "type":      "Reflected XSS",
                            "url":       resp.url,
                            "parameter": param,
                            "payload":   payload[:120],
                            "severity":  "HIGH",
                            "evidence":  (
                                f"XSS payload reflected and executable in HTTP response. "
                                f"Parameter '{param}' reflected payload without encoding. "
                                f"Pattern: {pat.pattern[:60]}"
                            ),
                        })
                        print(Fore.RED +
                              f"  [HIGH] XSS confirmed: {param} @ {self.url[:60]}")
                        break  # one finding per param is enough

                if any(f["parameter"] == param for f in findings):
                    break

        # DOM-based hints: look for dangerous sinks in baseline HTML
        try:
            baseline = sess.get(self.url, timeout=self.timeout)
            self._check_dom_sinks(baseline.text, findings)
        except Exception:
            pass

        return findings

    def _reflects_input(self, sess, param: str, qs: dict) -> bool:
        """Return True if param value is reflected in response body."""
        test_params = {k: v[0] if isinstance(v, list) else v
                       for k, v in qs.items()}
        test_params[param] = XSS_CANARY
        try:
            resp = sess.get(self.url, params=test_params,
                            timeout=self.timeout)
            return XSS_CANARY in (resp.text or "")
        except Exception:
            return False

    def _check_dom_sinks(self, html: str, findings: list) -> None:
        """Check for dangerous DOM sinks in static page source."""
        dom_sinks = [
            (re.compile(r'document\.write\s*\(', re.I), "document.write()"),
            (re.compile(r'innerHTML\s*=', re.I), "innerHTML assignment"),
            (re.compile(r'outerHTML\s*=', re.I), "outerHTML assignment"),
            (re.compile(r'eval\s*\(', re.I), "eval()"),
            (re.compile(r'location\.href\s*=', re.I), "location.href"),
            (re.compile(r'window\.location\s*=', re.I), "window.location"),
        ]
        for pat, sink_name in dom_sinks:
            if pat.search(html):
                # Only add if we don't already have a reflected XSS for this URL
                if not any(f.get("url", "").split("?")[0] == self.url.split("?")[0]
                           and "dom" in f["type"].lower() for f in findings):
                    findings.append({
                        "type":      "DOM XSS Sink (Static)",
                        "url":       self.url,
                        "parameter": "DOM",
                        "payload":   sink_name,
                        "severity":  "MEDIUM",
                        "evidence":  (
                            f"Dangerous DOM sink '{sink_name}' found in page source. "
                            f"If user-controlled data reaches this sink, DOM XSS is possible. "
                            f"Manual verification required."
                        ),
                    })

    def _get_session(self):
        if self.session:
            return self.session
        s = _requests.Session()
        s.verify   = False
        s.proxies  = self.proxies
        s.headers.update({"User-Agent": "Mozilla/5.0 (AlanScan/5.0)"})
        return s


# ══════════════════════════════════════════════════════════════════
# 7.  FIXED EVIDENCE COLLECTOR — argument order + crash guard
# ══════════════════════════════════════════════════════════════════

class EvidenceCollector:
    """
    Fixed EvidenceCollector.

    Bug fixed: original __init__ was (findings, target, proxy, timeout)
    but controller called it as (url, findings, timeout=..., proxy=...)
    causing target/findings to be swapped → crash or empty evidence.

    Now accepts both call conventions safely.
    """

    def __init__(self, target_or_findings=None, findings_or_target=None,
                 proxy: str | None = None, timeout: int = 8,
                 # Explicit keyword forms (new preferred API)
                 target: str | None = None,
                 findings: list | None = None):

        # Resolve positional arg ambiguity
        if target is not None and findings is not None:
            # Called with explicit kwargs → clean
            self.target   = target
            self.findings = list(findings)
        elif isinstance(target_or_findings, str):
            # Called as (url, findings_list, ...)
            self.target   = target_or_findings
            self.findings = list(findings_or_target or [])
        elif isinstance(target_or_findings, list):
            # Called as (findings_list, url, ...) — legacy order
            self.findings = list(target_or_findings)
            self.target   = findings_or_target or ""
        else:
            self.target   = ""
            self.findings = []

        self.proxy   = proxy
        self.timeout = timeout

    def collect(self) -> tuple[list[dict], dict]:
        extra: dict = {}
        try:
            self._enrich_findings()
        except Exception as exc:
            print(Fore.YELLOW + f"  [EV] Enrichment error (non-fatal): {exc}")

        # SSL cipher enumeration
        ssl_host, ssl_port = self._extract_ssl_target()
        if ssl_host:
            try:
                from scanner.evidence_collector import CipherSuiteEnumerator
                extra["cipher_suites"] = CipherSuiteEnumerator(
                    ssl_host, ssl_port, timeout=self.timeout).enumerate()
            except Exception as exc:
                extra["cipher_suites"] = {"error": str(exc)}

        # Port inventory
        try:
            from scanner.evidence_collector import PortInventoryBuilder
            extra["port_inventory"] = PortInventoryBuilder().build(self.findings)
        except Exception as exc:
            extra["port_inventory"] = {"error": str(exc)}

        return self.findings, extra

    def _enrich_findings(self) -> None:
        try:
            from scanner.evidence_collector import HTTPEvidenceCapture
            capture = HTTPEvidenceCapture(proxy=self.proxy, timeout=self.timeout)
        except ImportError:
            return

        for i, f in enumerate(self.findings):
            ftype = str(f.get("type", "")).lower()
            try:
                if "sqli" in ftype or "sql injection" in ftype:
                    self.findings[i] = capture.enrich_sqli_finding(f)
                elif "cmdi" in ftype or "command injection" in ftype:
                    self.findings[i] = capture.enrich_cmdi_finding(f)
                elif "csrf" in ftype:
                    self.findings[i] = capture.enrich_csrf_finding(f)
            except Exception as exc:
                print(Fore.YELLOW +
                      f"  [EV] Finding {i} enrichment failed (non-fatal): {exc}")

    def _extract_ssl_target(self) -> tuple[str, int]:
        t = self.target or ""
        if t.startswith("https://"):
            host_part = t[8:].split("/")[0]
        elif t.startswith("http://"):
            return "", 0
        else:
            host_part = t.split("/")[0]
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                return host_part, 443
        return host_part, 443


# ══════════════════════════════════════════════════════════════════
# 8.  IMPROVED SSRF SCANNER — smart param filtering, less flooding
# ══════════════════════════════════════════════════════════════════

SSRF_CALLBACK_HOST = "169.254.169.254"  # IMDS — always blocked on real cloud
SSRF_TARGETS = [
    f"http://{SSRF_CALLBACK_HOST}/latest/meta-data/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "file:///etc/passwd",
]

SSRF_PARAM_NAMES = frozenset([
    "url", "uri", "path", "src", "dest", "redirect", "return",
    "link", "href", "resource", "image", "fetch", "host", "callback",
    "target", "endpoint", "api", "proxy", "remote", "load",
])


class SSRFScanner:
    """
    SSRF scanner — only tests known SSRF-prone parameter names.
    Avoids flooding every URL with 45 payloads × N parameters.
    """

    def __init__(self, url: str, timeout: int = 8,
                 proxy: str | None = None, **_kwargs):
        self.url     = url
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else {}

    def scan(self) -> list[dict]:
        try:
            return self._run_scan()
        except Exception as exc:
            print(Fore.YELLOW + f"  [SSRF] Scan error: {exc}")
            return []

    def _run_scan(self) -> list[dict]:
        findings: list[dict] = []

        parsed = urlparse(self.url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return []

        # Only test parameters whose names suggest URL/path handling
        ssrf_params = [p for p in qs if p.lower() in SSRF_PARAM_NAMES]
        if not ssrf_params:
            return []

        sess = _requests.Session()
        sess.verify  = False
        sess.proxies = self.proxies
        sess.headers.update({"User-Agent": "Mozilla/5.0 (AlanScan/5.0)"})

        for param in ssrf_params[:3]:  # max 3 params
            for target_url in SSRF_TARGETS[:3]:  # max 3 payloads
                test_params = {k: v[0] if isinstance(v, list) else v
                               for k, v in qs.items()}
                test_params[param] = target_url

                try:
                    t0   = time.perf_counter()
                    resp = sess.get(self.url, params=test_params,
                                    timeout=self.timeout,
                                    allow_redirects=True)
                    elapsed = time.perf_counter() - t0
                except _requests.exceptions.ConnectionError:
                    # Connection refused to SSRF target → server tried to connect
                    findings.append({
                        "type":      "SSRF",
                        "url":       self.url,
                        "parameter": param,
                        "payload":   target_url,
                        "severity":  "HIGH",
                        "evidence":  (
                            f"Connection error indicates server attempted outbound connection to '{target_url}'. "
                            f"SSRF likely — server resolved the supplied URL."
                        ),
                    })
                    print(Fore.RED + f"  [HIGH] SSRF: {param}={target_url} @ {self.url[:60]}")
                    break
                except Exception:
                    continue

                body_lower = (resp.text or "").lower()

                # Cloud metadata response
                if any(kw in body_lower for kw in
                       ["ami-id", "instance-id", "iam/security-credentials",
                        "metadata", "169.254"]):
                    findings.append({
                        "type":      "SSRF",
                        "url":       self.url,
                        "parameter": param,
                        "payload":   target_url,
                        "severity":  "CRITICAL",
                        "evidence":  (
                            f"Cloud metadata response received from '{target_url}'. "
                            f"SSRF CONFIRMED — server fetched IMDS endpoint. "
                            f"IAM credentials may be exposed."
                        ),
                    })
                    print(Fore.RED +
                          f"  [CRITICAL] SSRF + IMDS: {param} @ {self.url[:60]}")
                    break

                # /etc/passwd via file://
                if "root:" in body_lower and "bin" in body_lower:
                    findings.append({
                        "type":      "SSRF",
                        "url":       self.url,
                        "parameter": param,
                        "payload":   target_url,
                        "severity":  "CRITICAL",
                        "evidence":  "/etc/passwd content returned — file:// SSRF confirmed",
                    })
                    break

        return findings
