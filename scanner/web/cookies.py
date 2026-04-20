"""
scanner/web/cookies.py
======================
Cookie Security Attribute Auditor.

Why Cookie Security Matters
---------------------------
Session cookies are the primary target of session hijacking attacks.
Three attributes protect them:

- ``HttpOnly``  – Prevents JavaScript from reading the cookie value.
                  Mitigates XSS-based session theft.
- ``Secure``    – Cookie is only transmitted over HTTPS connections.
                  Prevents cookie leakage over HTTP (SSL-stripping attacks).
- ``SameSite``  – Controls cross-site request behaviour.
                  ``Strict`` / ``Lax`` mitigate CSRF attacks.
                  ``None`` (without Secure) is dangerous.

Additionally:
- Overly long ``Max-Age`` / ``Expires`` values create persistent cookies that
  survive browser close and increase the exploitation window.
- Broad ``Domain`` / ``Path`` scopes increase the attack surface.

OWASP Reference: A07:2021 – Identification and Authentication Failures
"""

from urllib.parse import urlparse

import config

from ..events import ScanEventKind
from ..scan_logger import logger

from ..base_scanner import BaseScanner
from .base_module import ScanContext
from .http_retry import request_with_retries, touch_response_metadata

# Load-balancer / CDN / edge cookies — not set by the application itself.
_INFRA_COOKIE_NOTE = "Managed by infrastructure, not app-controlled."

_INFRA_COOKIE_PREFIXES = (
    "awsalb",
    "awsalbtg",
    "__cf",
    "_cf",
    "cf_clearance",
    "cf_bm",
    "incap_ses",
    "visid_incap",
    "nlbi_",
    "ak_bmsc",
    "bm_sz",
    "_abck",
    "bigipserver",
    "f5_cspm",
    "f5avr",
    "citrix_ns_id",
    "dtcookie",  # Dynatrace RUM
    "rxvisitor",
    "dtpc",
    "rxvt",
)

_INFRA_COOKIE_SUBSTRINGS = (
    "arraffinity",
    "applicationgatewayaffinity",
    "google_lb",
)

# Analytics / marketing cookies — missing security flags are lower risk than session cookies.
_ANALYTICS_COOKIE_PREFIXES = (
    "_ga",
    "_gid",
    "_gat",
    "__utm",
    "utm_",
    "_fbp",
    "_fbc",
    "_hj",
    "_pk_",
    "intercom",
    "mp_",
    "amplitude",
)


def _is_analytics_or_tracking_cookie(name: str) -> bool:
    nl = (name or "").strip().lower()
    return any(nl.startswith(p) for p in _ANALYTICS_COOKIE_PREFIXES)


def _is_infrastructure_cookie(name: str) -> bool:
    nl = (name or "").strip().lower()
    if not nl:
        return False
    for p in _INFRA_COOKIE_PREFIXES:
        if nl.startswith(p):
            return True
    return any(s in nl for s in _INFRA_COOKIE_SUBSTRINGS)


def _normalize_cookie_domain(dom: str) -> str:
    d = (dom or "").strip().lower()
    if d.startswith("."):
        d = d[1:]
    return d


def _default_cookie_path_from_request_path(url_path: str) -> str:
    """RFC 6265 default-path: directory of the request-path."""
    if not url_path:
        return "/"
    p = url_path if url_path.startswith("/") else "/" + url_path
    if p.endswith("/"):
        return p if len(p) > 1 else "/"
    if "/" not in p.rstrip("/"):
        return "/"
    parent = p.rsplit("/", 1)[0]
    return parent + "/" if parent.startswith("/") else "/" + parent + "/"


def _normalize_cookie_path_value(path: str | None) -> str:
    """Ensure path is non-empty and starts with ``/``."""
    p = (str(path).strip() if path else "") or "/"
    return p if p.startswith("/") else "/" + p


def _cookie_context_host_path(scanner_url: str, hop) -> tuple[str, str]:
    """Request host + default cookie path for a response hop (redirect or final)."""
    url = getattr(hop, "url", None) or ""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    def_path = _default_cookie_path_from_request_path(p.path or "/")
    if not host and scanner_url:
        p2 = urlparse(scanner_url)
        host = (p2.hostname or "").lower()
        def_path = _default_cookie_path_from_request_path(p2.path or "/")
    return host, def_path


class CookieScanner(BaseScanner):
    """
    Audits Set-Cookie response headers for missing security attributes.

    Parameters
    ----------
    url : str
        Target URL to fetch cookies from.
    timeout : int
        Request timeout.
    proxy : str | None
        Optional proxy.
    threads : int
        Unused – accepted for controller API consistency.
    """

    name = "cookies"

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
        Fetch the target URL and audit all Set-Cookie headers.

        Returns
        -------
        list[dict]
            One finding per missing or weak cookie attribute.
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
                raise RuntimeError(
                    "request failed after retries (see [HTTP_FAIL] / [RETRY] logs)"
                )
        except Exception as exc:
            logger.error(
                "  [!] Cookie scan request failed: %s",
                exc,
                extra={
                    "kind": ScanEventKind.COOKIES_FETCH_FAILED,
                    "url": self.url,
                    "error": str(exc),
                },
            )
            findings.append(
                {
                    "type": "Cookie Security Audit — Request Failed",
                    "url": self.url,
                    "parameter": "HTTP",
                    "payload": "N/A",
                    "severity": "INFO",
                    "evidence": (
                        "Cookie audit could not complete after retries: "
                        f"{type(exc).__name__}: {exc}"
                    ),
                },
            )
            return findings

        touch_response_metadata(resp)
        all_cookies = self._collect_set_cookie_strings(resp)

        if not all_cookies:
            logger.warning("  [!] No Set-Cookie headers found")
            return findings

        for cookie_str in all_cookies:
            if not cookie_str:
                continue
            findings.extend(self._audit_cookie(cookie_str))

        return findings

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _cookie_jar_entry_to_set_cookie(cookie) -> str:
        """Build a Set-Cookie-like string from a cookielib/requests cookie for auditing."""
        parts = [f"{cookie.name}={cookie.value}"]
        dom = getattr(cookie, "domain", None)
        if dom:
            parts.append(f"Domain={dom}")
        cpath = getattr(cookie, "path", None)
        if cpath and str(cpath).strip():
            parts.append(f"Path={cpath}")
        if getattr(cookie, "secure", False):
            parts.append("Secure")
        rest = getattr(cookie, "_rest", None) or {}
        if isinstance(rest, dict):
            for rk, rv in rest.items():
                lk = rk.lower()
                if lk in ("domain", "path"):
                    continue
                if lk == "httponly":
                    parts.append("HttpOnly")
                elif lk == "samesite" and rv:
                    parts.append(f"SameSite={rv}")
                elif rv is None or rv == "":
                    parts.append(rk)
                else:
                    parts.append(f"{rk}={rv}")
        if getattr(cookie, "expires", None):
            parts.append("Expires=Wed, 01 Jan 2030 00:00:00 GMT")
        return "; ".join(parts)

    @staticmethod
    def _set_cookie_lines_from_response_headers(resp) -> list[str]:
        """All Set-Cookie header field-values for one response (handles multiple headers)."""
        lines: list[str] = []
        raw = getattr(resp, "raw", None)
        raw_headers = getattr(raw, "headers", None) if raw is not None else None

        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            for key in ("Set-Cookie", "set-cookie"):
                vals = raw_headers.getlist(key)
                if vals:
                    lines.extend(vals)

        if not lines and hasattr(resp, "headers"):
            hdrs = resp.headers
            for hk, hv in hdrs.items():
                if hk.lower() == "set-cookie" and hv:
                    lines.append(hv)
            if not lines:
                for key in ("Set-Cookie", "set-cookie"):
                    hv = hdrs.get(key)
                    if hv:
                        lines = [hv] if isinstance(hv, str) else list(hv)
                        break

        return [str(c).strip() for c in lines if c and str(c).strip()]

    @staticmethod
    def _cookie_dedupe_key_from_set_cookie_line(
        line: str, request_host: str, default_path: str,
    ) -> tuple[str, str, str]:
        """
        Dedupe key (name, domain, path) for one Set-Cookie header line.
        Uses request_host / default_path when Domain / Path attributes are absent.
        """
        parts = [p.strip() for p in line.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            return ("", "", "/")
        name, _, _ = parts[0].partition("=")
        name = name.strip()
        if not name:
            return ("", "", "/")
        domain = _normalize_cookie_domain(request_host)
        cpath = _normalize_cookie_path_value(default_path)
        for seg in parts[1:]:
            sl = seg.lower()
            if sl.startswith("domain="):
                domain = _normalize_cookie_domain(seg.split("=", 1)[1])
            elif sl.startswith("path="):
                cpath = _normalize_cookie_path_value(seg.split("=", 1)[1])
        if not domain:
            domain = _normalize_cookie_domain(request_host)
        return (name.lower(), domain, cpath)

    def _jar_cookie_dedupe_key(self, cookie, default_host: str) -> tuple[str, str, str]:
        name = getattr(cookie, "name", "") or ""
        dom = _normalize_cookie_domain(getattr(cookie, "domain", "") or "")
        if not dom:
            dom = _normalize_cookie_domain(default_host)
        cpath = _normalize_cookie_path_value(getattr(cookie, "path", None))
        return (name.lower(), dom, cpath)

    def _collect_set_cookie_strings(self, resp) -> list[str]:
        """
        Collect Set-Cookie values from every redirect hop and the final response,
        then merge with ``session.cookies`` / ``response.cookies`` (post-auth state).

        Deduplicates by (cookie name, domain, path). Header lines from later hops
        overwrite earlier ones for the same key; jar entries fill gaps (cookies
        set on login that are not re-emitted on the final GET).
        """
        by_key: dict[tuple[str, str, str], str] = {}

        hops = list(getattr(resp, "history", []) or []) + [resp]
        for hop in hops:
            host, def_path = _cookie_context_host_path(self.url or "", hop)
            for line in self._set_cookie_lines_from_response_headers(hop):
                key = self._cookie_dedupe_key_from_set_cookie_line(line, host, def_path)
                if key[0]:
                    by_key[key] = line

        jar_host, _ = _cookie_context_host_path(self.url or "", resp)

        for jar in (getattr(resp, "cookies", None), getattr(self.session, "cookies", None)):
            if jar is None:
                continue
            try:
                for c in jar:
                    if not getattr(c, "name", None):
                        continue
                    jk = self._jar_cookie_dedupe_key(c, jar_host)
                    if jk[0] and jk not in by_key:
                        s = self._cookie_jar_entry_to_set_cookie(c)
                        if s:
                            by_key[jk] = s
            except (TypeError, AttributeError):
                continue

        return list(by_key.values())

    def _audit_cookie(self, cookie_str: str) -> list[dict]:
        """Audit a single raw Set-Cookie header string."""
        findings: list[dict] = []
        lower = cookie_str.lower()

        # Extract cookie name (first name=value pair before ';')
        first_pair = cookie_str.split(";", 1)[0].strip()
        name = first_pair.split("=", 1)[0].strip() if "=" in first_pair else first_pair

        infra = _is_infrastructure_cookie(name)

        # ── HttpOnly ──────────────────────────────────────────────────────
        if "httponly" not in lower:
            findings.append(self._finding(
                name, "Missing HttpOnly Flag", "MEDIUM",
                "Cookie can be accessed by JavaScript – XSS can steal the session"
            ))
            if infra:
                logger.info(
                    "  [INFO] Infrastructure cookie '%s' missing HttpOnly (not app-controlled)",
                    name,
                )
            else:
                logger.warning("  [MEDIUM] Cookie '%s' missing HttpOnly", name)

        # ── Secure ────────────────────────────────────────────────────────
        if "secure" not in lower:
            findings.append(self._finding(
                name, "Missing Secure Flag", "MEDIUM",
                "Cookie transmitted over HTTP – vulnerable to network interception"
            ))
            if infra:
                logger.info(
                    "  [INFO] Infrastructure cookie '%s' missing Secure (not app-controlled)",
                    name,
                )
            else:
                logger.warning("  [MEDIUM] Cookie '%s' missing Secure flag", name)

        # ── SameSite ──────────────────────────────────────────────────────
        if "samesite" not in lower:
            findings.append(self._finding(
                name, "Missing SameSite Attribute", "LOW",
                "No SameSite policy – CSRF attacks may be possible"
            ))
        elif "samesite=none" in lower and "secure" not in lower:
            findings.append(self._finding(
                name, "SameSite=None Without Secure", "HIGH",
                "SameSite=None without Secure flag allows cross-site cookie leakage"
            ))
            if infra:
                logger.info(
                    "  [INFO] Infrastructure cookie '%s' SameSite=None without Secure (not app-controlled)",
                    name,
                )
            else:
                logger.warning("  [HIGH] Cookie '%s' SameSite=None without Secure", name)

        # ── Session Cookie Persistence ────────────────────────────────────
        if "max-age" in lower or "expires" in lower:
            findings.append(self._finding(
                name, "Persistent Session Cookie", "LOW",
                "Cookie has explicit expiry – session survives browser closure"
            ))

        out: list[dict] = []
        for f in findings:
            fa = self._annotate_set_cookie_header(f, cookie_str)
            fa = self._downgrade_infrastructure_cookie_finding(fa, name)
            out.append(self._downgrade_tracking_cookie_finding(fa, name))
        return out

    @staticmethod
    def _finding(name: str, issue: str, severity: str, detail: str) -> dict:
        """Construct a standardised cookie finding dict."""
        return {
            "type":      f"Cookie Security – {issue}",
            "url":       "N/A",
            "parameter": name,
            "payload":   "N/A",
            "severity":  severity,
            "evidence":  detail,
        }

    @staticmethod
    def _downgrade_tracking_cookie_finding(finding: dict, cookie_name: str) -> dict:
        if not _is_analytics_or_tracking_cookie(cookie_name):
            return finding
        out = dict(finding)
        sev = (out.get("severity") or "").upper()
        if sev in ("HIGH", "MEDIUM"):
            out["severity"] = "LOW"
        elif sev == "LOW":
            out["severity"] = "INFO"
        detail = (out.get("evidence") or "").rstrip()
        note = " Common analytics/tracking cookie — lower impact than session authentication."
        if note.strip() not in detail:
            sep = "" if detail.endswith(".") else "."
            out["evidence"] = f"{detail}{sep}{note}".strip()
        ex = out.get("extra")
        base = dict(ex) if isinstance(ex, dict) else {}
        base["analytics_cookie"] = True
        out["extra"] = base
        return out

    @staticmethod
    def _downgrade_infrastructure_cookie_finding(finding: dict, cookie_name: str) -> dict:
        if not _is_infrastructure_cookie(cookie_name):
            return finding
        out = dict(finding)
        out["severity"] = "INFO"
        detail = (out.get("evidence") or "").rstrip()
        if _INFRA_COOKIE_NOTE not in detail:
            sep = "" if detail.endswith(".") else "."
            out["evidence"] = f"{detail}{sep} {_INFRA_COOKIE_NOTE}".strip()
        ex = out.get("extra")
        base = dict(ex) if isinstance(ex, dict) else {}
        base["infrastructure_cookie"] = True
        out["extra"] = base
        return out

    @staticmethod
    def _annotate_set_cookie_header(finding: dict, set_cookie_header: str) -> dict:
        if not set_cookie_header or not isinstance(finding, dict):
            return finding
        out = dict(finding)
        out["set_cookie_header"] = set_cookie_header.strip()
        return out
