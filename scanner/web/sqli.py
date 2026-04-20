"""
scanner/web/sqli.py
===================
State-driven SQL injection scanner built on BaseScanner.

Lifecycle states (per candidate):
  DISCOVERED -> QUEUED -> TESTED -> CONFIRMED -> REPORTED

Detection:
  - Error-based: two distinct payloads must surface DB error signatures.
  - Boolean-based: TRUE/FALSE pairs compared to baseline using **body length**,
    **content similarity** (``difflib``), and **SQL/error keyword** deltas — not
    HTTP status alone. Three independent pairs must agree (incl. numeric 7=7/7=8).
  - Time-based: response delay must exceed baseline by > 5s, reproduced
    with two distinct delay payloads.
  - Proof logging: confirmed issues log payload plus a short response snippet
    (``INJECTION_PROOF``). Pipeline does not skip boolean/time after error-based
    unless ``SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM`` is enabled in config.
"""

from __future__ import annotations

from ..scan_logger import logger
import time
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

import config

from ..base_scanner import BaseScanner
from .base_module import ScanContext, post_param_injection_order
from .injection_fp_guard import suppress_sqli_fp
from scanner.web.waf import WAF_BYPASS_PAYLOADS

# Substrings that often appear in DB/driver error pages; used for boolean diff signals.
_SQL_BOOLEAN_HINT_TOKENS = frozenset(
    (
        "syntax error",
        "sql syntax",
        "mysql",
        "mysqli",
        "odbc",
        "sqlite",
        "postgres",
        "postgresql",
        "ora-",
        "sqlstate",
        "sql server",
        "mssql",
        "warning:",
        "unclosed quotation",
        "invalid query",
        "driver",
    ),
)

_MAX_BODY_SNAPSHOT = 50_000


class VulnState:
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    TESTED = "TESTED"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"


def _response_snippet(text: str | None, limit: int = 320) -> str:
    if not text:
        return ""
    t = text.replace("\r", " ").replace("\n", " ")
    return (t[:limit] + ("…" if len(t) > limit else "")).strip()


class SQLiScanner(BaseScanner):
    """
    Multi-technique SQLi scanner with explicit state transitions and
    multi-payload confirmation.
    """

    name = "sqli"

    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.waf_bypass = bool(kwargs.get("waf_bypass", False))
        self.bypass_payloads: List[str] = []
        if self.waf_bypass:
            self.bypass_payloads = list(WAF_BYPASS_PAYLOADS.get("sqli", []))
        self.scan_intensity = str(
            kwargs.get("scan_intensity")
            or getattr(config, "SCAN_INTENSITY_DEFAULT", "medium"),
        ).lower()
        if self.scan_intensity not in ("light", "medium", "aggressive"):
            self.scan_intensity = "medium"

    def _payload_list(self, fast: bool = False) -> List[str]:
        intensity = self.scan_intensity
        if intensity == "light":
            fast = True
        src = list(config.SQLI_FAST_PAYLOADS if fast else config.SQLI_PAYLOADS)
        if intensity == "light":
            src = config.sql_payloads_skip_destructive(src)
        src = config.apply_intensity_payload_cap(src, intensity)
        if self.bypass_payloads:
            base = list(self.bypass_payloads)
            for p in src:
                if p not in base:
                    base.append(p)
            return self._dedupe_payloads(base)
        return self._dedupe_payloads(src)

    @staticmethod
    def _log_injection_proof(
        technique: str,
        url: str,
        param: str,
        payload: str,
        body: str | None,
    ) -> None:
        logger.info(
            "%s — payload + response snippet",
            technique,
            extra={
                "kind": "INJECTION_PROOF",
                "technique": technique,
                "url": url,
                "parameter": param,
                "payload": (payload or "")[:800],
                "response_snippet": _response_snippet(body),
            },
        )

    @staticmethod
    def _dedupe_payloads(payloads: List[str]) -> List[str]:
        seen: set[str] = set()
        out: List[str] = []
        for p in payloads:
            ps = str(p)
            if ps and ps not in seen:
                seen.add(ps)
                out.append(ps)
        return out

    def run(self, context: ScanContext) -> List[dict]:
        self.findings.clear()
        if context:
            if context.urls:
                self.urls = context.urls
            self.session = context.auth_session or context.session or self.session

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
        payload_list = self._dedupe_payloads(self._payload_list(fast=False))
        mode = "[WAF BYPASS MIX]" if self.bypass_payloads else ""

        logger.info(
            "  [*] SQLi (state-driven): %s GET target(s) + %s POST — %s payloads %s",
            len(get_targets),
            len(post_targets),
            len(payload_list),
            mode,
        )
        if not get_targets:
            logger.warning(
                "  [!] SQLi: no GET targets in context.scan_targets — GET-phase skipped "
                "(%s URLs in scope)",
                len(self.urls),
            )
        if not post_targets:
            logger.info(
                "  [i] SQLi: no POST targets in context.scan_targets — POST-phase skipped",
            )

        out: List[dict] = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {
                ex.submit(self._test_url, t["url"], t["params"]): t["url"]
                for t in get_targets
            }
            for fut in as_completed(futs):
                try:
                    out.extend(fut.result() or [])
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
                    out.extend(fut.result() or [])
                except Exception:
                    pass

        deduped = self._dedupe_findings(out)
        for f in deduped:
            self._add_finding(f)
        return deduped

    # --- GET: orchestrate three techniques ---------------------------------

    @staticmethod
    def _get_params_dict(
        url: str,
        params_override: dict[str, list[str]] | None,
    ) -> dict[str, list[str]]:
        if params_override is not None:
            return {
                k: list(v) if isinstance(v, list) else [str(v)]
                for k, v in params_override.items()
            }
        return parse_qs(urlparse(url).query, keep_blank_values=True)

    @staticmethod
    def _qs_first(values: list[str]) -> str:
        return values[0] if values else ""

    def _test_url(
        self,
        url: str,
        params_override: dict[str, list[str]] | None = None,
    ) -> List[dict]:
        findings: List[dict] = []
        err = self._error_based(url, params_override)
        findings.extend(err)
        if err and getattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", True):
            return findings
        findings.extend(self._boolean_blind(url, params_override))
        if self.scan_intensity != "light":
            findings.extend(self._time_blind(url, params_override))
        return findings

    def _error_based(
        self,
        url: str,
        params_override: dict[str, list[str]] | None = None,
    ) -> List[dict]:
        parsed = urlparse(url)
        params = self._get_params_dict(url, params_override)
        if not params:
            return []
        payloads = self._dedupe_payloads(self._payload_list(fast=False))
        findings: List[dict] = []

        for param in params:
            hits: List[Tuple[str, str]] = []
            state = VulnState.DISCOVERED
            for payload in payloads:
                if len(hits) >= 2:
                    break
                test_params = {k: self._qs_first(v) for k, v in params.items()}
                test_params[param] = payload
                test_url = self._rebuild_url(parsed, test_params)
                resp = self._safe_request(test_url)
                if not resp:
                    continue
                body = resp.text.lower()
                for sig in config.SQLI_ERROR_SIGNATURES:
                    if sig.lower() in body:
                        if not hits or hits[-1][0] != payload:
                            hits.append((payload, sig))
                            state = VulnState.QUEUED if len(hits) == 1 else VulnState.TESTED
                        break

            if len(hits) < 2 or hits[0][0] == hits[1][0]:
                continue

            state = VulnState.CONFIRMED
            p1, sig1 = hits[0]
            p2, sig2 = hits[1]
            evidence = (
                f"error-based: two payloads triggered DB error signatures "
                f"({sig1!r} / {sig2!r}); states={VulnState.DISCOVERED}->{state}"
            )
            fin = self._structured_finding(
                technique="Error-Based SQLi",
                url=self._rebuild_url(
                    parsed,
                    {**{k: self._qs_first(v) for k, v in params.items()}, param: p2},
                ),
                param=param,
                primary_payload=f"{p1} | {p2}",
                evidence=evidence,
                confidence=0.92,
                severity="CRITICAL",
                state=VulnState.REPORTED,
                extra={"payloads_confirmed": [p1, p2], "signatures": [sig1, sig2]},
            )
            probe = self._safe_request(fin["url"])
            if probe and suppress_sqli_fp(probe.text):
                logger.info(
                    "  [i] SQLi (error-based) suppressed — safe/parameterized query indicators: %s [%s]",
                    url,
                    param,
                )
                continue
            self._log_injection_proof(
                "SQLi (error-based)",
                url,
                param,
                fin.get("payload", "") or "",
                probe.text if probe else None,
            )
            logger.warning("  [CRITICAL] SQLi (Error) → %s [%s]", url, param)
            findings.append(fin)

        return findings

    @staticmethod
    def _sql_boolean_hint_hits(text: str) -> int:
        low = (text or "").lower()
        return sum(1 for tok in _SQL_BOOLEAN_HINT_TOKENS if tok in low)

    @staticmethod
    def _body_quick_ratio(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        return SequenceMatcher(None, a, b).quick_ratio()

    def _measure_get(self, full_url: str) -> Optional[Tuple[int, int, float, str]]:
        """Length, status, timing, and body snapshot (capped) for boolean analysis."""
        t0 = time.perf_counter()
        resp = self._safe_request(full_url)
        elapsed = time.perf_counter() - t0
        if not resp:
            return None
        text = (resp.text or "")[:_MAX_BODY_SNAPSHOT]
        return len(text), resp.status_code, elapsed, text

    def _boolean_blind(
        self,
        url: str,
        params_override: dict[str, list[str]] | None = None,
    ) -> List[dict]:
        parsed = urlparse(url)
        params = self._get_params_dict(url, params_override)
        if not params:
            return []
        findings: List[dict] = []

        # Three independent TRUE/FALSE pairs; includes numeric equality (7=7 vs 7=8) as
        # evaluated-expression style proof alongside string/OR forms.
        pairs = [
            ("' OR '1'='1' --", "' OR '1'='2' --"),
            ("' OR 1=1--", "' OR 1=2--"),
            ("' OR 7=7--", "' OR 7=8--"),
        ]
        # Body-centric: length + similarity + keyword deltas vs baseline; not status-only.
        len_thr = 72
        sim_tf_thr = 0.987  # TRUE vs FALSE bodies more dissimilar than this
        sim_base_thr = 0.9935  # injection vs baseline
        base_shift_len = max(24, len_thr // 3)

        for param in params:
            base_params = {k: self._qs_first(v) for k, v in params.items()}
            base_url = self._rebuild_url(parsed, base_params)
            base_m = self._measure_get(base_url)
            if not base_m:
                continue
            base_len, base_status, _base_elapsed, base_text = base_m

            state = VulnState.DISCOVERED
            pair_results: List[bool] = []

            for true_p, false_p in pairs:
                t_snaps: List[Tuple[int, int, str]] = []
                f_snaps: List[Tuple[int, int, str]] = []
                for _ in range(2):
                    tp = dict(base_params)
                    tp[param] = true_p
                    fp = dict(base_params)
                    fp[param] = false_p
                    mt = self._measure_get(self._rebuild_url(parsed, tp))
                    mf = self._measure_get(self._rebuild_url(parsed, fp))
                    if not mt or not mf:
                        continue
                    t_snaps.append((mt[0], mt[1], mt[3]))
                    f_snaps.append((mf[0], mf[1], mf[3]))

                if len(t_snaps) < 2:
                    continue

                avg_tl = sum(s[0] for s in t_snaps) / len(t_snaps)
                avg_fl = sum(s[0] for s in f_snaps) / len(f_snaps)
                length_diff = abs(avg_tl - avg_fl)

                ratio_tf = min(
                    self._body_quick_ratio(t_snaps[0][2], f_snaps[0][2]),
                    self._body_quick_ratio(t_snaps[1][2], f_snaps[1][2]),
                )
                hint_t = max(
                    self._sql_boolean_hint_hits(t_snaps[0][2]),
                    self._sql_boolean_hint_hits(t_snaps[1][2]),
                )
                hint_f = max(
                    self._sql_boolean_hint_hits(f_snaps[0][2]),
                    self._sql_boolean_hint_hits(f_snaps[1][2]),
                )
                hint_diff = hint_t != hint_f

                ratio_tb = min(
                    self._body_quick_ratio(base_text, t_snaps[0][2]),
                    self._body_quick_ratio(base_text, t_snaps[1][2]),
                )
                ratio_fb = min(
                    self._body_quick_ratio(base_text, f_snaps[0][2]),
                    self._body_quick_ratio(base_text, f_snaps[1][2]),
                )

                content_tf_diverges = (
                    length_diff >= len_thr
                    or ratio_tf < sim_tf_thr
                    or hint_diff
                )
                baseline_shift = (
                    abs(avg_tl - base_len) >= base_shift_len
                    or abs(avg_fl - base_len) >= base_shift_len
                    or ratio_tb < sim_base_thr
                    or ratio_fb < sim_base_thr
                    or hint_diff
                )

                # Never accept HTTP status flips alone without body/keyword signal.
                pair_ok = content_tf_diverges and baseline_shift

                if pair_ok:
                    pair_results.append(True)
                    state = VulnState.TESTED
                else:
                    pair_results.append(False)

            if len(pair_results) < 3 or not all(pair_results):
                continue

            state = VulnState.CONFIRMED
            evidence = (
                f"boolean-based: three TRUE/FALSE pairs agreed using body length, "
                f"content similarity vs baseline, and/or SQL/error keyword deltas "
                f"(not status-code-only); baseline len={base_len} status={base_status}; "
                f"pairs={pairs!r}; state={state}"
            )
            fin = self._structured_finding(
                technique="Boolean-Blind SQLi",
                url=url,
                param=param,
                primary_payload=f"{pairs[0][0]} / {pairs[1][0]}",
                evidence=evidence,
                confidence=0.78,
                severity="HIGH",
                state=VulnState.REPORTED,
                extra={"pairs": pairs},
            )
            rb = self._safe_request(base_url)
            rt = self._safe_request(
                self._rebuild_url(parsed, {**base_params, param: pairs[0][0]}),
            )
            if rb and rt and suppress_sqli_fp(rb.text, rt.text):
                logger.info(
                    "  [i] SQLi (boolean) suppressed — safe/parameterized query indicators: %s [%s]",
                    url,
                    param,
                )
                continue
            self._log_injection_proof(
                "SQLi (boolean-blind)",
                url,
                param,
                pairs[2][0],
                rt.text if rt else None,
            )
            logger.warning("  [HIGH] SQLi (Boolean-Blind) → %s [%s]", url, param)
            findings.append(fin)

        return findings

    def _time_blind(
        self,
        url: str,
        params_override: dict[str, list[str]] | None = None,
    ) -> List[dict]:
        parsed = urlparse(url)
        params = self._get_params_dict(url, params_override)
        if not params:
            return []
        findings: List[dict] = []
        delay_s = 5.0
        time_payloads = [
            ("' AND SLEEP(6)--", "MySQL SLEEP(6)"),
            ("' OR pg_sleep(6)--", "PostgreSQL pg_sleep(6)"),
        ]
        req_timeout = max(self.timeout + 14, 20)

        for param in params:
            base_params = {k: self._qs_first(v) for k, v in params.items()}
            base_url = self._rebuild_url(parsed, base_params)
            samples: List[float] = []
            for _ in range(3):
                t0 = time.perf_counter()
                r = self._timed_get(base_url, req_timeout)
                samples.append(time.perf_counter() - t0 if r is not None else 0.0)
            samples.sort()
            baseline = samples[1] if len(samples) >= 3 else (samples[0] if samples else 0.0)

            confirmed_payloads: List[str] = []
            state = VulnState.DISCOVERED

            for payload, hint in time_payloads:
                deltas: List[float] = []
                for _ in range(2):
                    test_params = dict(base_params)
                    test_params[param] = payload
                    test_url = self._rebuild_url(parsed, test_params)
                    t0 = time.perf_counter()
                    r = self._timed_get(test_url, req_timeout)
                    elapsed = time.perf_counter() - t0 if r is not None else 0.0
                    deltas.append(elapsed - baseline)

                if len(deltas) == 2 and min(deltas) > delay_s:
                    confirmed_payloads.append(payload)
                    state = VulnState.TESTED

            if len(confirmed_payloads) < 2:
                continue

            state = VulnState.CONFIRMED
            p1, p2 = confirmed_payloads[0], confirmed_payloads[1]
            evidence = (
                f"time-based: baseline(median)={baseline:.3f}s; "
                f"two payloads exceeded baseline by >{delay_s}s "
                f"({p1!r}, {p2!r}); state={state}"
            )
            fin = self._structured_finding(
                technique="Time-Based Blind SQLi",
                url=self._rebuild_url(parsed, {**base_params, param: p2}),
                param=param,
                primary_payload=f"{p1} | {p2}",
                evidence=evidence,
                confidence=0.82,
                severity="HIGH",
                state=VulnState.REPORTED,
                extra={"delay_threshold_s": delay_s, "baseline_s": baseline},
            )
            rb = self._timed_get(base_url, req_timeout)
            rchk = self._timed_get(fin["url"], req_timeout)
            bodies = [x.text for x in (rb, rchk) if x is not None]
            if bodies and suppress_sqli_fp(*bodies):
                logger.info(
                    "  [i] SQLi (time-based) suppressed — safe/parameterized query indicators: %s [%s]",
                    url,
                    param,
                )
                continue
            self._log_injection_proof(
                "SQLi (time-based)",
                url,
                param,
                p2,
                rchk.text if rchk else None,
            )
            logger.warning("  [HIGH] SQLi (Time-Blind) → %s [%s]", url, param)
            findings.append(fin)

        return findings

    def _timed_get(self, url: str, timeout: float) -> Optional[requests.Response]:
        from .http_retry import request_with_retries

        return request_with_retries(
            self.session,
            "GET",
            url,
            timeout=timeout,
            max_attempts=3,
            allow_redirects=False,
        )

    def _test_post_form(
        self,
        url: str,
        fields: dict,
        field_details: List[dict] | None = None,
    ) -> List[dict]:
        results: List[dict] = []
        payload_list = self._payload_list(fast=(self.scan_intensity == "light"))
        delay_s = 5.0
        req_timeout = max(self.timeout + 14, 20)

        ordered = post_param_injection_order(field_details, fields.keys())
        for field in ordered:
            hits: List[Tuple[str, str]] = []
            for payload in payload_list:
                if len(hits) >= 2:
                    break
                data = dict(fields)
                data[field] = payload
                resp = self._safe_post(url, data)
                if not resp:
                    continue
                low = resp.text.lower()
                for sig in config.SQLI_ERROR_SIGNATURES:
                    if sig.lower() in low:
                        if not hits or hits[-1][0] != payload:
                            hits.append((payload, sig))
                        break
            if len(hits) >= 2 and hits[0][0] != hits[1][0]:
                p1, s1 = hits[0]
                p2, s2 = hits[1]
                row = self._structured_finding(
                    technique="Error-Based SQLi (POST)",
                    url=url,
                    param=field,
                    primary_payload=f"{p1} | {p2}",
                    evidence=(
                        f"POST error-based: signatures {s1!r} and {s2!r} "
                        f"with distinct payloads; state={VulnState.REPORTED}"
                    ),
                    confidence=0.9,
                    severity="CRITICAL",
                    state=VulnState.REPORTED,
                    extra={"payloads_confirmed": [p1, p2]},
                )
                chk = self._safe_post(url, {**dict(fields), field: p2}, timeout=req_timeout)
                if chk and suppress_sqli_fp(chk.text):
                    logger.info(
                        "  [i] SQLi POST (error) suppressed — safe/parameterized query indicators: %s [%s]",
                        url,
                        field,
                    )
                    continue
                self._log_injection_proof(
                    "SQLi POST (error-based)",
                    url,
                    field,
                    row.get("payload", "") or "",
                    chk.text if chk else None,
                )
                results.append(row)
                logger.warning("  [CRITICAL] SQLi POST (Error) → %s [%s]", url, field)
                if getattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", False):
                    continue

            if self.scan_intensity == "light":
                continue

            time_posts = [
                ("' AND SLEEP(6)--", "MySQL"),
                ("' OR pg_sleep(6)--", "PostgreSQL"),
            ]
            baseline_samples: List[float] = []
            for _ in range(3):
                t0 = time.perf_counter()
                self._safe_post(url, dict(fields), timeout=req_timeout)
                baseline_samples.append(time.perf_counter() - t0)
            baseline_samples.sort()
            bmed = (
                baseline_samples[1]
                if len(baseline_samples) >= 3
                else (baseline_samples[0] if baseline_samples else 0.0)
            )
            ok: List[str] = []
            for pl, _db in time_posts:
                deltas: List[float] = []
                for _ in range(2):
                    d = dict(fields)
                    d[field] = pl
                    t0 = time.perf_counter()
                    self._safe_post(url, d, timeout=req_timeout)
                    deltas.append(time.perf_counter() - t0 - bmed)
                if len(deltas) == 2 and min(deltas) > delay_s:
                    ok.append(pl)
            if len(ok) >= 2:
                row = self._structured_finding(
                    technique="Time-Based Blind SQLi (POST)",
                    url=url,
                    param=field,
                    primary_payload=f"{ok[0]} | {ok[1]}",
                    evidence=(
                        f"POST time-based: baseline {bmed:.3f}s; "
                        f"> {delay_s}s delta with two payloads"
                    ),
                    confidence=0.8,
                    severity="HIGH",
                    state=VulnState.REPORTED,
                    extra={"payloads_confirmed": ok[:2]},
                )
                d0 = dict(fields)
                d1 = dict(fields)
                d0[field] = ok[0]
                d1[field] = ok[1]
                b0 = self._safe_post(url, d0, timeout=req_timeout)
                b1 = self._safe_post(url, d1, timeout=req_timeout)
                parts = [x.text for x in (b0, b1) if x is not None]
                if parts and suppress_sqli_fp(*parts):
                    logger.info(
                        "  [i] SQLi POST (time) suppressed — safe/parameterized query indicators: %s [%s]",
                        url,
                        field,
                    )
                    continue
                self._log_injection_proof(
                    "SQLi POST (time-based)",
                    url,
                    field,
                    row.get("payload", "") or "",
                    parts[-1] if parts else None,
                )
                results.append(row)
                logger.warning("  [HIGH] SQLi POST (Time-Blind) → %s [%s]", url, field)

        return results

    def _safe_post(
        self, url: str, data: dict, timeout: Optional[float] = None
    ) -> Optional[requests.Response]:
        from .http_retry import request_with_retries

        to = timeout if timeout is not None else self.timeout
        return request_with_retries(
            self.session,
            "POST",
            url,
            timeout=to,
            max_attempts=3,
            data=data,
            allow_redirects=True,
        )

    # --- shared -------------------------------------------------------------

    @staticmethod
    def _rebuild_url(parsed, params: dict) -> str:
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _structured_finding(
        self,
        technique: str,
        url: str,
        param: str,
        primary_payload: str,
        evidence: str,
        confidence: float,
        severity: str,
        state: str,
        extra: Optional[dict] = None,
    ) -> dict:
        row: Dict[str, Any] = {
            "type": technique,
            "url": url,
            "param": param,
            "parameter": param,
            "payload": primary_payload,
            "evidence": evidence,
            "confidence": confidence,
            "severity": severity,
            "state": state,
            "state_trace": [
                VulnState.DISCOVERED,
                VulnState.QUEUED,
                VulnState.TESTED,
                VulnState.CONFIRMED,
                VulnState.REPORTED,
            ],
        }
        if extra:
            row["extra"] = extra
        return row

    @staticmethod
    def _dedupe_findings(rows: List[dict]) -> List[dict]:
        seen: set[tuple[str, str, str]] = set()
        out: List[dict] = []
        for fi in rows:
            try:
                path = urlparse(fi.get("url", "")).path
            except Exception:
                path = fi.get("url", "")
            key = (path, fi.get("param") or fi.get("parameter", ""), fi.get("type", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append(fi)
        return out
