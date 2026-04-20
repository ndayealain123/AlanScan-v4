"""
scanner/controller.py  v5.0.0
===================================
AlanScan Enterprise Orchestrator — BaseScanner-integrated web pipeline.

Web scanners from ``scanner.web`` are invoked uniformly via
``scanner.run(target)`` where ``target`` is the active ``ScanContext``.

Finding lifecycle (HTTP findings):
  DISCOVERED → QUEUED → TESTED → CONFIRMED → REPORTED
"""

from __future__ import annotations

import hashlib
import threading
from collections import defaultdict
import time
import uuid
import os
import json
from typing import Any, Callable
from urllib.parse import urlparse

import config
from .events import ScanEventKind, safe_scan_event_kind
from .scan_logger import (
    logger,
    configure_scanner_console_logging,
    coerce_evidence_field,
)

from .scan_logger import safe_str
from .base_scanner import BaseScanner
from .web.crawler import Crawler, count_query_parameters
from .web.scan_targets import (
    post_form_action_keys_from_forms,
    prepare_scan_targets,
    url_scan_queue_rank,
)
from .web.waf import WAFDetector
from .web.sqli import SQLiScanner
from .web.xss import XSSScanner
from .web.csrf import CSRFScanner
from .web.ssrf import SSRFScanner
from .web.cmdi import CMDiScanner
from .web.xxe import XXEScanner
from .web.lfi import LFIScanner
from .web.headers import HeaderScanner
from .web.ssl_tls import SSLScanner
from .web.cookies import CookieScanner
from .web.directories import DirectoryScanner
from .web.api_security import APISecurityScanner
from .web.rate_limit import RateLimitScanner
from .web.idor import IDORScanner
from .web.auth_audit import AuthAudit
from .web.open_redirect import OpenRedirectScanner
from .web.method_tampering import MethodTamperingScanner
from .web.security_headers_plus import SecurityHeadersPlus
from .network.portscan import PortScanner
from .network.banner import BannerGrabber
from .network.cve import CVEMatcher
from .chainer import VulnChainer
from .ai_analyst import (
    AIAnalyst,
    _type_param_merge_key,
    classify_ai_api_error,
    user_facing_ai_message_from_exc,
)

_SEV_RANK_DEDUPE = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
from .scoring_engine import ScoringEngine
from .evidence_validator import EvidenceValidator
from .report_enricher import enrich_findings
from .evidence_collector import EvidenceCollector
from .thread_manager import AdaptiveThreadPool, RequestThrottler, ThresholdGuard
from .pentest_engine import PentestEngine, ScanState
from . import observability
from .schema import EVENT_VERSION, SCHEMA_VERSION
from .scan_logger import (
    StructuredLogger,
    LogConverter,
    enrich_chain_record,
    enrich_finding_record,
    normalize_finding_row,
)
from reports.reporter import Reporter
from reports.html_reporter import HTMLReporter
from reports.pdf_reporter import PDFReporter

from .web.base_module import ScanContext


_K_FINDING_COUNT_MISMATCH = safe_scan_event_kind(
    "FINDING_COUNT_MISMATCH",
    "finding_count_mismatch",
)

DEFAULT_MODULES = {
    "sqli": True, "xss": True, "csrf": True, "ssrf": True,
    "cmdi": True, "xxe": True, "lfi": True, "headers": True,
    "ssl": True, "cookies": True, "dirs": True, "waf": True,
    "api": True, "idor": True, "rate": True,
    "ports": True, "chain": True,
    "redirect": True, "method": True, "headers_plus": True,
}

# Ordered lifecycle labels attached to findings (module logic unchanged).
LIFECYCLE_STATES = (
    "DISCOVERED", "QUEUED", "TESTED", "CONFIRMED", "REPORTED",
)


def _normalize_finding_id(fid: Any) -> str | None:
    if not fid:
        return None
    return str(fid).strip().lower()


class ScannerController:
    """
    Enterprise orchestrator — threads, throttle, thresholds,
    state-driven FSM, live chain detection, JSONL logging.
    All ``scanner/web`` vulnerability modules run through ``BaseScanner.run``.
    """

    def __init__(self, threads: int = 12, timeout: int | None = None,
                 proxy: str | None = None,
                 report_format: str = "html",
                 ai_enabled: bool = False,
                 api_key: str | None = None,
                 modules: dict | None = None,
                 output_dir: str = "output",
                 credentials: str | None = None,
                 bearer_token: str | None = None,
                 throttle_rps: float = 5.0,
                 max_requests: int = 10000,
                 error_threshold: float = 0.30,
                 request_delay_sec: float | None = None,
                 scan_intensity: str = "medium",
                 compare_report_path: str | None = None):
        self.threads = threads
        self.timeout = int(
            timeout if timeout is not None else getattr(config, "TIMEOUT", 15),
        )
        self.proxy = proxy
        self.report_format = report_format
        self.ai_enabled = ai_enabled
        self.api_key = api_key
        self.scan_intensity = (scan_intensity or "medium").strip().lower()
        if self.scan_intensity not in ("light", "medium", "aggressive"):
            self.scan_intensity = "medium"
        self.modules = modules or dict(DEFAULT_MODULES)
        self.findings = []
        self._lock = threading.Lock()
        self._waf = None
        self.output_dir = output_dir
        self._validation_report = {}
        self._validated_findings_count: int | None = None
        # Length of ``self.findings`` after validation + scoring + enrichment + evidence (before AI).
        self._post_pipeline_findings_count: int | None = None
        self._start_time = None
        self._module_times = {}
        self._extra_evidence = {}
        self.credentials = credentials or ""
        self.bearer_token = (bearer_token or "").strip() or None
        self._auth_session = None
        self._scan_context_obj: ScanContext | None = None
        self._last_ai_data = {}
        self.chain_ai_overlay_skipped = False
        self._invalid_chain_finding_count = 0
        self.target = ""
        self.urls = []
        self._scan_context: dict = {}

        self.scan_id = str(uuid.uuid4())
        import config as _cfg
        _delay = float(
            request_delay_sec
            if request_delay_sec is not None
            else getattr(_cfg, "SAFE_DEFAULT_DELAY_SEC", 0.1)
        )
        self.request_delay_sec = _delay
        self.throttle_rps = float(throttle_rps)
        self.max_requests_budget = int(max_requests)
        self._throttler = RequestThrottler(
            rate=self.throttle_rps,
            burst=max(self.throttle_rps * 2.0, 2.0),
            min_delay_sec=_delay,
        )
        self._guard = ThresholdGuard(max_requests=max_requests,
                                     error_threshold=error_threshold)
        self._pool = AdaptiveThreadPool(
            workers=threads,
            throttler=self._throttler,
            guard=self._guard,
        )
        self._sl: StructuredLogger | None = None
        self._engine: PentestEngine | None = None
        self._module_step_failed = False
        self._metrics_tracker: dict[str, int] = {
            "total_modules": 0,
            "successful_modules": 0,
            "failed_modules": 0,
        }
        self._module_metrics: list[dict[str, Any]] = []
        self.compare_report_path = (compare_report_path or "").strip() or None
        try:
            configure_scanner_console_logging()
        except Exception:
            pass

    def _reset_scan_metrics(self) -> None:
        self._metrics_tracker = {
            "total_modules": 0,
            "successful_modules": 0,
            "failed_modules": 0,
        }
        self._module_step_failed = False
        self._module_metrics = []
        self.chain_ai_overlay_skipped = False
        self._invalid_chain_finding_count = 0

    def _record_module_metric(
        self,
        module_name: str,
        duration_s: float,
        findings_count: int,
        status: str,
    ) -> None:
        self._module_metrics.append(
            {
                "module_name": module_name,
                "duration": round(float(duration_s), 3),
                "findings_count": int(findings_count),
                "status": status,
                "schema_version": SCHEMA_VERSION,
                "event_version": EVENT_VERSION,
            }
        )

    def _metrics_begin_unit(self) -> None:
        self._metrics_tracker["total_modules"] += 1
        self._module_step_failed = False

    def _metrics_succeed_unit(self) -> None:
        self._metrics_tracker["successful_modules"] += 1

    def _metrics_fail_unit(self) -> None:
        self._metrics_tracker["failed_modules"] += 1

    def _emit_scan_metrics(self) -> None:
        duration = time.perf_counter() - (
            self._start_time if self._start_time is not None else time.perf_counter()
        )
        mt = self._metrics_tracker
        payload = {
            "kind": ScanEventKind.SCAN_METRICS,
            "total_modules": mt["total_modules"],
            "successful_modules": mt["successful_modules"],
            "failed_modules": mt["failed_modules"],
            "total_findings": len(self.findings),
            "scan_duration": round(duration, 3),
            "scan_id": self.scan_id,
            "module_metrics": list(self._module_metrics),
            "chain_ai_overlay_skipped": self.chain_ai_overlay_skipped,
            "invalid_chain_finding_count": self._invalid_chain_finding_count,
            "schema_version": SCHEMA_VERSION,
            "event_version": EVENT_VERSION,
        }
        logger.info("Scan metrics", extra=payload)
        if self._sl:
            persist = {k: v for k, v in payload.items() if k != "kind"}
            self._sl.log_scan_metrics(persist)

    @staticmethod
    def _log_injection_fp_guard_notice(enabled_modules: dict) -> None:
        """One-shot console notice when SQLi/CMDi/XXE modules run (fp_guard is in-scanner)."""
        if not any(enabled_modules.get(k) for k in ("sqli", "cmdi", "xxe")):
            return
        logger.info(
            "[INFO] injection_fp_guard active: false positives for XXE, CMDi, and SQLi are suppressed. "
            "URLs, crawl scope, thresholds, other scanners, and reporting pipelines remain unchanged. "
            "Suppressed hits log at [i]; no real vulnerabilities are affected.",
            extra={"phase": "injection_fp_guard"},
        )

    def scan_web(self, url: str, depth: int = 3) -> None:
        """Run full web scan with v5 thread/throttle/FSM pipeline."""
        try:
            from .request_stats import reset_http_request_total
            reset_http_request_total()
        except Exception:
            pass
        self.target = url
        self._start_time = time.perf_counter()
        self._sl = StructuredLogger(self.scan_id, self.output_dir, echo=False)
        self._sl.log_scan_start(target=url)
        self._engine = PentestEngine(
            target=url, scan_id=self.scan_id,
            log_dir=self.output_dir,
            on_state_change=lambda old, new, ctx:
                self._sl.log_state(old.name, new.name),
        )

        target: ScanContext = ScanContext(
            url,
            proxy=self.proxy,
            timeout=self.timeout,
            bearer_token=self.bearer_token,
        )
        self._scan_context_obj = target

        self._sl.log_metric("target", url)
        self._sl.log_metric("threads", self.threads)
        self._sl.log_metric("crawl_depth", depth)
        self._sl.log_metric("scan_id", self.scan_id)
        self._sl.log_metric("scan_intensity", self.scan_intensity)
        self._sl.log_metric("throttle_rps", self.throttle_rps)
        self._sl.log_metric("request_delay_sec", self.request_delay_sec)
        self._sl.log_metric("max_requests_budget", self.max_requests_budget)

        kw = dict(
            timeout=self.timeout,
            proxy=self.proxy,
            threads=self.threads,
            scan_intensity=self.scan_intensity,
            max_requests=self.max_requests_budget,
        )
        m = dict(self.modules)
        if self.scan_intensity == "light":
            for risky in ("cmdi", "xxe", "ssrf"):
                if m.get(risky):
                    m[risky] = False
                    logger.info(
                        "Light scan intensity: skipping invasive module %s",
                        risky,
                    )

        self._reset_scan_metrics()
        logger.info(
            "Scan started",
            extra={
                "kind": ScanEventKind.SCAN_START,
                "scan_id": self.scan_id,
                "target": url,
            },
        )
        self._log_injection_fp_guard_notice(m)

        scan_tok, mod_tok0 = observability.bind_scan_context(self.scan_id)
        try:
            self._engine.transition(ScanState.RECON, "scan_web start")

            _crawl_title = "CRAWLER — Discovering URLs"
            self._section(_crawl_title)
            _crawl_mod_tok = observability.set_module_context(_crawl_title)
            t0_crawl = time.perf_counter()
            self._sl.log_phase_start(_crawl_title)
            self._metrics_begin_unit()
            crawl_exc: Exception | None = None
            urls: list = []
            try:
                crawler = Crawler(url, depth=depth, **kw)
                crawl_out = crawler.crawl()
                urls = crawl_out.urls
                target.crawl_forms = list(crawl_out.forms)
                target.crawl_url_query_params = dict(crawl_out.url_query_params or {})
                st = dict(crawl_out.stats or {})
                st.update(count_query_parameters(urls))
                target.crawl_stats = st
                logger.info(
                    "  [*] Crawl integration: %s URLs, %s forms, %s distinct query keys, %s URLs with query param map",
                    st.get("unique_urls", len(urls)),
                    st.get("forms_total", len(target.crawl_forms)),
                    st.get("unique_query_keys", 0),
                    st.get("urls_query_param_maps", 0),
                )
                self._metrics_succeed_unit()
            except Exception as _e:
                self._metrics_fail_unit()
                crawl_exc = _e
            _crawl_dt = time.perf_counter() - t0_crawl
            crawl_status = "failed" if crawl_exc else "success"
            self._sl.log_phase_end(_crawl_title, _crawl_dt, len(urls), status=crawl_status)
            self._sl.log_module_complete(
                _crawl_title,
                duration_s=_crawl_dt,
                findings_count=len(urls),
                status=crawl_status,
            )
            self._record_module_metric(
                _crawl_title,
                _crawl_dt,
                0,
                crawl_status,
            )
            observability.reset_module_context(_crawl_mod_tok)
            if crawl_exc:
                raise crawl_exc
            self.urls = urls
            target.urls = urls
            logger.info(
                "Crawl finished",
                extra={
                    "kind": ScanEventKind.CRAWL_URLS_DISCOVERED,
                    "count": len(urls),
                },
            )
            self._scan_context = {
                "crawl_depth": depth, "threads": self.threads,
                "discovered_urls": len(urls),
                "crawl_forms": len(getattr(target, "crawl_forms", [])),
                "scan_intensity": self.scan_intensity,
                "throttle_rps": self.throttle_rps,
                "request_delay_sec": self.request_delay_sec,
                "max_requests_budget": self.max_requests_budget,
            }

            self._engine.transition(ScanState.AUTH_PROBE, "crawl done")
            self._timed_section("AUTHENTICATION AUDIT", lambda:
                self._run_auth_audit(url, urls, target))

            if self._auth_session:
                target.auth_session = self._auth_session
                # One canonical session for header/cookie scans and all modules that
                # use context.session (same object as auth_session after login).
                target.session = self._auth_session

            # §2.2: Prioritize high-value endpoints before scanning (queue order only)
            urls = self._prioritize_endpoints(
                urls,
                post_form_action_keys=post_form_action_keys_from_forms(
                    getattr(target, "crawl_forms", None),
                ),
            )
            target.urls = urls
            target.scan_targets = prepare_scan_targets(
                crawl_out,
                urls,
                target.session,
                timeout=self.timeout,
            )

            self._engine.transition(ScanState.ACTIVE_SCAN, "auth done")

            if m.get("waf"):
                self._timed_section("WAF DETECTION", lambda:
                    self._run_waf(url, kw))

            self._run_registered_web_modules(m, url, urls, kw, target)

            has_findings = any(not f.get("chain") for f in self.findings)
            if has_findings:
                self._engine.transition(ScanState.CHAIN_EVAL, "active scan done")
            if m.get("chain"):
                self._timed_section("VULNERABILITY CHAINING", lambda:
                    self._run_chaining())

            self._engine.transition(ScanState.VALIDATION, "chain eval done")
            self._timed_section(
                "FINDING CONSOLIDATION (PRE-VALIDATION)",
                lambda: self._run_group_similar_findings(),
            )
            self._timed_section(
                "FINDING DEDUPLICATION (ENDPOINT + PARAMETER)",
                lambda: self._run_dedupe_by_parameter(),
            )
            self._timed_section("EVIDENCE VALIDATION", lambda:
                self._run_validation())

            self._timed_section("CVSS SCORING", lambda:
                self._run_scoring())

            self._timed_section("SMART SEVERITY SCORING", lambda:
                self._run_smart_severity_scoring())

            self._timed_section("REPORT ENRICHMENT", lambda:
                self._run_enrichment())

            self._timed_section("EVIDENCE COLLECTION", lambda:
                self._run_evidence_collection(url))

            self._run_cvss_severity_enforcement()

            with self._lock:
                self._post_pipeline_findings_count = len(self.findings)

            ai_data = {}
            if self.ai_enabled:
                self._timed_section("AI NARRATIVE ANALYSIS", lambda:
                    self._run_ai_analysis())
                ai_data = self._last_ai_data

            self._engine.transition(ScanState.REPORTING, "analysis done")
            self._mark_findings_state("REPORTED")
            self._last_report_paths = self._generate_report(url, ai_data)

            self._engine.transition(ScanState.COMPLETE, "all done")

            gs = self._guard.summary()
            req_logged = gs.get("http_outbound_total", 0) or gs.get("total_requests", 0)
            self._sl.log_metric("total_requests", req_logged)
            self._sl.log_metric("budget_exhausted", gs["budget_exhausted"])
            self._emit_scan_metrics()
            self._print_guard_summary(gs)
            if self._sl:
                self._sl.log_scan_complete()
            try:
                if getattr(self, "_last_report_paths", None) and self._sl:
                    self._verify_output_artifacts(
                        self._last_report_paths,
                        jsonl_path=self._sl.path,
                        check_jsonl_events=True,
                    )
            except Exception:
                pass

        except Exception as exc:
            if self._engine:
                self._engine.abort(str(exc))
            if self._sl:
                self._sl.log_scan_aborted(error=str(exc))
            logger.error(
                "Scan aborted",
                extra={"kind": ScanEventKind.SCAN_ABORTED, "error": str(exc)},
            )
            # Best-effort report generation so output directory is complete.
            try:
                if not getattr(self, "_last_report_paths", None):
                    self._last_report_paths = self._generate_report(url, {})
            except Exception:
                pass
        finally:
            observability.reset_scan_context(scan_tok, mod_tok0)

    def _run_registered_web_modules(
        self,
        m: dict,
        url: str,
        urls: list,
        kw: dict,
        target: ScanContext,
    ) -> None:
        """
        Execute all enabled scanner/web modules via BaseScanner.run(target).
        Registry order matches the historical controller sequence.
        """
        waf_bypass = bool(self._waf)
        # §2.3: Concurrency control — heavy modules get fewer threads
        _HEAVY_MODULES = frozenset({"sqli", "lfi", "cmdi"})
        _LIGHT_MODULES = frozenset({"headers", "ssl", "cookies", "api",
                                    "redirect", "method", "headers_plus"})
        specs: list[tuple[str, str, Callable[[], BaseScanner]]] = [
            ("headers", "SECURITY HEADERS",
             lambda: HeaderScanner(url, **kw)),
            ("ssl", "SSL/TLS ANALYSIS",
             lambda: SSLScanner(url, **kw)),
            ("cookies", "COOKIE SECURITY",
             lambda: CookieScanner(url, **kw)),
            ("dirs", "DIRECTORY DISCOVERY",
             lambda: DirectoryScanner(url, **kw)),
            ("api", "API SECURITY TESTS",
             lambda: APISecurityScanner(url, urls, **kw)),
            ("idor", "IDOR HEURISTICS",
             lambda: IDORScanner(
                 urls, timeout=self.timeout, proxy=self.proxy,
                 session=self._auth_session,
                 max_requests=self.max_requests_budget)),
            ("rate", "RATE LIMITING HEURISTICS",
             lambda: RateLimitScanner(
                 urls, timeout=self.timeout, proxy=self.proxy,
                 max_requests=self.max_requests_budget)),
            ("redirect", "OPEN REDIRECT CHECKS",
             lambda: OpenRedirectScanner(
                 urls, timeout=self.timeout, proxy=self.proxy,
                 threads=self.threads,
                 max_requests=self.max_requests_budget)),
            ("method", "METHOD TAMPERING CHECKS",
             lambda: MethodTamperingScanner(
                 urls, timeout=self.timeout, proxy=self.proxy,
                 threads=self.threads,
                 max_requests=self.max_requests_budget)),
            ("headers_plus", "ENHANCED HEADER ANALYSIS",
             lambda: SecurityHeadersPlus(
                 url, urls, timeout=self.timeout, proxy=self.proxy,
                 max_requests=self.max_requests_budget)),
            ("lfi", "LFI / PATH TRAVERSAL",
             lambda: LFIScanner(urls, **kw)),
            ("sqli", "SQL INJECTION",
             lambda: SQLiScanner(urls, waf_bypass=waf_bypass, **kw)),
            ("xss", "CROSS-SITE SCRIPTING",
             lambda: XSSScanner(urls, waf_bypass=waf_bypass, **kw)),
            ("csrf", "CSRF CHECKS",
             lambda: CSRFScanner(url, urls, **kw)),
            ("ssrf", "SSRF CHECKS",
             lambda: SSRFScanner(urls, **kw)),
            ("cmdi", "COMMAND INJECTION",
             lambda: CMDiScanner(urls, **kw)),
            ("xxe", "XXE INJECTION",
             lambda: XXEScanner(urls, **kw)),
        ]

        for flag, title, factory in specs:
            if not m.get(flag):
                continue

            # §2.3: Adjust threads per module weight
            if flag in _HEAVY_MODULES:
                kw["threads"] = max(1, self.threads // 2)
            elif flag in _LIGHT_MODULES:
                kw["threads"] = min(self.threads + 5, 20)
            else:
                kw["threads"] = self.threads

            def _run_one(f=factory, ttl=title) -> None:
                self._execute_base_scanner(ttl, f, target)

            self._timed_section(title, _run_one)

    def _safe_module_results(self, name: str, fn: Callable[[], Any]) -> list:
        """Run a scanner callable; on failure log and return []."""
        try:
            r = fn()
            return r if isinstance(r, list) else []
        except Exception as e:
            self._module_step_failed = True
            logger.error(
                "Network module failed",
                extra={
                    "kind": ScanEventKind.NETWORK_MODULE_FAILED,
                    "module": name,
                    "error": str(e),
                },
            )
            if self._sl:
                self._sl.log_error(str(e), module=name)
            return []

    def _execute_base_scanner(
        self,
        title: str,
        factory: Callable[[], BaseScanner],
        target: ScanContext,
    ) -> None:
        """QUEUED → run(target) → collect with TESTED state."""
        if self._sl:
            self._sl.log_metric(f"module_{title}", "QUEUED")
        try:
            scanner = factory()
        except Exception as e:
            self._module_step_failed = True
            logger.error(
                "Scanner construction failed",
                extra={
                    "kind": ScanEventKind.MODULE_FAILED,
                    "module": title,
                    "error": str(e),
                },
            )
            if self._sl:
                self._sl.log_error(str(e), module=title)
            return
        if not isinstance(scanner, BaseScanner):
            self._module_step_failed = True
            err = f"{title}: expected BaseScanner, got {type(scanner)}"
            logger.error(
                "Scanner type mismatch",
                extra={
                    "kind": ScanEventKind.MODULE_FAILED,
                    "module": title,
                    "error": err,
                },
            )
            if self._sl:
                self._sl.log_error(err, module=title)
            return
        try:
            results = scanner.run(target)
        except Exception as e:
            self._module_step_failed = True
            logger.error(
                "Scanner run failed",
                extra={
                    "kind": ScanEventKind.MODULE_FAILED,
                    "module": title,
                    "error": str(e),
                },
            )
            if self._sl:
                self._sl.log_error(str(e), module=title)
            results = []
        if not isinstance(results, list):
            results = []
        self._collect(results, module_title=title)

    def scan_network(self, host: str) -> None:
        """Network scan with throttle + FSM."""
        try:
            from .request_stats import reset_http_request_total
            reset_http_request_total()
        except Exception:
            pass
        self._start_time = time.perf_counter()
        self._sl = StructuredLogger(self.scan_id, self.output_dir)
        self._sl.log_metric("target", host)
        self._sl.log_metric("scan_id", self.scan_id)
        self._sl.log_metric("scan_intensity", self.scan_intensity)
        self._sl.log_metric("throttle_rps", self.throttle_rps)
        self._sl.log_metric("request_delay_sec", self.request_delay_sec)
        self._sl.log_metric("max_requests_budget", self.max_requests_budget)
        self._sl.log_scan_start(target=host)
        self._reset_scan_metrics()
        logger.info(
            "Scan started",
            extra={
                "kind": ScanEventKind.SCAN_START,
                "scan_id": self.scan_id,
                "target": host,
            },
        )
        scan_tok, mod_tok0 = observability.bind_scan_context(self.scan_id)
        try:
            self._engine = PentestEngine(target=host, scan_id=self.scan_id,
                                         log_dir=self.output_dir)

            self._engine.transition(ScanState.RECON, "network scan start")
            self._section("NETWORK SCAN")

            self._timed_section("PORT SCAN", lambda: self._collect(
                self._safe_module_results(
                    "PORT SCAN",
                    lambda: PortScanner(host, timeout=1, threads=50).scan(),
                ), module_title="PORT SCAN"))

            open_ports = [f.get("port") for f in self.findings if f.get("port")]
            self._timed_section("BANNER GRABBING", lambda: self._collect(
                self._safe_module_results(
                    "BANNER GRABBING",
                    lambda: BannerGrabber(host, open_ports, timeout=3).grab(),
                ), module_title="BANNER GRABBING"))

            banner_findings = [f for f in self.findings if "banner" in f]
            self._timed_section("CVE CORRELATION", lambda: self._collect(
                self._safe_module_results(
                    "CVE CORRELATION",
                    lambda: CVEMatcher(banner_findings).match(),
                ), module_title="CVE CORRELATION"))

            # Run chaining before validation so that validated_findings includes
            # chain findings and counts remain consistent with the final report.
            self._engine.transition(ScanState.CHAIN_EVAL, "network scan done")
            self._timed_section("VULNERABILITY CHAINING", lambda:
                self._run_chaining())

            self._engine.transition(ScanState.VALIDATION, "active scan done")
            self._timed_section(
                "FINDING CONSOLIDATION (PRE-VALIDATION)",
                lambda: self._run_group_similar_findings(),
            )
            self._timed_section(
                "FINDING DEDUPLICATION (ENDPOINT + PARAMETER)",
                lambda: self._run_dedupe_by_parameter(),
            )
            self._timed_section("EVIDENCE VALIDATION", lambda:
                self._run_validation())
            self._timed_section("CVSS SCORING", lambda:
                self._run_scoring())
            self._timed_section("SMART SEVERITY SCORING", lambda:
                self._run_smart_severity_scoring())
            self._timed_section("REPORT ENRICHMENT", lambda:
                self._run_enrichment())
            self._run_cvss_severity_enforcement()

            with self._lock:
                self._post_pipeline_findings_count = len(self.findings)

            ai_data: dict = {}
            if self.ai_enabled:
                self._timed_section(
                    "AI NARRATIVE ANALYSIS",
                    lambda: self._run_ai_analysis(),
                )
                ai_data = self._last_ai_data or {}

            self._engine.transition(ScanState.REPORTING, "validation done")
            self._mark_findings_state("REPORTED")
            self._last_report_paths = self._generate_report(host, ai_data)
            self._emit_scan_metrics()
            if self._sl:
                self._sl.log_scan_complete()
            try:
                if getattr(self, "_last_report_paths", None) and self._sl:
                    self._verify_output_artifacts(
                        self._last_report_paths,
                        jsonl_path=self._sl.path,
                        check_jsonl_events=True,
                    )
            except Exception:
                pass
            self._engine.transition(ScanState.COMPLETE, "all done")
        except Exception as exc:
            if self._engine:
                self._engine.abort(str(exc))
            if self._sl:
                self._sl.log_scan_aborted(error=str(exc))
            logger.error(
                "Scan aborted",
                extra={"kind": ScanEventKind.SCAN_ABORTED, "error": str(exc)},
            )
            # Best-effort: still write reports so output directory is complete.
            try:
                if not getattr(self, "_last_report_paths", None):
                    self._last_report_paths = self._generate_report(host, {})
            except Exception:
                pass
        finally:
            observability.reset_scan_context(scan_tok, mod_tok0)

    def _collect(
        self,
        new_findings: list[dict],
        module_title: str | None = None,
    ) -> None:
        if not isinstance(new_findings, list):
            return
        approved = []
        mod_label = (module_title or "unknown").strip() or "unknown"
        for f in self._validated_findings(new_findings, module_title):
            ef = enrich_finding_record(
                f, scan_id=self.scan_id, module=mod_label,
            )
            sev = ef.get("severity", "INFO")
            if self._guard.record_finding(sev):
                approved.append(ef)
                if self._sl:
                    self._sl.log_finding(ef)
                if self._engine:
                    live = self._engine._chain_tracker.observe(ef)
                    if live:
                        normalized_live: list[dict] = []
                        for lc in live:
                            nl, _ = normalize_finding_row(lc)
                            if nl is not None:
                                nl = enrich_chain_record(
                                    nl,
                                    scan_id=self.scan_id,
                                    related_finding_ids=nl.get(
                                        "related_finding_ids",
                                    ),
                                    module=str(
                                        nl.get("module") or "VULNERABILITY CHAINING",
                                    ),
                                )
                                normalized_live.append(nl)
                        if normalized_live:
                            with self._lock:
                                self.findings.extend(normalized_live)
                            for nl in normalized_live:
                                if self._sl:
                                    self._sl.log_chain(nl)
            else:
                pass

        for f in approved:
            if f.get("chain"):
                continue
            f.setdefault("lifecycle_states", list(LIFECYCLE_STATES))
            f["scan_state"] = "TESTED"
            if module_title and self._sl:
                self._sl.log_metric(
                    "finding_lifecycle",
                    {"module": module_title, "state": "TESTED"},
                    module=mod_label,
                )

        with self._lock:
            self.findings.extend(approved)

    def _validated_findings(
        self,
        rows: list,
        module_title: str | None,
    ):
        """Yield only normalized dicts that satisfy the strict finding schema."""
        mod = module_title or ""
        for raw in rows:
            nf, reason = normalize_finding_row(raw)
            if nf is None:
                logger.debug(
                    "Finding rejected",
                    extra={
                        "kind": ScanEventKind.FINDING_REJECTED,
                        "reason": reason,
                        "module": mod,
                    },
                )
                continue
            yield nf

    def _mark_findings_state(self, state: str) -> None:
        with self._lock:
            rows = list(self.findings)
        for f in rows:
            if not isinstance(f, dict) or f.get("chain"):
                continue
            f.setdefault("lifecycle_states", list(LIFECYCLE_STATES))
            f["scan_state"] = state

    def _collect_throttled(self, fn, domain: str, module: str) -> None:
        if not self._guard.record_request(module):
            logger.warning(
                "Request skipped by guard",
                extra={
                    "kind": ScanEventKind.THROTTLE_CIRCUIT_SKIP,
                    "module": module,
                    "reason": "circuit-breaker or budget hit",
                },
            )
            return
        self._throttler.wait(domain)
        try:
            result = fn()
            self._collect(result or [], module_title=module)
            self._throttler.record_success(domain)
            self._guard.record_request(module, error=False)
        except Exception as exc:
            self._guard.record_request(module, error=True)
            logger.error(
                "Throttled module failed",
                extra={
                    "kind": ScanEventKind.HTTP_MODULE_FAILED,
                    "module": module,
                    "error": str(exc),
                },
            )
            self._sl and self._sl.log_error(str(exc), module=module)

    def _run_auth_audit(
        self,
        url: str,
        urls: list,
        target: ScanContext,
    ) -> None:
        try:
            aa = AuthAudit(
                url, urls, timeout=self.timeout,
                proxy=self.proxy, threads=self.threads,
                credentials=self.credentials,
            )
            results = aa.run(target)
            self._collect(results, module_title="AUTHENTICATION AUDIT")
            if target.auth_session:
                self._auth_session = target.auth_session
                logger.success(
                    "Authentication session established",
                    extra={"kind": ScanEventKind.AUTH_SESSION_ESTABLISHED},
                )
        except Exception as e:
            logger.warning(
                "Auth audit failed",
                extra={"kind": ScanEventKind.AUTH_AUDIT_FAILED, "error": str(e)},
            )

    def _run_waf(self, url: str, kw: dict) -> None:
        # §1.1: WAFDetector now accepts scan_intensity, timeout, headers
        # Backward-compat: retry with minimal args on TypeError
        def _try_waf(**wkw):
            wd = WAFDetector(url, **wkw)
            self._waf = wd.detect()
            self._collect(wd.findings, module_title="WAF DETECTION")
            if self._waf:
                self._scan_context_obj.waf_detected = True

        waf_kw = dict(kw)
        waf_kw.setdefault("scan_intensity", self.scan_intensity)
        try:
            _try_waf(**waf_kw)
        except TypeError:
            # WAFDetector may not yet accept scan_intensity — retry minimal
            try:
                _try_waf(timeout=self.timeout, proxy=self.proxy)
            except Exception as e2:
                logger.warning("WAF detection failed",
                    extra={"kind": ScanEventKind.WAF_DETECTION_FAILED, "error": str(e2)})
        except Exception as e:
            logger.warning("WAF detection failed",
                extra={"kind": ScanEventKind.WAF_DETECTION_FAILED, "error": str(e)})

    def _run_chaining(self) -> None:
        with self._lock:
            current = list(self.findings)
        chains = VulnChainer(current).analyse(scan_id=self.scan_id)
        if chains:
            with self._lock:
                self.findings.extend(chains)
            for c in chains:
                self._sl and self._sl.log_chain(c)

    def _run_validation(self) -> None:
        with self._lock:
            current = list(self.findings)
        validated, stats = EvidenceValidator(current).validate()
        for f in validated:
            if isinstance(f, dict) and not f.get("chain"):
                f.setdefault("lifecycle_states", list(LIFECYCLE_STATES))
                f["scan_state"] = "CONFIRMED"
        with self._lock:
            self.findings = validated
        self._validated_findings_count = len(validated)
        self._validation_report = stats
        logger.info(
            "[INFO] Validation summary: %s/%s findings retained after validation",
            len(validated),
            stats.get("total_input", 0),
        )

    def _run_scoring(self) -> None:
        with self._lock:
            current = list(self.findings)
        scored = ScoringEngine(current).score_all()
        with self._lock:
            self.findings = scored

    def _run_smart_severity_scoring(self) -> None:
        """§4 — Contextual severity: admin/sensitive param → boost; reflection-only → lower."""
        try:
            from config import smart_severity_adjust
        except ImportError:
            return
        with self._lock:
            current = list(self.findings)
        adjusted = []
        for f in current:
            if not isinstance(f, dict) or f.get("chain"):
                adjusted.append(f)
                continue
            new_sev = smart_severity_adjust(f)
            if new_sev != f.get("severity", "INFO"):
                nf = dict(f)
                nf["_original_severity"] = f.get("severity")
                nf["severity"] = new_sev
                adjusted.append(nf)
            else:
                adjusted.append(f)
        with self._lock:
            self.findings = adjusted

    def _run_enrichment(self) -> None:
        with self._lock:
            current = list(self.findings)
        enriched = enrich_findings(current)
        with self._lock:
            self.findings = enriched

    def _run_evidence_collection(self, url: str) -> None:
        try:
            collector = EvidenceCollector(
                self.findings, url,
                timeout=self.timeout, proxy=self.proxy,
            )
            enriched, extra = collector.collect()
            with self._lock:
                self.findings = enriched
                self._extra_evidence = extra
        except Exception as exc:
            logger.warning(
                "Evidence collection failed",
                extra={"kind": ScanEventKind.EVIDENCE_COLLECTION_FAILED, "error": str(exc)},
            )

    def _merge_ai_analysis_onto_findings(
        self,
        pre_ai: list[dict],
        ai_result: dict,
    ) -> list[dict]:
        """
        Keep the validated finding row count; copy ``ai_analysis`` from the analyst's
        internally merged rows (type + parameter for non-chain; finding_id for chains).
        """
        self.chain_ai_overlay_skipped = False
        self._invalid_chain_finding_count = 0
        merged = ai_result.get("findings")
        if not isinstance(merged, list):
            merged = []
        if not merged:
            if pre_ai:
                logger.warning(
                    "AI narrative returned no finding rows; keeping validated findings list unchanged",
                    extra={"kind": ScanEventKind.AI_ANALYSIS_FAILED, "pre_count": len(pre_ai)},
                )
            return [dict(f) for f in pre_ai if isinstance(f, dict)]

        non_merged = [x for x in merged if isinstance(x, dict) and not x.get("chain")]
        chain_merged = [x for x in merged if isinstance(x, dict) and x.get("chain")]

        ai_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for f in non_merged:
            k = _type_param_merge_key(f)
            aa = f.get("ai_analysis")
            if isinstance(aa, dict):
                ai_by_key[k] = aa

        pre_non: list[dict] = []
        pre_chain: list[dict] = []
        for f in pre_ai:
            if not isinstance(f, dict):
                continue
            cp = dict(f)
            if cp.get("chain"):
                pre_chain.append(cp)
            else:
                pre_non.append(cp)

        for f in pre_non:
            k = _type_param_merge_key(f)
            if k in ai_by_key:
                f["ai_analysis"] = dict(ai_by_key[k])

        chain_id_invalid: list[dict[str, Any]] = []
        for i, cf in enumerate(pre_chain):
            if _normalize_finding_id(cf.get("finding_id")):
                continue
            chain_id_invalid.append(
                {
                    "pre_chain_index": i,
                    "finding_id_original": cf.get("finding_id"),
                },
            )
        skip_chain_ai_overlay = bool(chain_id_invalid)
        if skip_chain_ai_overlay:
            self.chain_ai_overlay_skipped = True
            self._invalid_chain_finding_count = len(chain_id_invalid)
            logger.error(
                "[ERROR] Chain finding(s) have missing or empty finding_id; skipping chain AI overlay",
                extra={
                    "phase": "chain_ai_overlay",
                    "invalid_chain_finding_ids": chain_id_invalid,
                    "pre_chain_count": len(pre_chain),
                },
            )

        if not skip_chain_ai_overlay:
            allow_chain_positional = os.environ.get(
                "ALANSCAN_CHAIN_AI_POSITIONAL_FALLBACK", ""
            ).strip().lower() in ("1", "true", "yes")

            merged_indices_by_nid: dict[str, list[int]] = defaultdict(list)
            merged_without_id: list[int] = []
            for j, x in enumerate(chain_merged):
                mid = _normalize_finding_id(x.get("finding_id"))
                if mid:
                    merged_indices_by_nid[mid].append(j)
                else:
                    merged_without_id.append(j)

            dup_merged_nids = {n: idxs for n, idxs in merged_indices_by_nid.items() if len(idxs) > 1}
            if dup_merged_nids:
                logger.warning(
                    "[WARN] Duplicate normalized finding_id in AI chain rows",
                    extra={
                        "kind": _K_FINDING_COUNT_MISMATCH,
                        "phase": "chain_ai_overlay",
                        "duplicate_merged_ids": {
                            k: idxs for k, idxs in dup_merged_nids.items()
                        },
                    },
                )

            pre_nid_counts: dict[str, int] = defaultdict(int)
            for f in pre_chain:
                pn = _normalize_finding_id(f.get("finding_id"))
                if pn:
                    pre_nid_counts[pn] += 1
            dup_pre_nids = {n: c for n, c in pre_nid_counts.items() if c > 1}
            if dup_pre_nids:
                logger.warning(
                    "[WARN] Duplicate normalized finding_id in pre-AI chain rows",
                    extra={
                        "kind": _K_FINDING_COUNT_MISMATCH,
                        "phase": "chain_ai_overlay",
                        "duplicate_pre_counts": dict(dup_pre_nids),
                    },
                )

            used_merged_chain: set[int] = set()
            strict_matched_pre_indices: set[int] = set()

            for i, f in enumerate(pre_chain):
                cid = _normalize_finding_id(f.get("finding_id"))
                if not cid:
                    continue
                pool = [j for j in merged_indices_by_nid.get(cid, []) if j not in used_merged_chain]
                if not pool:
                    continue
                j = pool[0]
                used_merged_chain.add(j)
                src = chain_merged[j]
                if isinstance(src.get("ai_analysis"), dict):
                    f["ai_analysis"] = dict(src["ai_analysis"])
                strict_matched_pre_indices.add(i)

            unmatched_pre: list[dict[str, Any]] = []
            for i, f in enumerate(pre_chain):
                if i in strict_matched_pre_indices:
                    continue
                orig = f.get("finding_id")
                nid = _normalize_finding_id(orig)
                reason = "missing_finding_id" if not nid else "no_ai_row_for_id"
                unmatched_pre.append(
                    {
                        "pre_chain_index": i,
                        "finding_id_original": orig,
                        "finding_id_normalized": nid,
                        "reason": reason,
                    },
                )

            unused_merged: list[dict[str, Any]] = []
            for j, x in enumerate(chain_merged):
                if j in used_merged_chain:
                    continue
                unused_merged.append(
                    {
                        "merged_chain_index": j,
                        "finding_id_original": x.get("finding_id"),
                        "finding_id_normalized": _normalize_finding_id(x.get("finding_id")),
                    },
                )

            if unmatched_pre or unused_merged:
                logger.warning(
                    "[WARN] Chain AI overlay: strict finding_id match incomplete",
                    extra={
                        "kind": _K_FINDING_COUNT_MISMATCH,
                        "phase": "chain_ai_overlay",
                        "unmatched_pre_chain": unmatched_pre,
                        "unused_merged_chain": unused_merged,
                        "allow_positional_fallback": allow_chain_positional,
                    },
                )

            if allow_chain_positional and (unmatched_pre or unused_merged):
                unused_queue = [j for j in range(len(chain_merged)) if j not in used_merged_chain]
                for i, f in enumerate(pre_chain):
                    if i in strict_matched_pre_indices:
                        continue
                    if isinstance(f.get("ai_analysis"), dict):
                        continue
                    if not unused_queue:
                        break
                    j = unused_queue.pop(0)
                    used_merged_chain.add(j)
                    src = chain_merged[j]
                    if isinstance(src.get("ai_analysis"), dict):
                        f["ai_analysis"] = dict(src["ai_analysis"])
                    logger.warning(
                        "[WARN] Chain AI overlay: degraded positional assignment "
                        "(ALANSCAN_CHAIN_AI_POSITIONAL_FALLBACK)",
                        extra={
                            "kind": _K_FINDING_COUNT_MISMATCH,
                            "phase": "chain_ai_overlay_degraded",
                            "pre_chain_index": i,
                            "merged_chain_index": j,
                            "pre_finding_id_original": f.get("finding_id"),
                            "merged_finding_id_original": src.get("finding_id"),
                        },
                    )

        if len(non_merged) < len(pre_non):
            logger.info(
                "AI narrative merged %s non-chain rows into %s for LLM context; "
                "reports keep all %s validated rows with shared ai_analysis per (issue class, parameter)",
                len(pre_non),
                len(non_merged),
                len(pre_non),
                extra={
                    "phase": "ai_narrative_merge",
                    "pre_non_chain_rows": len(pre_non),
                    "ai_non_chain_rows": len(non_merged),
                },
            )

        out: list[dict] = []
        i_nc, i_ch = 0, 0
        for f in pre_ai:
            if not isinstance(f, dict):
                continue
            if f.get("chain"):
                out.append(pre_chain[i_ch])
                i_ch += 1
            else:
                out.append(pre_non[i_nc])
                i_nc += 1
        return out

    def _run_ai_analysis(self) -> None:
        if not self.ai_enabled:
            logger.info("[INFO] AI narrative analysis skipped (disabled)")
            return
        try:
            with self._lock:
                snapshot = list(self.findings)
            result = AIAnalyst(snapshot, api_key=self.api_key).analyse()
            overlaid = self._merge_ai_analysis_onto_findings(snapshot, result)
            result["findings"] = overlaid
            result["priority_order"] = list(range(len(overlaid)))
            if len(overlaid) != len(snapshot):
                logger.warning(
                    "[WARN] Finding count mismatch: validated=%s, final=%s",
                    len(snapshot),
                    len(overlaid),
                    extra={
                        "kind": _K_FINDING_COUNT_MISMATCH,
                        "validated_findings_count": len(snapshot),
                        "final_findings_count": len(overlaid),
                        "phase": "post_ai_overlay",
                    },
                )
            with self._lock:
                self.findings = overlaid
            self._last_ai_data = result
            logger.info(
                "[INFO] AI narrative analysis completed; findings=%s",
                len(overlaid),
            )
        except Exception as e:
            err = str(e)
            user_ai = user_facing_ai_message_from_exc(e)
            err_type = classify_ai_api_error(e)
            logger.warning(
                "%s",
                user_ai,
                extra={
                    "kind": ScanEventKind.AI_ANALYSIS_FAILED,
                    "error": err,
                    "error_type": err_type,
                },
            )
            with self._lock:
                snap = list(self.findings)
            logger.info(
                "[INFO] AI narrative analysis failed; findings unchanged (%s rows)",
                len(snap),
            )
            self._last_ai_data = {
                "executive_summary": (
                    f"{user_ai} Deterministic templates apply; findings list is unchanged."
                ),
                "vulnerability_summary": (
                    f"{user_ai} Use the findings table and JSON export for technical detail."
                ),
                "risk_explanation": (
                    "Risk assessment text was not generated; use severity counts and CVSS data "
                    "in this report until the narrative module succeeds."
                ),
                "attack_chain_description": (
                    "Attack chain narrative was not generated due to a narrative module error."
                ),
                "stakeholder_summary": (
                    "Stakeholder narrative was not generated; use raw severity data and logs."
                ),
                "top_3_priorities": "",
                "attacker_perspective": "",
                "remediation_roadmap": "",
                "compliance_impact": "",
                "overall_risk": "Unknown",
                "total_fix_effort": "Unknown",
                "findings": snap,
                "priority_order": [],
                "narrative_processing_seconds": 0.0,
            }

    def _run_group_similar_findings(self) -> None:
        """Count-changing SQLi grouping done before validation."""
        with self._lock:
            before = len(self.findings)
            self.findings = self._group_similar_findings(self.findings)
            after = len(self.findings)
        if after < before:
            logger.info(
                "Finding consolidation (similar SQLi) removed %s row(s); %s remain before deduplication "
                "(reason: same-endpoint SQLi merged into one row)",
                before - after,
                after,
                extra={
                    "phase": "group_similar",
                    "removed": before - after,
                    "remaining": after,
                },
            )

    def _run_dedupe_by_parameter(self) -> None:
        """One row per endpoint + parameter + issue class (highest severity wins)."""
        with self._lock:
            self.findings = self._dedupe_findings_by_parameter(self.findings)

    def _dedupe_findings_by_parameter(self, rows: list[dict]) -> list[dict]:
        if not rows:
            return rows

        def _key(f: dict) -> tuple:
            if f.get("chain"):
                cid = str(f.get("chain_id", "") or f.get("finding_id", "") or "")
                if not cid:
                    cid = hashlib.sha256(
                        f"{f.get('type', '')}|{f.get('payload', '')}|{f.get('severity', '')}".encode(
                            "utf-8",
                            errors="replace",
                        ),
                    ).hexdigest()[:16]
                return ("chain", cid)
            u = coerce_evidence_field(f.get("url", ""))
            try:
                p = urlparse(u)
                base = f"{p.scheme}://{p.netloc}{p.path}".lower().rstrip("/")
            except Exception:
                base = u.split("?", 1)[0].lower()
            param = coerce_evidence_field(f.get("parameter", "")).lower()
            ftype = coerce_evidence_field(f.get("type", "")).lower()
            if "sql" in ftype:
                bucket = "sqli"
            elif "xss" in ftype or "ssti" in ftype:
                bucket = "xss"
            elif "csrf" in ftype:
                bucket = "csrf"
            elif "cmdi" in ftype or "command" in ftype:
                bucket = "cmdi"
            elif "lfi" in ftype or "traversal" in ftype:
                bucket = "lfi"
            else:
                bucket = ftype[:48] or "misc"
            return ("f", base, param, bucket)

        buckets: dict[tuple, list[dict]] = defaultdict(list)
        for f in rows:
            if not isinstance(f, dict):
                continue
            buckets[_key(f)].append(f)

        out: list[dict] = []
        for grp in buckets.values():
            if len(grp) == 1:
                out.append(grp[0])
                continue

            def _rank(x: dict) -> tuple:
                sev = _SEV_RANK_DEDUPE.get(
                    str(x.get("severity", "INFO")).upper(), 9,
                )
                sc = x.get("scoring") or {}
                cv = 0.0
                if isinstance(sc, dict):
                    try:
                        cv = float(sc.get("base_cvss", 0) or 0)
                    except (TypeError, ValueError):
                        cv = 0.0
                ev_len = len(coerce_evidence_field(x.get("evidence", "")))
                return (sev, -cv, -ev_len)

            best = min(grp, key=_rank)
            out.append(best)
        removed = len(rows) - len(out)
        if removed:
            logger.info(
                "Finding deduplication removed %s row(s); %s remain before validation "
                "(reason: same endpoint + parameter + issue class — highest severity row kept)",
                removed,
                len(out),
                extra={
                    "phase": "dedupe_by_parameter",
                    "removed": removed,
                    "remaining": len(out),
                },
            )
        return out

    def _performance_insights(self) -> dict[str, Any]:
        mt = dict(self._module_times or {})
        if not mt:
            return {"summary": "", "slowest": [], "tips": []}
        slow = sorted(mt.items(), key=lambda x: -float(x[1]))[:10]
        tips: list[str] = []
        if slow and float(slow[0][1]) > 90.0:
            tips.append(
                f"Slowest phase was «{slow[0][0]}» ({float(slow[0][1]):.1f}s). "
                "Try --intensity light, lower --depth, or fewer enabled modules."
            )
        if len(mt) >= 14:
            tips.append(
                "Large sequential module count — disable unused checks in the profile for CI-style runs."
            )
        if self.scan_intensity == "aggressive":
            tips.append(
                "Aggressive intensity uses full payload sets; use medium/light for rate-sensitive targets."
            )
        if float(self.throttle_rps) < 5.0:
            tips.append(
                "Low --rate-limit increases wall-clock time but reduces load on fragile targets."
            )
        summary = "\n".join(
            f"• {n}: {float(s):.2f}s" for n, s in slow[:6]
        )
        return {"summary": summary, "slowest": slow, "tips": tips}

    def _run_cvss_severity_enforcement(self) -> None:
        """Count-preserving severity normalization after scoring."""
        with self._lock:
            self.findings = self._enforce_cvss_severity(self.findings)

    def _run_consolidation(self) -> None:
        """Backward-compatible wrapper (group + enforce)."""
        self._run_group_similar_findings()
        self._run_cvss_severity_enforcement()

    def _enforce_cvss_severity(self, findings: list) -> list:
        out = []
        for f in findings:
            nf = dict(f)
            if not nf.get("chain"):
                sc = nf.get("scoring", {}) or {}
                band = sc.get("severity_band")
                if band:
                    nf["severity"] = band
            out.append(nf)
        return out

    def _group_similar_findings(self, findings: list) -> list:
        grouped = []
        used = set()
        for i, f in enumerate(findings):
            if i in used:
                continue
            if f.get("chain"):
                grouped.append(f)
                continue
            ftype = coerce_evidence_field(f.get("type", "")).lower()
            if "sql" not in ftype:
                grouped.append(f)
                continue
            try:
                p = urlparse(coerce_evidence_field(f.get("url", "")))
                base_key = f"{p.scheme}://{p.netloc}{p.path}"
                endpoint = p.path.lower()
            except Exception:
                base_key = coerce_evidence_field(f.get("url", "")).split("?", 1)[0]
                endpoint = base_key.lower()
            params = []
            members = []
            for j, g in enumerate(findings):
                if j in used or g.get("chain"):
                    continue
                gt = coerce_evidence_field(g.get("type", "")).lower()
                if "sql" not in gt:
                    continue
                gp = coerce_evidence_field(g.get("url", "")).split("?", 1)[0]
                if gp != base_key:
                    continue
                used.add(j)
                members.append(g)
                prm = coerce_evidence_field(g.get("parameter", "")).strip()
                if prm and prm not in ("N/A", "") and prm not in params:
                    params.append(prm)
            if not members:
                grouped.append(f)
                continue
            primary = max(
                members,
                key=lambda x: float(
                    (
                        (x.get("scoring", {}) or {}).get("base_cvss")
                        or 0
                    )
                ),
            )
            label = ("Login Form"
                     if any(k in endpoint for k in ["login", "dologin", "signin", "auth"])
                     else "Endpoint")
            param_text = ", ".join(params) if params else "N/A"
            merged = dict(primary)
            merged["type"] = (
                f"SQL INJECTION – {label} ({param_text})"
            ).upper()
            merged["parameter"] = param_text
            merged["evidence"] = " | ".join(
                [str(m.get("evidence", "")) for m in members[:3]
                 if m.get("evidence")]
            )[:1200]
            vals = [m.get("validation", {}) for m in members
                    if isinstance(m.get("validation", {}), dict)]
            if vals:
                has_confirmed = any(v.get("verification_status") == "Confirmed"
                                    for v in vals)
                merged.setdefault("validation", {})
                merged["validation"]["verification_status"] = (
                    "Confirmed" if has_confirmed
                    else "Potential / needs manual verification"
                )
            grouped.append(merged)
        return grouped

    def _prioritize_endpoints(
        self,
        urls: list,
        *,
        post_form_action_keys: set | None = None,
    ) -> list:
        """
        §2.2: Endpoint prioritization (execution order only).

        Order: POST form actions → URLs with query parameters → dynamic application
        paths → static HTML-style pages → static assets. Within a tier, sensitive
        path hints (login, api, …) sort earlier. Original crawl order is preserved
        as a stable tie-breaker.
        """
        if not urls:
            return []
        fk = post_form_action_keys or set()
        indexed = list(enumerate(urls))
        indexed.sort(
            key=lambda iu: (
                url_scan_queue_rank(iu[1], post_form_action_keys=fk),
                iu[0],
            ),
        )
        return [iu[1] for iu in indexed]

    def _estimate_requests(self, url_count: int) -> str:
        try:
            total = url_count * 12 + 150
            if total > 5000:
                return f"~{round(total/1000, 1)}K"
            return str(total)
        except Exception:
            return "N/A"

    # ── Report safety normalization ────────────────────────────────────────

    _REPORT_FLOAT_KEYS = {
        "base_cvss",
        "cvss_score",
        "confidence",
        "duration",
        "duration_s",
        "scan_duration",
        "scan_time",
        "total_time",
        "seconds",
        "elapsed_s",
        "error_rate",
        "rate",
        "value",
    }
    _REPORT_INT_KEYS = {
        "port",
        "total_open",
        "total_modules",
        "successful_modules",
        "failed_modules",
        "total_findings",
        "findings_count",
        "threads",
        "pool_workers",
        "requests",
        "discovered_urls",
        "seq",
    }

    def _sanitize_for_report(self, obj: Any, *, key: str | None = None) -> Any:
        """
        Replace None values anywhere under report inputs.

        - For known numeric keys, None becomes 0/0.0 to avoid float() crashes.
        - For everything else, None becomes "".
        """
        if obj is None:
            if key in self._REPORT_FLOAT_KEYS:
                return 0.0
            if key in self._REPORT_INT_KEYS:
                return 0
            return ""
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                ks = safe_str(k) if k is not None else ""
                out[ks] = self._sanitize_for_report(v, key=ks)
            return out
        if isinstance(obj, list):
            return [self._sanitize_for_report(x) for x in obj]
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="replace")
        return obj

    def _verify_output_artifacts(
        self,
        paths: dict[str, str],
        *,
        jsonl_path: str = "",
        check_jsonl_events: bool = False,
    ) -> None:
        """Final production validation: ensure outputs exist and are non-empty."""
        def _contains_none(obj: Any) -> bool:
            if obj is None:
                return True
            if isinstance(obj, dict):
                return any(_contains_none(v) for v in obj.values())
            if isinstance(obj, list):
                return any(_contains_none(x) for x in obj)
            return False

        def _ok_file(p: str) -> bool:
            try:
                return bool(p) and os.path.exists(p) and os.path.getsize(p) > 0
            except Exception:
                return False

        html_p = paths.get("html", "")
        pdf_p = paths.get("pdf", "")
        json_p = paths.get("json", "")

        html_ok = _ok_file(html_p)
        pdf_ok = _ok_file(pdf_p)
        json_ok = _ok_file(json_p)

        # JSONL: not empty, parses, and payload contains no None values.
        jsonl_ok = False
        seen_events: set[str] = set()
        if jsonl_path:
            try:
                jsonl_ok = os.path.exists(jsonl_path) and os.path.getsize(jsonl_path) > 0
                if jsonl_ok:
                    with open(jsonl_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            rec = json.loads(line)
                            # Required envelope keys
                            required_keys = {
                                "schema",
                                "schema_version",
                                "event_version",
                                "event_id",
                                "scan_id",
                                "event",
                                "module",
                                "timestamp",
                                "ts_iso",
                                "payload",
                            }
                            if not required_keys.issubset(set(rec.keys())):
                                jsonl_ok = False
                                break
                            if _contains_none(rec.get("payload")):
                                jsonl_ok = False
                                break
                            seen_events.add(str(rec.get("event", "")))
            except Exception:
                jsonl_ok = False

        # Validate HTML/PDF basic sanity
        if html_ok:
            try:
                with open(html_p, "r", encoding="utf-8") as f:
                    head = f.read(2048)
                if "<html" not in head.lower():
                    html_ok = False
            except Exception:
                html_ok = False
        if json_ok:
            try:
                with open(json_p, "r", encoding="utf-8") as f:
                    json.loads(f.read())
            except Exception:
                json_ok = False

        if not html_ok:
            logger.error("HTML report invalid or empty", extra={"kind": "OUTPUT_VALIDATE_FAIL", "file": html_p})
        if not pdf_ok:
            logger.error("PDF report invalid or empty", extra={"kind": "OUTPUT_VALIDATE_FAIL", "file": pdf_p})
        if not json_ok:
            logger.error("JSON report invalid or empty", extra={"kind": "OUTPUT_VALIDATE_FAIL", "file": json_p})
        if not jsonl_ok:
            logger.error("JSONL log invalid or empty", extra={"kind": "OUTPUT_VALIDATE_FAIL", "file": jsonl_path})
        elif check_jsonl_events:
            # Minimum event coverage (scan is finished, so these must exist).
            missing = {"SCAN_START", "SCAN_METRICS", "SCAN_COMPLETE"} - seen_events
            if missing:
                logger.error(
                    "JSONL missing required scan events",
                    extra={"kind": "OUTPUT_VALIDATE_FAIL", "missing_events": sorted(missing), "file": jsonl_path},
                )

    def _generate_report(self, target: str, ai_data: dict) -> dict[str, str]:
        self._section("GENERATING REPORTS")
        html_path = ""
        pdf_path = ""
        json_path = ""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except Exception as e:
            logger.error(
                "[ERROR] Report generation failed: %s",
                e,
                extra={"kind": ScanEventKind.REPORT_SAVE_FAILED, "phase": "makedirs"},
            )
        safe_target = safe_str(target) or "N/A"
        safe_findings = self._sanitize_for_report(self.findings)
        safe_ai_data = self._sanitize_for_report(ai_data or {})
        final_n = len(self.findings)
        if (
            self._validated_findings_count is not None
            and self._validated_findings_count != final_n
        ):
            logger.warning(
                "[WARN] Finding count mismatch: validated=%s, final=%s",
                self._validated_findings_count,
                final_n,
                extra={
                    "kind": _K_FINDING_COUNT_MISMATCH,
                    "validated_findings_count": self._validated_findings_count,
                    "final_findings_count": final_n,
                    "phase": "report_generation",
                },
            )
        if (
            self._post_pipeline_findings_count is not None
            and self._post_pipeline_findings_count != final_n
        ):
            logger.warning(
                "[WARN] Finding count mismatch: post_pipeline=%s, final=%s",
                self._post_pipeline_findings_count,
                final_n,
                extra={
                    "kind": _K_FINDING_COUNT_MISMATCH,
                    "post_pipeline_findings_count": self._post_pipeline_findings_count,
                    "final_findings_count": final_n,
                    "phase": "report_generation",
                },
            )
        extra_data = {
            "validation_report": self._validation_report,
            "ai_summary": {
                "overall_risk": ai_data.get("overall_risk", ""),
                "executive_summary": ai_data.get("executive_summary", ""),
                "vulnerability_summary": ai_data.get("vulnerability_summary", ""),
                "risk_explanation": ai_data.get("risk_explanation", ""),
                "attack_chain_description": ai_data.get(
                    "attack_chain_description",
                    "",
                ),
                "stakeholder_summary": ai_data.get("stakeholder_summary", ""),
                "narrative_processing_seconds": ai_data.get(
                    "narrative_processing_seconds",
                    0.0,
                ),
                "total_fix_effort": ai_data.get("total_fix_effort", ""),
                "llm_attack_paths": ai_data.get("llm_attack_paths", ""),
                "llm_business_impact": ai_data.get("llm_business_impact", ""),
            },
            "scan_metrics": {
                "total_time": round(
                    time.perf_counter() - (
                        self._start_time if hasattr(self, "_start_time")
                        else time.perf_counter()
                    ), 2),
                "scan_id": self.scan_id,
                "module_times": self._module_times,
                "findings_count": len(self.findings),
                "validated_findings_count": self._validated_findings_count,
                "post_pipeline_findings_count": self._post_pipeline_findings_count,
                "threads": self.threads,
                "request_estimate": self._estimate_requests(len(self.urls)),
                "crawl_depth": self._scan_context.get("crawl_depth", "N/A"),
                "discovered_urls": len(self.urls),
                "guard_summary": self._guard.summary(),
                "pool_workers": self._pool.current_workers,
                "scan_intensity": self.scan_intensity,
                "throttle_rps": self.throttle_rps,
                "request_delay_sec": self.request_delay_sec,
                "max_requests_budget": self.max_requests_budget,
                "performance_insights": self._performance_insights(),
                "chain_ai_overlay_skipped": self.chain_ai_overlay_skipped,
                "invalid_chain_finding_count": self._invalid_chain_finding_count,
            },
            "cipher_suites": self._extra_evidence.get("cipher_suites", {}),
            "port_inventory": self._extra_evidence.get("port_inventory", {}),
        }
        scan_comparison: dict[str, Any] = {}
        if self.compare_report_path:
            try:
                from .scan_compare import compare_scan_findings, load_previous_report

                prev_rows, prev_meta = load_previous_report(self.compare_report_path)
                scan_comparison = compare_scan_findings(prev_rows, self.findings)
                scan_comparison["baseline_report_path"] = self.compare_report_path
                scan_comparison["baseline_meta"] = prev_meta
            except Exception as exc:
                scan_comparison = {
                    "error": str(exc),
                    "summary_line": "Scan comparison failed — could not load or parse baseline report.",
                }
        extra_data["scan_comparison"] = scan_comparison

        safe_extra_data = self._sanitize_for_report(extra_data)
        html_ok = False
        pdf_ok = False
        json_ok = False
        try:
            html_path = HTMLReporter(
                safe_target,
                safe_findings,
                safe_ai_data,
                output_dir=self.output_dir,
                extra_data=safe_extra_data,
            ).save()
            if html_path:
                html_ok = True
                logger.info("[OK] HTML report saved → %s", html_path)
        except Exception as e:
            logger.error(
                "[ERROR] Report generation failed: %s",
                e,
                extra={
                    "kind": ScanEventKind.REPORT_SAVE_FAILED,
                    "format": "html",
                    "error": str(e),
                },
            )
        try:
            pdf_path = PDFReporter(
                safe_target,
                safe_findings,
                safe_ai_data,
                output_dir=self.output_dir,
                extra_data=safe_extra_data,
            ).save()
            if pdf_path:
                pdf_ok = True
                logger.info("[OK] PDF report saved → %s", pdf_path)
        except Exception as e:
            logger.error(
                "[ERROR] Report generation failed: %s",
                e,
                extra={
                    "kind": ScanEventKind.REPORT_SAVE_FAILED,
                    "format": "pdf",
                    "error": str(e),
                },
            )
        try:
            json_path = Reporter(
                safe_target,
                safe_findings,
                "json",
                output_dir=self.output_dir,
                extra_data=safe_extra_data,
            ).save()
            if json_path:
                json_ok = True
                logger.info("[OK] JSON report saved → %s", json_path)
        except Exception as e:
            logger.error(
                "[ERROR] Report generation failed: %s",
                e,
                extra={
                    "kind": ScanEventKind.REPORT_SAVE_FAILED,
                    "format": "json",
                    "error": str(e),
                },
            )

        if self._sl:
            try:
                LogConverter(self._sl.path, self.output_dir).convert_to_json()
                logger.info("[OK] Events JSON export completed")
            except Exception as e:
                logger.error(
                    "[ERROR] Report generation failed: %s",
                    e,
                    extra={"kind": ScanEventKind.REPORT_SAVE_FAILED, "format": "events_json"},
                )

        def _report_status(ok: bool) -> str:
            return "OK" if ok else "FAILED"

        def _report_sym(ok: bool) -> str:
            return "✓" if ok else "✗"

        if html_ok and pdf_ok and json_ok:
            report_save_summary = (
                "Reports saved → "
                f"HTML {_report_sym(True)}, PDF {_report_sym(True)}, JSON {_report_sym(True)}"
            )
            report_save_summary_plain = (
                "Reports saved → HTML OK, PDF OK, JSON OK"
            )
        elif not html_ok and not pdf_ok and not json_ok:
            report_save_summary = "Report generation failed (no files created)"
            report_save_summary_plain = report_save_summary
        else:
            report_save_summary = (
                "Reports partially saved → "
                f"HTML {_report_sym(html_ok)}, PDF {_report_sym(pdf_ok)}, "
                f"JSON {_report_sym(json_ok)}"
            )
            report_save_summary_plain = (
                "Reports partially saved → "
                f"HTML: {_report_status(html_ok)}, "
                f"PDF: {_report_status(pdf_ok)}, "
                f"JSON: {_report_status(json_ok)}"
            )

        total_time = time.perf_counter() - self._start_time
        try:
            logger.success(
                "Scan and report generation finished",
                extra={
                    "kind": ScanEventKind.SCAN_COMPLETE,
                    "duration_s": total_time,
                    "scan_id": self.scan_id,
                    "report_save_summary": report_save_summary,
                    "report_save_summary_plain": report_save_summary_plain,
                    "report_output_dir": self.output_dir,
                },
            )
        except Exception as e:
            logger.error(
                "[ERROR] Report generation failed: %s",
                e,
                extra={
                    "kind": ScanEventKind.REPORT_SAVE_FAILED,
                    "phase": "scan_complete_log",
                },
            )
        paths = {"html": html_path, "pdf": pdf_path, "json": json_path}
        self._last_report_paths = paths  # used by scan-level final verification
        try:
            if self._sl:
                self._verify_output_artifacts(
                    paths,
                    jsonl_path=self._sl.path,
                    check_jsonl_events=False,
                )
        except Exception:
            # Validation must never stop the scan.
            pass
        return paths

    def _section(self, title: str) -> None:
        logger.info(
            "Scan phase boundary",
            extra={"kind": ScanEventKind.MODULE_START, "title": title},
        )

    def _timed_section(self, name: str, fn) -> None:
        self._section(name)
        mod_tok = observability.set_module_context(name)
        if self._sl:
            self._sl.log_phase_start(name)
        t0 = time.perf_counter()
        with self._lock:
            cnt0 = len(self.findings)
        self._metrics_begin_unit()
        failed_exc = False
        try:
            fn()
        except Exception as exc:
            failed_exc = True
            self._metrics_fail_unit()
            logger.warning(
                "Timed scan phase raised",
                extra={
                    "kind": ScanEventKind.MODULE_PHASE_ERROR,
                    "phase": name,
                    "error": str(exc),
                },
            )
            if self._sl:
                self._sl.log_error(str(exc), module=name)
        else:
            if self._module_step_failed:
                self._metrics_fail_unit()
            else:
                self._metrics_succeed_unit()
        dt = time.perf_counter() - t0
        with self._lock:
            cnt1 = len(self.findings)
        findings_delta = max(0, cnt1 - cnt0)
        status = (
            "failed" if failed_exc or self._module_step_failed else "success"
        )
        self._record_module_metric(name, dt, findings_delta, status)
        observability.reset_module_context(mod_tok)
        self._module_times[name] = round(dt, 2)
        if self._sl:
            with self._lock:
                cnt = len(self.findings)
            self._sl.log_phase_end(name, dt, cnt, status=status)
            self._sl.log_module_complete(
                name,
                duration_s=dt,
                findings_count=cnt,
                status=status,
            )
        logger.info(
            "Scan phase timing",
            extra={"kind": ScanEventKind.MODULE_PHASE_TIMER, "phase": name, "seconds": dt},
        )

    def _print_guard_summary(self, gs: dict) -> None:
        logger.info(
            "Guard summary header",
            extra={"kind": ScanEventKind.GUARD_SUMMARY_HEADER},
        )
        shown = gs.get("http_outbound_total", 0)
        if not shown:
            shown = gs.get("total_requests", 0)
        logger.info(
            "HTTP request total",
            extra={"kind": ScanEventKind.GUARD_SUMMARY_HTTP_TOTAL, "count": shown},
        )
        logger.info(
            "Budget state",
            extra={
                "kind": ScanEventKind.GUARD_SUMMARY_BUDGET,
                "exhausted": gs.get("budget_exhausted", False),
            },
        )
        for mod, stats in gs.get("modules", {}).items():
            ex = {
                "kind": ScanEventKind.GUARD_SUMMARY_MODULE,
                "module": mod,
                "requests": stats["requests"],
                "error_rate": stats["error_rate"],
                "tripped": stats["tripped"],
            }
            if stats["tripped"]:
                logger.warning("Module guard stats", extra=ex)
            else:
                logger.success("Module guard stats", extra=ex)
        logger.info(
            "Guard summary footer",
            extra={"kind": ScanEventKind.GUARD_SUMMARY_FOOTER},
        )
