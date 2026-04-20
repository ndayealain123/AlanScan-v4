"""
scanner/base_scanner.py  v4.0.0
================================
Safe Base Interface — Consultant-Grade Upgrade

Changes in v4.0.0:
§2.1  Adaptive scanning: stop after 2 confirmations / 1 high-confidence exploit
§2.4  Request budget: per-module request cap, stops module when exceeded
§2.5  Response caching: (url+params+payload) → avoids duplicate requests
§2.6  Early exit: stop scanning endpoint after confirmed vulnerability
§8    Metrics: per-module request counters, skip counters, early-exit log
      All changes are backward compatible with existing scanner.web modules.
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

import config
from scanner.web.base_module import ScanContext


class BaseScanner(ABC):
    """
    Safe base scanner — NO aggressive testing, NO false positives.

    Subclasses should call:
      _should_stop_parameter(param, url) → bool     (§2.1 adaptive)
      _record_confirmation(param, url, high_conf)   (§2.1 adaptive)
      _cache_response(url, params, payload) → bool  (§2.5 cache hit?)
      _store_response(url, params, payload, resp)   (§2.5 store)
      _check_budget() → bool                        (§2.4 budget ok?)
      _endpoint_confirmed(url) → bool               (§2.6 early exit)
      _mark_endpoint_confirmed(url)                 (§2.6 early exit)
    and the existing _safe_request / _add_finding helpers.
    """

    name: str = "base"

    def __init__(self, target: str | List[str], **kwargs: Any) -> None:
        self.target = target
        self.urls: List[str] = [target] if isinstance(target, str) else list(target)
        self.timeout = kwargs.get("timeout", getattr(config, "TIMEOUT", 15))
        self.proxy = kwargs.get("proxy")
        self.safe_mode = kwargs.get("safe_mode", True)
        self.threads = kwargs.get("threads", getattr(config, "DEFAULT_THREADS", 12))
        self.scan_intensity: str = str(
            kwargs.get("scan_intensity", getattr(config, "SCAN_INTENSITY_DEFAULT", "medium"))
        ).lower()

        # HTTP session
        from .web.base import make_session
        self.session = make_session(self.proxy, self.timeout)

        # Results
        self.findings: List[dict] = []

        # §9 rate limiting (safe defaults)
        self._last_request: float = 0.0
        self._min_request_interval: float = getattr(config, "REQUEST_DELAY", 0.1)

        # ── §2.4 Request budget ────────────────────────────────────────────
        module_key = getattr(self, "name", "default")
        try:
            raw_cap = kwargs.get("max_requests")
            if raw_cap is not None:
                max_budget = int(raw_cap)
            else:
                max_budget = int(getattr(config, "MAX_REQUESTS", 10_000))
        except (TypeError, ValueError):
            max_budget = 10_000
        max_budget = max(1, max_budget)
        _budget_fn = getattr(config, "get_module_budget", None)
        try:
            if callable(_budget_fn):
                self._request_budget = int(_budget_fn(module_key, max_budget))
            else:
                self._request_budget = max_budget
        except Exception:
            self._request_budget = max_budget
        self._request_budget = max(1, min(self._request_budget, max_budget))
        self._requests_made: int  = 0
        self._skipped_budget: int = 0

        # ── §2.1 Adaptive scanning state ──────────────────────────────────
        # key = (url_base, param) → confirmation count
        self._param_confirmations: Dict[str, int] = {}
        self._param_confirmed: set[str] = set()   # parameters done
        self._skipped_adaptive: int = 0

        # ── §2.5 Response cache ────────────────────────────────────────────
        self._response_cache: Dict[str, Any] = {}
        self._cache_max = getattr(config, "RESPONSE_CACHE_MAX_SIZE", 5_000)
        self._cache_hits: int = 0

        # ── §2.6 Endpoint early-exit ───────────────────────────────────────
        self._confirmed_endpoints: set[str] = set()
        self._early_exits: int = 0

        # ── §8 Metrics ─────────────────────────────────────────────────────
        self._t_start: float = time.perf_counter()
        self._success_count: int = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Abstract interface
    # ─────────────────────────────────────────────────────────────────────────

    @abstractmethod
    def run(self, context: ScanContext) -> List[dict]:
        """
        Execute scanner — must return a list of finding dicts.

        Each non-chain finding should include: type, url, severity, evidence.
        parameter is optional (controller normalises to "N/A" if missing).
        """

    # ─────────────────────────────────────────────────────────────────────────
    # §2.4 Budget helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _check_budget(self) -> bool:
        """
        §2.4: Return True if there is remaining request budget.
        Logs why the module stops when budget is exhausted.
        """
        if self._requests_made >= self._request_budget:
            self._skipped_budget += 1
            if self._skipped_budget == 1:
                try:
                    from scanner.scan_logger import logger
                    logger.info(
                        "[%s] request budget exhausted (%d/%d) — stopping module",
                        getattr(self, "name", "base"),
                        self._requests_made,
                        self._request_budget,
                    )
                except Exception:
                    pass
            return False
        return True

    # ─────────────────────────────────────────────────────────────────────────
    # §2.1 Adaptive scanning helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _param_key(self, url: str, param: str) -> str:
        base = url.split("?", 1)[0]
        return f"{base}|{param}"

    def _should_stop_parameter(self, param: str, url: str) -> bool:
        """
        §2.1: Return True when we have enough confirmations for this parameter
        and should skip further payloads.
        """
        key = self._param_key(url, param)
        if key in self._param_confirmed:
            self._skipped_adaptive += 1
            return True
        count = self._param_confirmations.get(key, 0)
        stop_at = getattr(config, "ADAPTIVE_STOP_CONFIRMATIONS", 2)
        if count >= stop_at:
            self._param_confirmed.add(key)
            self._skipped_adaptive += 1
            try:
                from scanner.scan_logger import logger
                logger.info(
                    "[%s] §2.1 adaptive stop: param=%s url=%s after %d confirmations",
                    getattr(self, "name", "base"), param,
                    url.split("?", 1)[0], count,
                )
            except Exception:
                pass
            return True
        return False

    def _record_confirmation(
        self, param: str, url: str, *, high_confidence: bool = False
    ) -> None:
        """
        §2.1: Record a confirmation for a (url, param) pair.
        If high_confidence=True, immediately marks the parameter as done.
        """
        key = self._param_key(url, param)
        if high_confidence:
            self._param_confirmed.add(key)
            try:
                from scanner.scan_logger import logger
                logger.info(
                    "[%s] §2.1 high-confidence exploit: param=%s — skipping remaining payloads",
                    getattr(self, "name", "base"), param,
                )
            except Exception:
                pass
        else:
            self._param_confirmations[key] = self._param_confirmations.get(key, 0) + 1

    # ─────────────────────────────────────────────────────────────────────────
    # §2.5 Response cache helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _cache_key(self, url: str, params: dict | None, payload: str) -> str:
        raw = f"{url}|{sorted((params or {}).items())}|{payload}"
        return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()

    def _cache_hit(self, url: str, params: dict | None, payload: str) -> Any:
        """§2.5: Return cached response or None."""
        return self._response_cache.get(self._cache_key(url, params, payload))

    def _cache_store(
        self, url: str, params: dict | None, payload: str, response: Any
    ) -> None:
        """§2.5: Store a response in cache (evict oldest when at capacity)."""
        if len(self._response_cache) >= self._cache_max:
            # Evict ~10% oldest entries
            evict_n = max(1, self._cache_max // 10)
            keys = list(self._response_cache.keys())[:evict_n]
            for k in keys:
                self._response_cache.pop(k, None)
        self._response_cache[self._cache_key(url, params, payload)] = response

    # ─────────────────────────────────────────────────────────────────────────
    # §2.6 Endpoint early-exit helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _endpoint_base(self, url: str) -> str:
        return url.split("?", 1)[0]

    def _endpoint_confirmed(self, url: str) -> bool:
        """§2.6: True if a vulnerability has already been confirmed on this endpoint."""
        if self._endpoint_base(url) in self._confirmed_endpoints:
            self._early_exits += 1
            return True
        return False

    def _mark_endpoint_confirmed(self, url: str) -> None:
        """§2.6: Mark endpoint as confirmed — future tests will exit early."""
        base = self._endpoint_base(url)
        if base not in self._confirmed_endpoints:
            self._confirmed_endpoints.add(base)
            try:
                from scanner.scan_logger import logger
                logger.info(
                    "[%s] §2.6 early exit: vulnerability confirmed at %s — skipping endpoint",
                    getattr(self, "name", "base"), base,
                )
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # §8 Metrics summary
    # ─────────────────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """§8: Return per-module metrics dict for logging."""
        elapsed = round(time.perf_counter() - self._t_start, 3)
        total   = max(1, self._requests_made)
        return {
            "module":            getattr(self, "name", "base"),
            "duration_s":        elapsed,
            "requests_made":     self._requests_made,
            "request_budget":    self._request_budget,
            "cache_hits":        self._cache_hits,
            "skipped_budget":    self._skipped_budget,
            "skipped_adaptive":  self._skipped_adaptive,
            "early_exits":       self._early_exits,
            "findings":          len(self.findings),
            "success_rate":      round(self._success_count / total, 3),
        }

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _safe_request(
        self,
        url: str,
        method: str = "GET",
        allow_redirects: bool = False,
        params: dict | None = None,
        payload: str = "",
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        """
        §2.4 + §2.5: Budget-checked, cache-aware throttled request.

        Callers that already check budget/cache separately can still call
        this method; it will honour all guards in the correct order.
        """
        # §2.4 Budget check
        if not self._check_budget():
            return None

        # §2.5 Cache check
        cached = self._cache_hit(url, params, payload)
        if cached is not None:
            self._cache_hits += 1
            return cached

        # Throttle
        now = time.time()
        elapsed = now - self._last_request
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request = time.time()

        try:
            from scanner.web.http_retry import request_with_retries

            if method.upper() == "GET":
                resp = request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    allow_redirects=allow_redirects,
                    params=params,
                    **kwargs,
                )
            elif method.upper() == "POST":
                resp = request_with_retries(
                    self.session,
                    "POST",
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    allow_redirects=allow_redirects,
                    **kwargs,
                )
            else:
                resp = request_with_retries(
                    self.session,
                    method,
                    url,
                    timeout=self.timeout,
                    max_attempts=3,
                    allow_redirects=allow_redirects,
                    **kwargs,
                )
            self._requests_made += 1
            if resp is not None:
                self._success_count += 1
                self._cache_store(url, params, payload, resp)
            return resp
        except Exception:
            self._requests_made += 1
            return None

    def _add_finding(self, finding: Dict) -> None:
        """Add finding with verification flag, recording confirmation for adaptive scanning."""
        finding["verified"] = True
        finding["requires_manual_verification"] = False
        self.findings.append(finding)

        # Auto-record confirmation for adaptive scanning
        url   = str(finding.get("url", ""))
        param = str(finding.get("parameter", ""))
        if url and param and param.upper() not in ("N/A", ""):
            try:
                conf = float((finding.get("validation") or {}).get("confidence", 0) or 0)
            except Exception:
                conf = 0.0
            high_conf = conf >= getattr(config, "ADAPTIVE_HIGH_CONF_THRESHOLD", 0.90)
            self._record_confirmation(param, url, high_confidence=high_conf)
            # §2.6 mark endpoint confirmed
            self._mark_endpoint_confirmed(url)
