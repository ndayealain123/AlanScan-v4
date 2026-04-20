"""
scanner/thread_manager.py
=========================
Thread pool with throttling, retries, and threshold guarding.
Uses ThreadPoolExecutor(max_workers from config), per-domain token bucket,
config-driven floor delay, and 3-attempt retry for submitted work units.
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, Future, as_completed, TimeoutError
from typing import Any, Callable, List, Optional, Dict

try:
    import config
except ImportError:
    config = None  # type: ignore

from .scan_logger import logger

_POOL_WORKERS = getattr(config, "THREAD_POOL_MAX_WORKERS", 20) if config else 20
_THROTTLE_DELAY = float(getattr(config, "REQUEST_THROTTLE_DELAY_SEC", 0.05) if config else 0.05)
_RETRY_ATTEMPTS = int(getattr(config, "HTTP_RETRY_ATTEMPTS", 3) if config else 3)
_RETRY_BACKOFF = float(getattr(config, "HTTP_RETRY_BACKOFF_SEC", 0.35) if config else 0.35)


class ThresholdGuard:
    """
    Circuit-breaker + scan budget + finding caps.
    """

    def __init__(self, max_requests: int = 5000, error_threshold: float = 0.3):
        self.max_requests = max_requests
        self.error_threshold = error_threshold
        self.requests = 0
        self.errors = 0
        self.findings_by_severity: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._start_time = time.monotonic()

    def record_request(self, module: str = "generic", error: bool = False) -> bool:
        with self._lock:
            self.requests += 1
            if error:
                self.errors += 1
            if self.requests >= self.max_requests:
                return False
            if self.requests > 100:
                error_rate = self.errors / self.requests
                if error_rate > self.error_threshold:
                    return False
            return True

    def record_finding(self, severity: str) -> bool:
        severity = severity.upper()
        with self._lock:
            self.findings_by_severity[severity] = self.findings_by_severity.get(severity, 0) + 1
            return True

    def summary(self) -> dict:
        try:
            from .request_stats import get_http_request_total
            http_out = int(get_http_request_total())
        except Exception:
            http_out = 0
        with self._lock:
            elapsed = time.monotonic() - self._start_time
            error_rate = self.errors / max(1, self.requests)
            return {
                "total_requests": self.requests,
                "http_outbound_total": http_out,
                "total_errors": self.errors,
                "error_rate": round(error_rate, 3),
                "budget_exhausted": self.requests >= self.max_requests,
                "circuit_broken": (self.requests > 100 and error_rate > self.error_threshold),
                "findings": dict(self.findings_by_severity),
                "elapsed_s": round(elapsed, 2),
                "rps": round(self.requests / max(1, elapsed), 2),
                "modules": {},
            }


class RequestThrottler:
    """
    Per-domain token bucket + optional fixed floor delay from config (thread-safe).
    """

    def __init__(self, rate: float = 10.0, burst: float = 20.0,
                 min_delay_sec: float | None = None):
        self.rate = rate
        self.burst = burst
        self._min_delay = float(min_delay_sec if min_delay_sec is not None else _THROTTLE_DELAY)
        self._domains: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()

    def wait(self, domain: str) -> None:
        with self._lock:
            if domain not in self._domains:
                self._domains[domain] = {
                    "last_refill": time.monotonic(),
                    "tokens": float(self.burst),
                }
            d = self._domains[domain]
            now = time.monotonic()
            elapsed = now - d["last_refill"]
            d["tokens"] = min(self.burst, d["tokens"] + (elapsed * self.rate))
            d["last_refill"] = now
            if d["tokens"] < 1.0:
                wait_time = (1.0 - d["tokens"]) / self.rate
                time.sleep(wait_time)
                d["tokens"] = 0.0
                d["last_refill"] = time.monotonic()
            else:
                d["tokens"] -= 1.0
        if self._min_delay > 0:
            time.sleep(self._min_delay)

    def record_success(self, domain: str) -> None:
        pass


def _run_with_retries(fn: Callable[..., Any], args: tuple, kwargs: dict) -> Any:
    """Run callable with up to HTTP_RETRY_ATTEMPTS attempts (thread-safe per call)."""
    last_exc: Optional[BaseException] = None
    attempts = max(1, _RETRY_ATTEMPTS)
    for attempt in range(attempts):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(_RETRY_BACKOFF * (attempt + 1))
            logger.debug("thread_manager retry %s/%s after %s", attempt + 1, attempts, exc)
    if last_exc is not None:
        raise last_exc
    return None


class AdaptiveThreadPool:
    """
    Fixed-size pool (default 20 workers) with retry-wrapped submissions.
    """

    def __init__(self, workers: int, throttler: RequestThrottler, guard: ThresholdGuard):
        self.max_workers = max(1, min(int(workers or _POOL_WORKERS), _POOL_WORKERS))
        self.throttler = throttler
        self.guard = guard
        self._executor = ThreadPoolExecutor(max_workers=_POOL_WORKERS)
        self._futures: List[Future] = []
        self._submit_lock = threading.Lock()

    @property
    def current_workers(self) -> int:
        return _POOL_WORKERS

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        def _job() -> Any:
            return _run_with_retries(fn, args, kwargs)

        with self._submit_lock:
            future = self._executor.submit(_job)
            self._futures.append(future)
        return future

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


class SafeThreadPool:
    """
    Context-managed pool using the same max worker cap and retries.
    """

    def __init__(self, max_workers: int | None = None, task_timeout: int = 30):
        self.max_workers = max(1, min(int(max_workers or _POOL_WORKERS), _POOL_WORKERS))
        self.task_timeout = task_timeout
        self._executor: Optional[ThreadPoolExecutor] = None
        self._futures: List[Future] = []
        self._lock = threading.Lock()

    def __enter__(self) -> SafeThreadPool:
        self._executor = ThreadPoolExecutor(max_workers=_POOL_WORKERS)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.shutdown()

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        def _job() -> Any:
            return _run_with_retries(fn, args, kwargs)

        assert self._executor is not None
        future = self._executor.submit(_job)
        with self._lock:
            self._futures.append(future)
        return future

    def submit_many(self, fn: Callable, items: List, unpack: bool = True) -> List[Future]:
        futures = []
        for item in items:
            if unpack and isinstance(item, (tuple, list)):
                futures.append(self.submit(fn, *item))
            else:
                futures.append(self.submit(fn, item))
        return futures

    def harvest(self, futures: Optional[List[Future]] = None,
                timeout: Optional[float] = None) -> List[Any]:
        if futures is None:
            with self._lock:
                futures = list(self._futures)
        results: List[Any] = []
        if not futures:
            return results
        timeout = timeout or self.task_timeout
        start_time = time.monotonic()
        try:
            for future in as_completed(futures, timeout=timeout):
                try:
                    result = future.result(timeout=5)
                    if result is not None:
                        if isinstance(result, list):
                            results.extend(result)
                        else:
                            results.append(result)
                except TimeoutError:
                    logger.debug("Future timed out")
                except Exception as e:
                    logger.debug("Future exception: %s", e)
                if time.monotonic() - start_time > timeout:
                    logger.warning("Harvest timeout reached. Returning %s partial results.", len(results))
                    break
        except TimeoutError:
            abandoned = len([f for f in futures if not f.done()])
            logger.warning("Harvest timed out; %s future(s) abandoned.", abandoned)
        return results

    def shutdown(self, wait: bool = True) -> None:
        if self._executor:
            with self._lock:
                for future in self._futures:
                    if not future.done():
                        future.cancel()
            self._executor.shutdown(wait=wait, cancel_futures=True)
            self._executor = None


class RequestThrottle:
    """Legacy simple request throttler (thread-safe)."""

    def __init__(self, rate: float = 10.0):
        self.rate = rate
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            required_wait = (1.0 / self.rate) - elapsed
            if required_wait > 0:
                time.sleep(required_wait)
            self._last_request = time.time()
        if _THROTTLE_DELAY > 0:
            time.sleep(_THROTTLE_DELAY)
