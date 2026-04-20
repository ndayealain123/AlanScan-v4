"""
Application-level HTTP retries shared by crawler, scanners, and refetch logic.

Retries up to ``max_attempts`` times on socket timeouts, connection errors,
and HTTP 429 / 5xx. urllib3 adapter retries are disabled in ``make_session`` so
this layer is the single policy (with visible retry / failure logs).
"""

from __future__ import annotations

import random
import time
from typing import Any

import requests

import config
from ..events import ScanEventKind
from ..scan_logger import logger

RETRYABLE_HTTP_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 0.35
_BACKOFF_MAX = 8.0

_RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    requests.Timeout,
    requests.ConnectionError,
    OSError,
    requests.exceptions.ChunkedEncodingError,
    requests.exceptions.ContentDecodingError,
)


def _sleep_before_retry(attempt_index: int, response: requests.Response | None) -> None:
    if response is not None:
        ra = response.headers.get("Retry-After")
        if ra:
            try:
                time.sleep(min(_BACKOFF_MAX, float(ra)))
                return
            except (TypeError, ValueError):
                pass
    delay = min(
        _BACKOFF_MAX,
        _BACKOFF_BASE * (2**attempt_index) + random.uniform(0, 0.12),
    )
    time.sleep(delay)


def touch_response_metadata(resp: requests.Response | None) -> None:
    """
    Force consumption of ``response.headers`` and ``response.cookies`` so
    underlying adapters complete parsing (helps header/cookie audits).
    """
    if resp is None:
        return
    try:
        list(resp.headers.items())
    except Exception:
        pass
    try:
        list(resp.cookies)
    except Exception:
        pass


def request_with_retries(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: float | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    **kwargs: Any,
) -> requests.Response | None:
    """
    Perform ``method`` request with retries.

    Logs each failed attempt (reason + URL), backoff, then a final
    ``[HTTP_FAIL]`` if all attempts are exhausted. Does not fail silently.
    """
    if max_attempts < 1:
        logger.error(
            "  [HTTP_FAIL] %s %s — max_attempts must be >= 1 (got %s)",
            method.upper(),
            str(url)[:512],
            max_attempts,
        )
        return None
    if not url:
        logger.error(
            "  [HTTP_FAIL] empty URL for %s",
            method.upper(),
            extra={"kind": ScanEventKind.HTTP_RETRIES_EXHAUSTED},
        )
        return None
    if timeout is None:
        timeout = float(
            getattr(session, "timeout", None) or getattr(config, "TIMEOUT", 15),
        )
    url_display = str(url)[:512]
    last_resp: requests.Response | None = None
    last_exc: BaseException | None = None
    last_status: int | None = None
    m = method.upper()

    for attempt in range(1, max_attempts + 1):
        try:
            resp = session.request(
                m,
                url,
                timeout=timeout,
                **kwargs,
            )
            last_resp = resp
            last_exc = None
            last_status = resp.status_code
            if resp.status_code not in RETRYABLE_HTTP_STATUS:
                if attempt > 1:
                    logger.info(
                        "  [RETRY] %s %s succeeded on attempt %s/%s (HTTP %s)",
                        m,
                        url_display,
                        attempt,
                        max_attempts,
                        resp.status_code,
                    )
                return resp
            if attempt >= max_attempts:
                logger.error(
                    "  [HTTP_FAIL] %s %s — giving up after %s attempts "
                    "(last HTTP %s; retryable status)",
                    m,
                    url_display,
                    max_attempts,
                    resp.status_code,
                    extra={
                        "kind": ScanEventKind.HTTP_RETRIES_EXHAUSTED,
                        "method": m,
                        "url": url_display,
                        "attempts": max_attempts,
                        "last_status": resp.status_code,
                    },
                )
                touch_response_metadata(resp)
                return resp
            logger.warning(
                "  [RETRY] %s %s attempt %s/%s got HTTP %s — backing off",
                m,
                url_display,
                attempt,
                max_attempts,
                resp.status_code,
            )
            _sleep_before_retry(attempt - 1, resp)
        except _RETRYABLE_EXCEPTIONS as exc:
            last_resp = None
            last_exc = exc
            last_status = None
            if attempt >= max_attempts:
                logger.error(
                    "  [HTTP_FAIL] %s %s — %s attempts exhausted: %s: %s",
                    m,
                    url_display,
                    max_attempts,
                    type(exc).__name__,
                    exc,
                    extra={
                        "kind": ScanEventKind.HTTP_RETRIES_EXHAUSTED,
                        "method": m,
                        "url": url_display,
                        "attempts": max_attempts,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                )
                return None
            logger.warning(
                "  [RETRY] %s %s attempt %s/%s failed: %s: %s",
                m,
                url_display,
                attempt,
                max_attempts,
                type(exc).__name__,
                exc,
            )
            _sleep_before_retry(attempt - 1, None)
        except Exception as exc:
            last_exc = exc
            logger.error(
                "  [HTTP_FAIL] %s %s — non-retryable error on attempt %s/%s: %s: %s",
                m,
                url_display,
                attempt,
                max_attempts,
                type(exc).__name__,
                exc,
                extra={
                    "kind": ScanEventKind.HTTP_RETRIES_EXHAUSTED,
                    "method": m,
                    "url": url_display,
                    "attempts": attempt,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            raise

    return None
