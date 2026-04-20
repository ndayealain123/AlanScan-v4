"""
Global HTTP request counter — incremented by CountingHTTPAdapter in web/base.py.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_total_http_requests = 0


def record_http_request() -> None:
    global _total_http_requests
    with _lock:
        _total_http_requests += 1


def get_http_request_total() -> int:
    with _lock:
        return _total_http_requests


def reset_http_request_total() -> None:
    global _total_http_requests
    with _lock:
        _total_http_requests = 0
