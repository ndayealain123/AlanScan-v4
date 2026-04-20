"""
scanner/web/base.py
===================
Shared HTTP session factory used by every web scanner module.

Why a shared base?
  All web modules need identical retry logic, proxy settings, header defaults,
  and timeout configuration.  Centralising this avoids repetition and ensures
  a single change here applies everywhere.

Key Features
------------
- urllib3 adapter retries disabled (``total=0``); use
  ``scanner.web.http_retry.request_with_retries`` for 3 attempts with logging.
- Optional proxy injection via the ``proxy`` keyword.
- Consistent User-Agent so the tool appears as a real browser to WAFs.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import config


class CountingHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that increments global request stats on each outbound request."""

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        try:
            from ..request_stats import record_http_request
            record_http_request()
        except Exception:
            pass
        return super().send(
            request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies
        )


def normalize_url(url: str) -> str:
    """
    Standardize URL by removing trailing slash and fragments.
    Ensures 'host/' and 'host' are treated as the same URL.
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlparse, urlunparse, urldefrag
        # Remove fragments
        url, _ = urldefrag(url)
        p = urlparse(url)
        # Rebuild without fragment and rstrip slash from path
        path = p.path.rstrip("/")
        return urlunparse(p._replace(path=path, fragment=""))
    except Exception:
        return url.rstrip("/")

def make_session(proxy: str | None = None, timeout: int | None = None) -> requests.Session:
    """
    Build and return a configured requests.Session.

    Parameters
    ----------
    proxy : str | None
        Proxy URL, e.g. ``"http://127.0.0.1:8080"`` for Burp Suite intercept.
    timeout : int
        Default timeout stored on the session for callers to reference.

    Returns
    -------
    requests.Session
        Ready-to-use session with retry, proxy, and header defaults applied.
    """
    if timeout is None:
        timeout = int(getattr(config, "TIMEOUT", 15))

    session = requests.Session()

    # ── Retry Adapter ────────────────────────────────────────────────────────
    # Disabled here to avoid stacking with ``request_with_retries`` (single policy).
    retry_strategy = Retry(total=0)
    adapter = CountingHTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # ── Default Headers ───────────────────────────────────────────────────────
    session.headers.update(config.DEFAULT_HEADERS)

    # ── Proxy ─────────────────────────────────────────────────────────────────
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        # Disable SSL verification when routing through Burp / ZAP
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    # Attach timeout as a convenience attribute
    session.timeout = timeout

    return session
