"""
scanner/web/idor.py
===================
Heuristic IDOR (Insecure Direct Object Reference) detector.

Safety: This module is conservative and only flags *potential* IDOR based on
response differentials. It does not attempt authenticated exploitation.
"""

from __future__ import annotations

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

ID_PARAMS = {"id", "user", "user_id", "account", "account_id", "order", "order_id", "doc", "doc_id", "file", "file_id"}


from ..base_scanner import BaseScanner
from .base_module import ScanContext

class IDORScanner(BaseScanner):
    name = "idor"

    def __init__(self, urls: list[str], timeout: int = 10, proxy: str | None = None, session: object | None = None, **kwargs):
        super().__init__(urls, timeout=timeout, proxy=proxy, **kwargs)
        if session is not None:
            self.session = session

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self) -> list[dict]:
        parameterised = [u for u in self.urls if "?" in u]
        if not parameterised:
            return []
        logger.info(
            "  [*] IDOR heuristics on %s parameterised URL(s)",
            len(parameterised),
        )
        findings: list[dict] = []
        for url in parameterised[:120]:  # cap
            try:
                findings.extend(self._test_url(url))
            except Exception:
                continue
        # Dedup
        seen, out = set(), []
        for f in findings:
            key = (f.get("type",""), f.get("url",""), f.get("parameter",""))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _test_url(self, url: str) -> list[dict]:
        res: list[dict] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param, vals in params.items():
            if param.lower() not in ID_PARAMS:
                continue
            v = (vals[0] if vals else "").strip()
            if not v.isdigit():
                continue
            base_params = {k: (vv[0] if vv else "") for k, vv in params.items()}
            base_url = urlunparse(parsed._replace(query=urlencode(base_params)))
            try:
                b = self.session.get(base_url, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue

            # increment/decrement probe
            for new_v in (str(int(v) + 1), str(max(0, int(v) - 1))):
                test_params = dict(base_params)
                test_params[param] = new_v
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    t = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue

                # If status stays 200 and length stays very similar, could indicate accessible object
                if b.status_code == 200 and t.status_code == 200:
                    if abs(len(b.text) - len(t.text)) < max(120, int(len(b.text) * 0.02)):
                        res.append({
                            "type": "Potential IDOR (Heuristic)",
                            "url": base_url,
                            "parameter": param,
                            "payload": f"{param}={new_v}",
                            "severity": "LOW",
                            "evidence": f"ID-like parameter changed from {v} to {new_v} and response remained similar (200 + near-equal length). Verify authorization controls.",
                        })
                        break
        return res

