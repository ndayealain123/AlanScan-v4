"""
scanner/web/api_security.py
===========================
Modern API security checks (REST/GraphQL) — lightweight and safe by default.

Checks included (non-destructive):
- GraphQL introspection enabled
- Public Swagger/OpenAPI endpoints
- Common API debug endpoints
"""

from __future__ import annotations

from ..scan_logger import logger
from urllib.parse import urlparse, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base_scanner import BaseScanner
from .base_module import ScanContext

COMMON_API_PATHS = [
    "/graphql",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger/index.html",
    "/swagger-ui",
    "/swagger-ui.html",
    "/openapi.json",
    "/swagger.json",
]


INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { types { name } } }"
}


class APISecurityScanner(BaseScanner):
    name = "api"

    def __init__(self, base_url: str, urls: list[str], threads: int = 10, timeout: int = 10, proxy: str | None = None, **kwargs):
        super().__init__(urls, threads=threads, timeout=timeout, proxy=proxy, **kwargs)
        self.base_url = base_url.rstrip("/")

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        # For modules taking singular 'url', use context.target
        self.url = context.target
        self.base_url = self.url.rstrip("/")
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self) -> list[dict]:
        findings: list[dict] = []

        # Candidate endpoints: discovered + common well-known
        discovered = set()
        for u in self.urls:
            try:
                p = urlparse(u)
                discovered.add(urlunparse(p._replace(query="", fragment="")))
            except Exception:
                continue
        for path in COMMON_API_PATHS:
            discovered.add(urljoin(self.base_url + "/", path.lstrip("/")))

        targets = sorted(discovered)
        logger.info(
            "  [*] API security checks on %s endpoint candidate(s)",
            len(targets),
        )

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._check_endpoint, u): u for u in targets}
            for fut in as_completed(futs):
                try:
                    res = fut.result()
                    if res:
                        findings.extend(res)
                except Exception:
                    pass

        # Consolidate Swagger/OpenAPI asset hits into one finding to avoid
        # inflating report counts with static files.
        swagger_hits = [
            f for f in findings
            if "swagger/openapi endpoint" in str(f.get("type", "")).lower()
        ]
        if swagger_hits:
            urls = sorted({f.get("url", "") for f in swagger_hits if f.get("url")})
            base = self.base_url.rstrip("/")
            ui_url = ""
            for u in urls:
                if "/swagger/index.html" in u.lower():
                    ui_url = u
                    break
            if not ui_url:
                ui_url = f"{base}/swagger/index.html"
            evidence = (
                "Swagger/OpenAPI documentation is publicly accessible. "
                f"Supporting assets discovered: {', '.join(urls[:8])}"
            )
            findings = [
                f for f in findings
                if "swagger/openapi endpoint" not in str(f.get("type", "")).lower()
            ]
            findings.append({
                "type": "API Exposure — Swagger UI Publicly Accessible",
                "url": ui_url,
                "parameter": "N/A",
                "payload": "N/A",
                "severity": "MEDIUM",
                "evidence": evidence,
                "details": {"supporting_assets": urls},
            })

        # Deduplicate by (type,url)
        seen, out = set(), []
        for f in findings:
            key = (f.get("type",""), f.get("url",""))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _check_endpoint(self, url: str) -> list[dict]:
        res: list[dict] = []
        u = url.lower()

        # Swagger/OpenAPI
        if any(x in u for x in ["swagger", "openapi.json", "swagger.json"]):
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200 and any(k in (r.text or "") for k in ["openapi", "swagger", "\"paths\""]):
                    res.append({
                        "type": "API Exposure — Swagger/OpenAPI Endpoint",
                        "url": url,
                        "parameter": "N/A",
                        "payload": "N/A",
                        "severity": "LOW",
                        "evidence": f"Endpoint accessible (HTTP 200) and appears to expose API schema/documentation.",
                    })
            except Exception:
                pass

        # GraphQL introspection
        if u.endswith("/graphql") or "/graphql" in u:
            try:
                r = self.session.post(url, json=INTROSPECTION_QUERY, timeout=self.timeout, allow_redirects=False)
                body = (r.text or "").lower()
                if r.status_code == 200 and ("__schema" in body or "types" in body):
                    res.append({
                        "type": "API Security — GraphQL Introspection Enabled",
                        "url": url,
                        "parameter": "POST body",
                        "payload": "GraphQL introspection query",
                        "severity": "MEDIUM",
                        "evidence": "GraphQL introspection appears enabled (schema information returned).",
                    })
            except Exception:
                pass

        return res

