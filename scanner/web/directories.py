"""
scanner/web/directories.py
==========================
Hidden Directory and Sensitive File Discovery.

Purpose
-------
Many web applications inadvertently expose administrative panels, backup files,
source code archives, and configuration files in predictable locations.
This module brute-forces a curated wordlist of paths and reports candidates only
after **response validation** — not on HTTP 200 alone.

Detection Logic
---------------
- **Baseline**: Fetches the real homepage (follow redirects) plus a random
  non-existent path. Response bodies are normalized and compared using content
  similarity (``difflib``), not only status codes or lengths.
- **Generic SPA / catch-all**: If a probe matches the homepage (or a 200
  ``noop`` probe) within a similarity threshold, it is treated as a false
  positive unless directory-listing markers or sensitive-body fingerprints
  apply.
- **Sensitive fingerprints**: Paths like ``.git`` / ``.env`` require corroborating
  body content (e.g. ``ref: refs/``, ``KEY=value`` lines) when the shell would
  otherwise match the SPA baseline.
- HTTP 403/401/500 and validated redirects are likewise filtered when the body
  is indistinguishable from the generic baseline.

Concurrency
-----------
Uses a ThreadPoolExecutor for parallel requests, dramatically reducing the
time needed to check a large wordlist.
"""

from __future__ import annotations

import random
import re
import string
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlunparse

from ..scan_logger import logger
from ..base_scanner import BaseScanner
from .base_module import ScanContext
import config

# Paths that are always CRITICAL if found
CRITICAL_PATHS = {
    ".git",
    ".env",
    ".htpasswd",
    "config.php",
    "wp-config.php",
    "database.yml",
    "settings.py",
    "application.properties",
    "web.config",
    "appsettings.json",
    "backup",
    "backups",
    "phpinfo.php",
    "server-status",
    "console",
}

_BASELINE_BODY_MAX = 200_000
_COMPARE_NORM_MAX = 120_000
_CONTENT_QUICK_RATIO_THRESHOLD = 0.93


def _directory_listing_evidence(body: str) -> bool:
    """True when body looks like an auto-generated directory index, not a generic app page."""
    b = (body or "").lower()
    return any(
        sig in b
        for sig in (
            "index of /",
            "index of ",
            "<title>index of ",
            "parent directory",
            "directory listing for ",
            "folder listing",
            "[to parent directory]",
            "web server directory listing",
        )
    )


class DirectoryScanner(BaseScanner):
    """
    Threaded directory and file brute-force scanner.

    Parameters
    ----------
    base_url : str
        Target base URL (no trailing slash needed).
    threads : int
        Parallel request workers.
    timeout : int
        Per-request timeout.
    proxy : str | None
        Optional proxy.
    """

    name = "dirs"

    def __init__(
        self,
        base_url: str,
        threads: int = 10,
        timeout: int = 10,
        proxy: str | None = None,
        **kwargs,
    ):
        bu = base_url.rstrip("/")
        super().__init__(bu, threads=threads, timeout=timeout, proxy=proxy, **kwargs)
        self.base_url = bu
        self._baseline: dict | None = None  # set in scan()

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        self.url = context.target
        self.base_url = self.url.rstrip("/")
        self.session = context.unified_session
        return self.scan()

    @staticmethod
    def _normalize_body_for_compare(text: str) -> str:
        t = text or ""
        t = re.sub(r"\s+", " ", t.strip())
        return t[:_COMPARE_NORM_MAX]

    @staticmethod
    def _spa_shell_score(body: str) -> int:
        """Heuristic score for single-page-app shells (high → likely generic router)."""
        b = (body or "")[:100_000].lower()
        if not b:
            return 0
        score = 0
        markers = (
            'id="root"',
            "id='root'",
            'id="app"',
            'id="__next"',
            'id="app-root"',
            "ng-version=",
            'data-reactroot',
            "react refresh",
            "__next_f.push",
            "vite-plugin",
            "webpackjsonp",
            '<noscript>you need to enable javascript',
            "<title>loading</title>",
        )
        for m in markers:
            if m in b:
                score += 1
        if b.count("<script") >= 3 and "<div" in b:
            score += 1
        return score

    @staticmethod
    def _is_likely_spa_shell(body: str) -> bool:
        return DirectoryScanner._spa_shell_score(body) >= 3

    @staticmethod
    def _sensitive_body_evidence(clean_path: str, body: str) -> bool:
        """
        True when body content strongly suggests a real leak for this path
        (not the same HTML shell as '/').
        """
        if not body or not clean_path:
            return False
        p = clean_path.strip("/").lower()
        bl = body.lower()

        if ".git" in p:
            return (
                "ref: refs/" in body
                or "repositoryformatversion" in bl
                or "\n[core]" in body
                or "[core]\n" in body
            )

        if p == ".env" or p.endswith("/.env") or ".env" in p:
            return bool(
                re.search(
                    r"(?m)^[A-Za-z_][A-Za-z0-9_]{0,48}=[^\r\n]+$",
                    body,
                )
            )

        if "wp-config" in p:
            return "db_name" in bl or "db_password" in bl or "define(" in body

        if "phpinfo" in p:
            return "php version" in bl or "phpinfo()" in bl

        if "server-status" in p or p == "server-status":
            return "server uptime" in bl or "apache server status" in bl or "server version" in bl

        return False

    @classmethod
    def _compare_to_baseline_norm(
        cls,
        baseline_norm: str,
        body: str,
    ) -> tuple[bool, float]:
        """
        Return (is_generic_duplicate, quick_ratio).
        Duplicate ≈ normalized bodies align above CONTENT_QUICK_RATIO_THRESHOLD.
        """
        if not baseline_norm:
            return False, 0.0
        norm = cls._normalize_body_for_compare(body[:_BASELINE_BODY_MAX])
        ratio = SequenceMatcher(None, baseline_norm, norm).quick_ratio()
        return ratio >= _CONTENT_QUICK_RATIO_THRESHOLD, ratio

    def _is_generic_duplicate_response(self, body: str) -> tuple[bool, str, float]:
        """
        True if body matches the homepage baseline or a 200 noop probe closely enough
        to treat as the same SPA / catch-all page.
        """
        b = self._baseline or {}
        best_r = 0.0

        hn = b.get("homepage_norm") or ""
        if hn:
            _, r = self._compare_to_baseline_norm(hn, body)
            best_r = max(best_r, r)
            if r >= _CONTENT_QUICK_RATIO_THRESHOLD:
                return True, "homepage", r
            if (
                r >= 0.88
                and b.get("homepage_spa_likely")
                and self._is_likely_spa_shell(body)
            ):
                return True, "homepage_spa_borderline", r

        noop_st = int(b.get("noop_status", 0) or 0)
        if noop_st == 200:
            nn = b.get("noop_norm") or ""
            if nn:
                _, r2 = self._compare_to_baseline_norm(nn, body)
                best_r = max(best_r, r2)
                if r2 >= _CONTENT_QUICK_RATIO_THRESHOLD:
                    return True, "noop_200_probe", r2

        return False, "", best_r

    def _baseline_for_finding(self) -> dict:
        """Strip large norm strings from embedded baseline metadata."""
        b = self._baseline or {}
        out: dict = {}
        for k, v in b.items():
            if k.endswith("_norm"):
                continue
            out[k] = v
        out["content_threshold_quick_ratio"] = _CONTENT_QUICK_RATIO_THRESHOLD
        return out

    def scan(self) -> list[dict]:
        """
        Run the directory bruteforce scan.

        Returns
        -------
        list[dict]
            Findings for every reachable sensitive path discovered.
        """
        findings: list[dict] = []
        logger.info("  [*] Checking %s paths", len(config.DIR_WORDLIST))

        self._baseline = self._build_baseline()
        if self._baseline.get("homepage_norm"):
            logger.info(
                "  [*] Directory baseline: homepage HTTP %s len=%s spa_likely=%s",
                self._baseline.get("homepage_status"),
                self._baseline.get("homepage_len"),
                self._baseline.get("homepage_spa_likely"),
            )
        else:
            logger.warning(
                "  [!] Directory scan: weak homepage baseline — content comparison limited",
            )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_path, path): path
                for path in config.DIR_WORDLIST
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        seen: set[tuple] = set()
        deduped: list[dict] = []
        for fi in findings:
            try:
                from urllib.parse import urlparse as _up

                base = _up(fi.get("url", "")).path
            except Exception:
                base = fi.get("url", "")
            key = (fi.get("url", ""), fi.get("parameter", ""), fi.get("type", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(fi)
        return deduped

    def _check_path(self, path: str) -> dict | None:
        url = urljoin(self.base_url + "/", path)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            status = int(getattr(resp, "status_code", 0) or 0)
            body = getattr(resp, "text", "") or ""
            resp_len = len(body)
            location = (
                (resp.headers.get("Location", "") if hasattr(resp, "headers") else "")
                or ""
            )

            severity, note, extra = self._classify(
                path, status, url, resp_len, location, body
            )
            if severity is None:
                return None

            logger.warning("  [%s] %s → %s  %s", severity, status, url, note)

            return {
                "type": "Exposed Path / File",
                "url": url,
                "parameter": "path",
                "payload": path,
                "severity": severity,
                "evidence": f"HTTP {status} – {note}",
                "http": {
                    "status": status,
                    "redirect_location": location,
                    "response_len": resp_len,
                    "baseline": self._baseline_for_finding(),
                    **(extra or {}),
                },
            }

        except Exception as exc:
            logger.warning(
                "  [!] Directory probe failed for %s: %s",
                url,
                exc,
            )
            return None

    def _classify(
        self,
        path: str,
        status: int,
        url: str,
        resp_len: int,
        location: str,
        body: str,
    ) -> tuple[str | None, str, dict]:
        clean = path.strip("/").lower()
        extra: dict = {}

        def _dup_check() -> tuple[bool, str, float]:
            return self._is_generic_duplicate_response(body)

        # ── HTTP 200 ──────────────────────────────────────────────────────
        if status == 200:
            if _directory_listing_evidence(body):
                return (
                    "HIGH",
                    "Directory listing or index page exposed (validated by body markers)",
                    extra,
                )

            if self._sensitive_body_evidence(clean, body):
                sev = "CRITICAL" if clean in CRITICAL_PATHS else "HIGH"
                return (
                    sev,
                    "Sensitive path: body matches leak signatures (not generic SPA baseline)",
                    extra,
                )

            dup, dup_src, sim_r = _dup_check()
            if dup:
                extra["content_matches_baseline"] = dup_src
                extra["content_similarity_quick_ratio"] = round(sim_r, 4)
                return (
                    None,
                    "",
                    extra,
                )

            if self._baseline and self._is_soft_404_like(resp_len):
                if clean not in CRITICAL_PATHS:
                    extra["soft_404_suspected"] = True
                    return None, "", extra

            if clean in CRITICAL_PATHS:
                return (
                    "CRITICAL",
                    "Sensitive path: HTTP 200 with body differing from homepage baseline",
                    extra,
                )

            return (
                "LOW",
                "HTTP 200 — body differs from homepage baseline (not treated as generic SPA shell)",
                extra,
            )

        # ── 401 / 403: ignore if same shell as homepage (no path-specific signal)
        if status in (401, 403):
            dup, dup_src, sim_r = _dup_check()
            if dup and not self._sensitive_body_evidence(clean, body):
                extra["content_matches_baseline"] = dup_src
                extra["content_similarity_quick_ratio"] = round(sim_r, 4)
                return None, "", extra

            if clean in CRITICAL_PATHS:
                return (
                    "HIGH",
                    f"HTTP {status} – path exists but access is restricted",
                    extra,
                )
            return "LOW", f"HTTP {status} – path exists (access restricted)", extra

        # ── Redirects ─────────────────────────────────────────────────────
        if status in (301, 302, 307, 308):
            if status == 302:
                return None, "", extra

            extra["redirect_location"] = location
            validated = self._validate_redirect(url, location)
            extra["redirect_validated"] = bool(validated.get("validated"))
            extra["redirect_final_url"] = validated.get("final_url", "")
            extra["redirect_final_status"] = validated.get("final_status", None)
            extra["redirect_final_len"] = validated.get("final_len", None)
            extra["redirect_reason"] = validated.get("reason", "")

            if not validated.get("validated"):
                return None, "", extra

            final_status = int(validated.get("final_status") or 0)
            if final_status == 200:
                if clean in CRITICAL_PATHS:
                    return (
                        "CRITICAL",
                        "Redirect validated → sensitive resource accessible",
                        extra,
                    )
                return "HIGH", "Redirect validated → resource accessible", extra
            if final_status in (401, 403):
                if clean in CRITICAL_PATHS:
                    return (
                        "HIGH",
                        f"Redirect validated → HTTP {final_status} (restricted) but resource exists",
                        extra,
                    )
                return (
                    "MEDIUM",
                    f"Redirect validated → HTTP {final_status} (restricted) but resource exists",
                    extra,
                )

            return None, "", extra

        if status == 500:
            dup, _, sim_r = _dup_check()
            if dup:
                extra["content_similarity_quick_ratio"] = round(sim_r, 4)
                return None, "", extra
            return (
                "LOW",
                "Internal Server Error – path may have triggered backend logic",
                extra,
            )

        return None, "", extra

    def _is_soft_404_like(self, resp_len: int) -> bool:
        """Length aligned with noop probe (same status) suggests soft-404."""
        if not self._baseline:
            return False
        base_len = int(self._baseline.get("noop_len", -1) or -1)
        if base_len < 0:
            return False
        return abs(resp_len - base_len) <= max(120, int(base_len * 0.02))

    def _validate_redirect(self, original_url: str, location: str) -> dict:
        """Validate redirects; reject targets that match the generic baseline."""
        if not location:
            return {"validated": False, "reason": "Empty Location header"}

        try:
            orig = urlparse(original_url)
            if isinstance(location, str) and location.startswith(("http://", "https://")):
                target = location
            else:
                loc_str = str(location)
                path_part = loc_str if loc_str.startswith("/") else (orig.path.rstrip("/") + "/" + loc_str)
                target = urlunparse(orig._replace(path=path_part, query="", fragment=""))

            r = self.session.get(target, timeout=self.timeout, allow_redirects=False)
            final_status = int(getattr(r, "status_code", 0) or 0)
            final_text = getattr(r, "text", "") or ""
            final_len = len(final_text)

            dup, dup_src, sim_r = self._is_generic_duplicate_response(final_text)
            if dup:
                return {
                    "validated": False,
                    "reason": (
                        "Redirect target matches homepage/SPA baseline "
                        f"({dup_src}, quick_ratio≈{sim_r:.3f})"
                    ),
                    "final_url": target,
                    "final_status": final_status,
                    "final_len": final_len,
                }

            if self._baseline and final_status == int(
                self._baseline.get("noop_status", -1)
            ) and self._is_soft_404_like(final_len):
                return {
                    "validated": False,
                    "reason": "Redirect target matches noop probe (soft-404 suspected)",
                    "final_url": target,
                    "final_status": final_status,
                    "final_len": final_len,
                }

            if final_status in (200, 401, 403):
                return {
                    "validated": True,
                    "reason": "Redirect target indicates resource exists",
                    "final_url": target,
                    "final_status": final_status,
                    "final_len": final_len,
                }

            return {
                "validated": False,
                "reason": f"Redirect target not confirmatory (HTTP {final_status})",
                "final_url": target,
                "final_status": final_status,
                "final_len": final_len,
            }
        except Exception as e:
            return {"validated": False, "reason": f"Redirect validation error: {e}"}

    def _build_baseline(self) -> dict:
        """
        Capture homepage (primary) and random-path probe for content comparison.
        """
        out: dict = {}

        home_url = self.base_url.rstrip("/") + "/"
        try:
            r = self.session.get(
                home_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            body = getattr(r, "text", "") or ""
            body_cap = body[:_BASELINE_BODY_MAX]
            out["homepage_url"] = getattr(r, "url", "") or home_url
            out["homepage_status"] = int(getattr(r, "status_code", 0) or 0)
            out["homepage_len"] = len(body)
            out["homepage_norm"] = self._normalize_body_for_compare(body_cap)
            out["homepage_spa_likely"] = self._is_likely_spa_shell(body)
        except Exception as exc:
            logger.warning("  [!] Directory baseline: homepage fetch failed: %s", exc)
            out["homepage_url"] = home_url
            out["homepage_status"] = -1
            out["homepage_len"] = -1
            out["homepage_norm"] = ""
            out["homepage_spa_likely"] = False

        token = "alanscan-404-" + "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(18)
        )
        probe_url = urljoin(self.base_url + "/", token)
        try:
            r2 = self.session.get(probe_url, timeout=self.timeout, allow_redirects=False)
            body2 = getattr(r2, "text", "") or ""
            out["noop_url"] = probe_url
            out["noop_status"] = int(getattr(r2, "status_code", 0) or 0)
            out["noop_len"] = len(body2)
            out["noop_norm"] = self._normalize_body_for_compare(
                body2[:_BASELINE_BODY_MAX]
            )
        except Exception as exc:
            logger.warning("  [!] Directory baseline: noop probe failed: %s", exc)
            out["noop_url"] = probe_url
            out["noop_status"] = -1
            out["noop_len"] = -1
            out["noop_norm"] = ""

        return out
