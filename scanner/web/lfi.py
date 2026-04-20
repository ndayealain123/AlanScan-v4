"""
scanner/web/lfi.py
==================
Local File Inclusion (LFI) and Path Traversal Scanner.

Attack Description
------------------
Path traversal (CWE-22) occurs when user-supplied input is used to construct
a filesystem path without adequate validation.  Attackers use sequences like
``../`` to escape the intended directory and read arbitrary files.

LFI is a sub-class where the traversal causes a server-side script to *include*
a file (in PHP: ``include($_GET['page'])``), potentially executing it.

Detection Approach
------------------
1. For each URL with query parameters, inject path traversal sequences.
2. Check the response for known signatures of the target files:
   - ``/etc/passwd`` → look for ``root:x:0:0``
   - ``/etc/shadow`` → look for ``$6$`` (SHA-512 hash prefix)
   - ``win.ini``     → look for ``[fonts]``
3. Additionally check for PHP wrapper disclosure:
   - ``php://filter/convert.base64-encode/resource=index`` can leak source

OWASP Reference: A01:2021 – Broken Access Control, CWE-22
"""

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import config


# Signatures that confirm the traversal was successful
FILE_SIGNATURES = {
    "/etc/passwd":    ["root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh"],
    "/etc/shadow":    ["$6$", "$5$", "$1$", "root:$"],
    "win.ini":        ["[fonts]", "[extensions]", "[mci extensions]"],
    "windows/win.ini":["[fonts]"],
    "boot.ini":       ["[boot loader]", "operating systems"],
}


from ..base_scanner import BaseScanner
from .base_module import ScanContext

class LFIScanner(BaseScanner):
    """
    LFI / Path Traversal vulnerability scanner.
    """
    name = "lfi"

    def __init__(self, urls: list[str], threads: int = 10,
                 timeout: int = 10, proxy: str | None = None, **kwargs):
        super().__init__(urls, threads=threads, timeout=timeout, proxy=proxy, **kwargs)

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self) -> list[dict]:
        """
        Scan all parameterised URLs for path traversal / LFI.

        Returns
        -------
        list[dict]
            All LFI/traversal findings.
        """
        findings: list[dict] = []
        parameterised = [u for u in self.urls if "?" in u]

        if not parameterised:
            logger.warning("  [!] No parameterised URLs for LFI testing")
            return findings

        logger.info("  [*] Testing %s URL(s) for LFI", len(parameterised))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_url, url): url
                for url in parameterised
            }
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    pass


        # ── Deduplicate: same path+param+type reported only once ────────────
        seen, deduped = set(), []
        for fi in findings:
            try:
                from urllib.parse import urlparse as _up
                base = _up(fi.get("url","")).path
            except Exception:
                base = fi.get("url","")
            key = (fi.get("url",""), fi.get("parameter",""), fi.get("type",""))
            if key not in seen:
                seen.add(key)
                deduped.append(fi)
        return deduped


    def _test_url(self, url: str) -> list[dict]:
        """Test a single URL across all LFI payloads."""
        results: list[dict] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            for payload in config.LFI_PAYLOADS:
                test_params        = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url           = urlunparse(
                    parsed._replace(query=urlencode(test_params))
                )

                try:
                    resp = self.session.get(test_url, timeout=self.timeout,
                                            allow_redirects=False)
                    # Check for known file content signatures
                    evidence = self._check_signatures(resp.text)
                    if evidence:
                        finding = {
                            "type":      "Local File Inclusion / Path Traversal",
                            "url":       test_url,
                            "parameter": param,
                            "payload":   payload,
                            "severity":  "CRITICAL",
                            "evidence":  evidence,
                        }
                        logger.warning("  [CRITICAL] LFI → %s [%s]", url, param)
                        results.append(finding)
                        break  # Confirmed; skip remaining payloads for this param

                except Exception:
                    continue

        return results

    @staticmethod
    def _check_signatures(body: str) -> str | None:
        """
        Search the response body for file-content signatures.

        Returns the first matching signature string if found,
        or None if the response doesn't indicate successful traversal.
        """
        for file_path, signatures in FILE_SIGNATURES.items():
            for sig in signatures:
                if sig in body:
                    return f"File content signature '{sig}' found (likely {file_path})"
        return None
