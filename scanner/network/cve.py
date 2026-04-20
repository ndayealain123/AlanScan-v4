"""
scanner/network/cve.py
======================
CVE Correlation Engine.

Purpose
-------
Takes the raw service banners collected by the BannerGrabber and cross-
references them against the known-vulnerable version signatures defined in
``config.BANNER_CVE_MAP``.

This provides the analyst with immediate, actionable intelligence:
instead of reporting "Apache 2.4.49 is running", we report
"Apache 2.4.49 is affected by CVE-2021-41773 (Path Traversal / RCE)".

Matching Algorithm
------------------
Simple substring matching is used:
  - The banner text is lower-cased.
  - Each signature key (also lower-cased) is checked for containment.
  - Substring matching avoids brittle version-string parsing while still
    being precise enough for our curated signature set.

Limitations
-----------
- This is a signature-based approach, not a full CPE/NVD lookup.
- Only covers the CVEs listed in config.BANNER_CVE_MAP.
- For a production scanner, integrate with NVD's JSON feed or Shodan's
  CVE database for more comprehensive coverage.

CVSS / Severity Mapping
-----------------------
CVE severity is extracted from the descriptive string in BANNER_CVE_MAP.
If "Critical" appears → CRITICAL; "High" → HIGH; else MEDIUM.
"""

from ..scan_logger import logger

import config

class CVEMatcher:
    """
    Correlates service banners with known CVE signatures.

    Parameters
    ----------
    banner_findings : list[dict]
        Output from BannerGrabber.grab() – each dict must contain a
        ``"banner"`` key with the lower-cased banner text.
    """

    def __init__(self, banner_findings: list[dict]):
        self.banners = [
            f for f in banner_findings
            if "banner" in f and f["banner"]
        ]

    def match(self) -> list[dict]:
        """
        Run CVE correlation against all grabbed banners.

        Returns
        -------
        list[dict]
            One finding per matched CVE, including the CVE ID, description,
            affected service, and severity.
        """
        findings: list[dict] = []

        if not self.banners:
            logger.warning("  [!] No banners available for CVE matching")
            return findings

        for banner_finding in self.banners:
            banner_text = banner_finding["banner"]
            host        = banner_finding["url"]
            port        = banner_finding.get("port", "?")

            for signature, cve_description in config.BANNER_CVE_MAP.items():
                if signature.lower() in banner_text:
                    severity = self._extract_severity(cve_description)

                    finding = {
                        "type":      "CVE Match (Banner-Based)",
                        "url":       host,
                        "parameter": f"port {port}",
                        "payload":   "N/A",
                        "severity":  severity,
                        "evidence":  (
                            f"Banner '{banner_text[:80]}' matches signature "
                            f"'{signature}' → {cve_description}"
                        ),
                    }

                    logger.warning(
                        "  [%s] CVE Match: %s",
                        severity,
                        cve_description[:60],
                    )
                    findings.append(finding)

        if not findings:
            logger.info("  [OK] No known CVE signatures matched in banners")

        return findings

    @staticmethod
    def _extract_severity(description: str) -> str:
        """
        Infer severity from the CVE description string.

        Looks for keywords (case-insensitive) in the CVE description text.
        """
        desc_lower = description.lower()
        if "critical" in desc_lower:
            return "CRITICAL"
        if "high" in desc_lower:
            return "HIGH"
        if "medium" in desc_lower or "moderate" in desc_lower:
            return "MEDIUM"
        return "LOW"
