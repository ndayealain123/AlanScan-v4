"""
scanner/web/headers.py - SAFE Headers Scanner (100% Deterministic)
"""

from ..scan_logger import logger
from typing import List, Dict, Optional

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext
from .version_disclosure_header import is_reportable_version_disclosure_header
import config

class HeaderScanner(BaseScanner):
    """
    SAFE Security Headers Scanner - 100% deterministic.
    
    Detection Method:
    - Header presence check: Either header exists or doesn't
    - This is 100% accurate
    
    No false positives because we're checking for ABSENCE of security headers.
    """
    name = "headers"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.base_url = target if isinstance(target, str) else target[0]
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe header security check."""
        findings = []
        
        try:
            resp = self._safe_request(self.base_url, allow_redirects=True)
            if not resp:
                return findings
            
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            # Check for missing security headers
            missing = []
            for header, description in config.SECURITY_HEADERS.items():
                if header.lower() not in headers_lower:
                    missing.append({"header": header, "description": description})
            
            if missing:
                missing_names = [m["header"] for m in missing]
                finding = {
                    "type": "Missing Security Headers",
                    "url": self.base_url,
                    "parameter": "response_headers",
                    "payload": "N/A",
                    "severity": "LOW",
                    "evidence": f"Missing headers: {', '.join(missing_names)}",
                    "confidence": 1.0,
                    "verified": True,
                }
                findings.append(finding)
                logger.info("  [LOW] Missing headers: %s", ", ".join(missing_names))
            
            # Check information disclosure headers (real version token; skip URL reflection)
            for disclosure_header in ["server", "x-powered-by"]:
                if disclosure_header in headers_lower:
                    value = headers_lower[disclosure_header]
                    if not is_reportable_version_disclosure_header(
                        disclosure_header, value, self.base_url
                    ):
                        continue
                    finding = {
                        "type": "Information Disclosure (Header)",
                        "url": self.base_url,
                        "parameter": disclosure_header,
                        "payload": "N/A",
                        "severity": "LOW",
                        "evidence": f"Header '{disclosure_header}: {value}' reveals software",
                        "confidence": 1.0,
                        "verified": True,
                    }
                    findings.append(finding)
                    logger.info("  [LOW] Version disclosure: %s: %s", disclosure_header, value)
            
        except Exception as e:
            logger.warning("  [!] Header scan error: %s", e)
        
        return findings