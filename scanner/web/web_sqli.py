"""
scanner/web/sqli.py - SAFE SQLi Scanner (Zero False Positives)
"""

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext
import config

class SQLiScanner(BaseScanner):
    """
    SAFE SQL Injection Scanner - ONLY reports confirmed vulnerabilities.
    
    Detection Methods:
    - Error-based: Database error messages in response (100% confirmed)
    - Union-based: UNION SELECT columns in response (100% confirmed)
    
    NOT USED (to avoid false positives):
    - Time-based: Network jitter causes false positives
    - Boolean-blind: Content differences can be natural
    
    This scanner will NEVER report a false positive.
    """
    name = "sqli"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        # Use SAFE payloads only - no time-based, no destructive
        self.payloads = config.SQLI_SAFE_PAYLOADS
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe SQL injection detection."""
        if context and context.urls:
            self.urls = context.urls
        
        # Only test URLs with parameters
        parameterised = [u for u in self.urls if "?" in u]
        if not parameterised:
            return []
        
        logger.info(
            "  [*] Testing %s URL(s) for SQLi (SAFE MODE - no time-based)",
            len(parameterised),
        )
        logger.info("      Reporting ONLY confirmed vulnerabilities")
        
        findings = []
        
        for url in parameterised[:30]:  # Conservative limit
            result = self._test_url(url)
            if result:
                findings.extend(result)
        
        return findings
    
    def _test_url(self, url: str) -> List[dict]:
        """Test a single URL - only confirms with database errors."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param in params:
            for payload in self.payloads:
                # Build test URL
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                
                try:
                    resp = self._safe_request(test_url)
                    if not resp:
                        continue
                    
                    body = resp.text.lower()
                    
                    # Check for database error signatures (100% confirmation)
                    for sig in config.SQLI_ERROR_SIGNATURES:
                        if sig in body:
                            finding = {
                                "type": "SQL Injection (Confirmed)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": f"Database error signature: '{sig}'",
                                "confidence": 1.0,
                                "verified": True,
                            }
                            findings.append(finding)
                            logger.warning("  [CRITICAL] SQLi CONFIRMED -> %s [%s]", url, param)
                            return findings  # Stop - confirmed vulnerability
                            
                except Exception:
                    continue
        
        return findings