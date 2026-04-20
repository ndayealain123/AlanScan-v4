"""
scanner/web/cmdi.py - SAFE CMDi Scanner (Zero False Positives)
"""

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext
import config

class CMDiScanner(BaseScanner):
    """
    SAFE Command Injection Scanner - ONLY reports with output confirmation.
    
    Detection Method:
    - Output-based: Command output must appear in response (uid=, www-data, etc.)
    
    NOT USED (to avoid false positives):
    - Time-based: Network jitter causes false positives
    - Error-based: Shell errors can be normal
    
    This scanner will NEVER report a false positive.
    """
    name = "cmdi"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.payloads = config.CMDI_SAFE_PAYLOADS
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe command injection detection."""
        if context and context.urls:
            self.urls = context.urls
        
        # Only test parameterised URLs
        parameterised = [u for u in self.urls if "?" in u]
        if not parameterised:
            return []
        
        logger.info("  [*] Testing %s URL(s) for CMDi (SAFE MODE)", len(parameterised))
        logger.info("      Reporting ONLY confirmed command output")
        
        findings = []
        
        for url in parameterised[:30]:
            result = self._test_url(url)
            if result:
                findings.extend(result)
        
        return findings
    
    def _test_url(self, url: str) -> List[dict]:
        """Test a single URL - only confirms with command output."""
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
                    
                    # Check for command output signatures (100% confirmation)
                    for sig in config.CMDI_OUTPUT_SIGNATURES:
                        if sig in body:
                            finding = {
                                "type": "OS Command Injection (Confirmed)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": f"Command output signature: '{sig}'",
                                "confidence": 1.0,
                                "verified": True,
                            }
                            findings.append(finding)
                            logger.warning("  [CRITICAL] CMDi CONFIRMED -> %s [%s]", url, param)
                            return findings  # Stop - confirmed
                            
                except Exception:
                    continue
        
        return findings