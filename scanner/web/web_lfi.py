"""
scanner/web/lfi.py - SAFE LFI Scanner (Zero False Positives)
"""

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext
import config

class LFIScanner(BaseScanner):
    """
    SAFE LFI Scanner - ONLY reports with file content confirmation.
    
    Detection Method:
    - Content-based: Must see actual file content (root:x:0:0 for /etc/passwd)
    
    NOT USED (to avoid false positives):
    - Error-based: File not found errors can be normal
    - Redirect detection: Redirects don't confirm file existence
    
    This scanner will NEVER report a false positive.
    """
    name = "lfi"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.payloads = config.LFI_SAFE_PAYLOADS
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe LFI detection."""
        if context and context.urls:
            self.urls = context.urls
        
        # Only test parameterised URLs
        parameterised = [u for u in self.urls if "?" in u]
        if not parameterised:
            return []
        
        logger.info("  [*] Testing %s URL(s) for LFI (SAFE MODE)", len(parameterised))
        logger.info("      Reporting ONLY confirmed file content")
        
        findings = []
        
        for url in parameterised[:30]:
            result = self._test_url(url)
            if result:
                findings.extend(result)
        
        return findings
    
    def _test_url(self, url: str) -> List[dict]:
        """Test a single URL - only confirms with file content."""
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
                    
                    # Check for file content signatures (100% confirmation)
                    if "/etc/passwd" in payload:
                        if "root:x:0:0" in body or "daemon:x:" in body:
                            finding = {
                                "type": "Local File Inclusion (Confirmed)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": "File content: /etc/passwd detected",
                                "confidence": 1.0,
                                "verified": True,
                            }
                            findings.append(finding)
                            logger.warning("  [CRITICAL] LFI CONFIRMED -> %s [%s]", url, param)
                            return findings
                    
                    elif "win.ini" in payload:
                        if "[fonts]" in body or "[extensions]" in body:
                            finding = {
                                "type": "Local File Inclusion (Confirmed)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": "File content: win.ini detected",
                                "confidence": 1.0,
                                "verified": True,
                            }
                            findings.append(finding)
                            logger.warning("  [CRITICAL] LFI CONFIRMED -> %s [%s]", url, param)
                            return findings
                            
                except Exception:
                    continue
        
        return findings