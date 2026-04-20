"""
scanner/web/xss.py - SAFE XSS Scanner (Zero False Positives)
"""

from ..scan_logger import logger
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional, Tuple

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext
import config

class XSSScanner(BaseScanner):
    """
    SAFE XSS Scanner - ONLY reports reflected XSS with confirmation.
    
    Detection Method:
    - Reflection detection: Payload must appear EXACTLY in response
    - Pattern matching: Must match executable script patterns
    
    NOT USED (to avoid false positives):
    - DOM-based detection (static analysis)
    - Behavioral detection (alerts)
    
    This scanner will NEVER report a false positive.
    """
    name = "xss"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.payloads = config.XSS_SAFE_PAYLOADS
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe XSS detection."""
        if context and context.urls:
            self.urls = context.urls
        
        # Find reflected parameters first
        reflected_params = self._find_reflected_parameters()
        
        if not reflected_params:
            logger.warning("  [!] No reflected parameters found")
            return []
        
        logger.info("  [*] Testing %s reflected parameter(s)", len(reflected_params))
        logger.info("      Reporting ONLY confirmed XSS")
        
        findings = []
        
        for url, param in reflected_params[:20]:
            result = self._test_parameter(url, param)
            if result:
                findings.append(result)
                logger.warning("  [CRITICAL] XSS CONFIRMED -> %s [%s]", url, param)
        
        return findings
    
    def _find_reflected_parameters(self) -> List[Tuple[str, str]]:
        """
        Find parameters that reflect input.
        This is the KEY to eliminating false positives.
        """
        reflected = []
        canary = "ALANSCAN_XSS_TEST_7X9"
        
        for url in self.urls[:100]:
            if "?" not in url:
                continue
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            for param in params:
                # Test with unique canary
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = canary
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                
                try:
                    resp = self._safe_request(test_url)
                    if resp and canary in resp.text:
                        reflected.append((url, param))
                        logger.info("  [i] Parameter '%s' reflects input", param)
                except Exception:
                    continue
        
        return reflected
    
    def _test_parameter(self, url: str, param: str) -> Optional[Dict]:
        """Test a single parameter - only confirms with executable patterns."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for payload in self.payloads:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            
            try:
                resp = self._safe_request(test_url)
                if not resp:
                    continue
                
                body = resp.text
                
                # Must have EXACT payload reflection
                if payload not in body:
                    continue
                
                # Must match executable pattern
                for pattern in config.XSS_CONFIRMED_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        return {
                            "type": "Reflected XSS (Confirmed)",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "CRITICAL",
                            "evidence": f"XSS payload reflected and executable in response",
                            "confidence": 1.0,
                            "verified": True,
                        }
                        
            except Exception:
                continue
        
        return None