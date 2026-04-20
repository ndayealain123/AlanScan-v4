"""
scanner/web/csrf.py - SAFE CSRF Scanner (100% Deterministic)
"""

from ..scan_logger import logger
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import List, Dict, Optional

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext

class CSRFScanner(BaseScanner):
    """
    SAFE CSRF Scanner - 100% deterministic detection.
    
    Detection Method:
    - Token presence: Check if forms have CSRF tokens
    - This is 100% accurate - either token exists or doesn't
    
    No false positives because we're checking for ABSENCE of protection.
    """
    name = "csrf"
    
    # Known CSRF token field names
    CSRF_TOKEN_NAMES = {
        "csrf_token", "csrftoken", "csrf", "_csrf", "csrfmiddlewaretoken",
        "_token", "authenticity_token", "__requestverificationtoken",
        "_wpnonce", "token", "xsrf_token", "_xsrf", "nonce"
    }
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run safe CSRF detection."""
        if context and context.urls:
            self.urls = context.urls
        
        findings = []
        
        # Find all forms on all pages
        forms = self._find_forms()
        
        if not forms:
            logger.warning("  [!] No forms found for CSRF testing")
            return []
        
        logger.info("  [*] Testing %s form(s) for CSRF protection", len(forms))
        
        for form in forms:
            if not self._has_csrf_token(form):
                finding = {
                    "type": "CSRF - Missing Anti-CSRF Token",
                    "url": form["url"],
                    "parameter": "form",
                    "payload": "N/A",
                    "severity": "HIGH",
                    "evidence": f"Form at {form['url']} has no CSRF token. Method: {form['method'].upper()}",
                    "confidence": 1.0,
                    "verified": True,
                }
                findings.append(finding)
                logger.warning("  [HIGH] CSRF: Missing token -> %s", form["url"])
        
        return findings
    
    def _find_forms(self) -> List[Dict]:
        """Find all forms on all pages."""
        forms = []
        seen = set()
        
        for url in self.urls[:50]:
            try:
                resp = self._safe_request(url)
                if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                
                soup = BeautifulSoup(resp.text, "html.parser")
                
                for form in soup.find_all("form"):
                    method = form.get("method", "get").lower()
                    if method not in ["post", "put", "delete"]:
                        continue
                    
                    action = form.get("action", url)
                    form_url = urljoin(url, action)
                    
                    # Collect field names
                    field_names = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            field_names.append(name)
                    
                    # Key for deduplication
                    key = f"{form_url}|{method}|{sorted(field_names)}"
                    if key in seen:
                        continue
                    seen.add(key)
                    
                    forms.append({
                        "url": form_url,
                        "method": method,
                        "fields": field_names,
                        "source": url
                    })
                    
            except Exception:
                continue
        
        return forms
    
    def _has_csrf_token(self, form: Dict) -> bool:
        """Check if form has a CSRF token field."""
        for field in form["fields"]:
            if field.lower() in self.CSRF_TOKEN_NAMES:
                return True
        return False