"""
scanner/web/dom_xss.py - DYNAMIC DOM XSS with 0% False Positives
"""

from ..scan_logger import logger
import threading
import time
from typing import List, Dict, Optional
from urllib.parse import urlparse

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, JavascriptException
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logger.warning(
        "  [!] Selenium not installed. DOM XSS detection requires: pip install selenium webdriver-manager"
    )

from ..base_scanner import BaseScanner
from scanner.web.base_module import ScanContext


class DOMXSSScanner(BaseScanner):
    """
    DOM-Based XSS Scanner with Browser Automation - 0% False Positives.
    
    Method: Actual browser execution with alert detection
    Confirmation: Must see JavaScript alert() dialog
    False Positive Rate: 0% (alert must actually fire)
    """
    name = "dom_xss"
    
    def __init__(self, target: str | List[str], **kwargs):
        super().__init__(target, **kwargs)
        self.headless = kwargs.get("headless", True)
        self.driver = None
        
        # Payloads that trigger alerts (must be confirmed)
        self.payloads = [
            ("<img src=x onerror=alert('DOM_XSS_CONFIRMED')>", "event"),
            ("<svg onload=alert('DOM_XSS_CONFIRMED')>", "svg"),
            ("<script>alert('DOM_XSS_CONFIRMED')</script>", "script"),
            ("javascript:alert('DOM_XSS_CONFIRMED')", "url"),
            ("<body onload=alert('DOM_XSS_CONFIRMED')>", "body"),
        ]
        
        self.confirmation_string = "DOM_XSS_CONFIRMED"
    
    def run(self, context: Optional[ScanContext] = None) -> List[dict]:
        """Run dynamic DOM XSS detection."""
        if not SELENIUM_AVAILABLE:
            return []
        
        if context and context.urls:
            self.urls = context.urls
        
        logger.info("  [*] Dynamic DOM XSS detection on %s URL(s)", len(self.urls))
        logger.info("      Using actual browser execution - 0% false positives")
        
        findings = []
        
        try:
            self._init_driver()
            
            for url in self.urls[:20]:
                result = self._test_url(url)
                if result:
                    findings.append(result)
                    logger.warning("  [CRITICAL] DOM XSS CONFIRMED -> %s", url)
            
        except Exception as e:
            logger.warning("  [!] DOM XSS scanner error: %s", e)
        
        finally:
            self._cleanup()
        
        return findings
    
    def _init_driver(self):
        """Initialize Chrome driver with security options."""
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-popup-blocking")
        
        # Disable logs to reduce noise
        chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
        
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.driver.set_page_load_timeout(self.timeout)
    
    def _test_url(self, url: str) -> Optional[Dict]:
        """Test a URL for DOM XSS with actual alert detection."""
        
        # Test 1: URL parameters
        if "?" in url:
            result = self._test_url_params(url)
            if result:
                return result
        
        # Test 2: URL hash/fragment
        result = self._test_hash(url)
        if result:
            return result
        
        # Test 3: DOM sinks in page (with user interaction simulation)
        result = self._test_dom_sinks(url)
        if result:
            return result
        
        return None
    
    def _test_url_params(self, url: str) -> Optional[Dict]:
        """Test URL parameters with actual browser execution."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param in params:
            for payload, ptype in self.payloads:
                # Build test URL
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                
                try:
                    # Load page
                    self.driver.get(test_url)
                    
                    # Check for alert dialog
                    alert_detected = self._check_for_alert()
                    
                    if alert_detected:
                        return {
                            "type": "DOM-Based XSS (Confirmed)",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "CRITICAL",
                            "evidence": f"JavaScript alert() triggered in browser context",
                            "payload_type": ptype,
                            "verified": True,
                            "confidence": 1.0
                        }
                        
                except TimeoutException:
                    continue
                except Exception:
                    continue
        
        return None
    
    def _test_hash(self, url: str) -> Optional[Dict]:
        """Test URL hash for XSS."""
        for payload, ptype in self.payloads:
            test_url = f"{url}#{payload}"
            
            try:
                self.driver.get(test_url)
                
                alert_detected = self._check_for_alert()
                
                if alert_detected:
                    return {
                        "type": "DOM-Based XSS (Hash/Fragment)",
                        "url": test_url,
                        "parameter": "location.hash",
                        "payload": payload,
                        "severity": "CRITICAL",
                        "evidence": "JavaScript alert() triggered via location.hash",
                        "payload_type": ptype,
                        "verified": True,
                        "confidence": 1.0
                    }
                    
            except Exception:
                continue
        
        return None
    
    def _test_dom_sinks(self, url: str) -> Optional[Dict]:
        """Test DOM sinks by simulating user interaction."""
        try:
            self.driver.get(url)
            
            # Try to find and trigger potential sinks
            # Look for input fields that might reflect to DOM
            inputs = self.driver.find_elements(By.TAG_NAME, "input")
            
            for inp in inputs:
                for payload, ptype in self.payloads:
                    try:
                        inp.clear()
                        inp.send_keys(payload)
                        
                        # Try to trigger (submit, blur, change)
                        inp.send_keys("\n")  # Try enter key
                        
                        # Check for alert
                        alert_detected = self._check_for_alert()
                        
                        if alert_detected:
                            return {
                                "type": "DOM-Based XSS (Stored/DOM Sink)",
                                "url": url,
                                "parameter": inp.get_attribute("name") or "input",
                                "payload": payload,
                                "severity": "CRITICAL",
                                "evidence": "JavaScript alert() triggered via DOM manipulation",
                                "payload_type": ptype,
                                "verified": True,
                                "confidence": 1.0
                            }
                            
                    except Exception:
                        continue
                        
        except Exception:
            pass
        
        return None
    
    def _check_for_alert(self) -> bool:
        """Check if an alert dialog was triggered."""
        try:
            # Switch to alert if present
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            
            # Check if it's our confirmation string
            if self.confirmation_string in alert_text:
                # Dismiss alert
                alert.dismiss()
                return True
                
        except:
            pass
        
        return False
    
    def _cleanup(self):
        """Clean up browser driver."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass