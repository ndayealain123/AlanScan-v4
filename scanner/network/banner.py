"""
scanner/network/banner.py
=========================
Service Banner Grabber.

What Is Banner Grabbing?
------------------------
Many network services (FTP, SSH, SMTP, HTTP, Telnet, etc.) transmit a plaintext
"banner" immediately upon connection.  This banner typically contains the service
name, version, and sometimes the OS.

Example banners:
  FTP:   ``220 ProFTPD 1.3.5 Server``
  SSH:   ``SSH-2.0-OpenSSH_7.4``
  SMTP:  ``220 mail.example.com ESMTP Postfix``
  HTTP:  Server header: ``Apache/2.4.49 (Unix)``

Why It Matters
--------------
Version information allows an attacker (or a scanner like us) to cross-reference
known CVE databases.  A single ProFTPD 1.3.5 banner is enough to confirm
CVE-2015-3306 (unauthenticated RCE via the mod_copy module).

Technique
---------
1. For HTTP/HTTPS ports, send a real HEAD request and extract the Server header.
2. For all other ports, open a raw TCP socket and read the first 1024 bytes.
3. Decode the bytes as UTF-8 (with error replacement for binary protocols).
4. Store the decoded banner for CVE matching.
"""

from ..scan_logger import logger, coerce_evidence_field
import socket

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

import config

# Ports where we send an HTTP HEAD request instead of raw socket read
HTTP_PORTS = {80, 8080, 8443, 443, 8888}


class BannerGrabber:
    """
    Grabs service banners from open ports.

    Parameters
    ----------
    host : str
        Target IP address.
    open_ports : list[int]
        List of confirmed open port numbers (from the PortScanner).
    timeout : int
        Per-connection timeout.
    """

    def __init__(self, host: str, open_ports: list[int], timeout: int = 3):
        self.host       = host
        self.open_ports = open_ports
        self.timeout    = timeout

    def grab(self) -> list[dict]:
        """
        Grab banners from all open ports in parallel.

        Returns
        -------
        list[dict]
            Findings containing banner text and port/service metadata.
        """
        findings: list[dict] = []

        if not self.open_ports:
            logger.warning("  [!] No open ports to grab banners from")
            return findings

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._grab_banner, port): port
                for port in self.open_ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def _grab_banner(self, port: int) -> dict | None:
        """
        Attempt to grab a banner from a single port.

        Uses an HTTP HEAD request for web ports, raw TCP read for others.
        """
        banner = None

        if port in HTTP_PORTS:
            banner = self._http_banner(port)
        else:
            banner = self._raw_banner(port)

        if not banner:
            return None

        service = config.PORT_SERVICE_MAP.get(port, "Unknown")
        banner_s = coerce_evidence_field(banner)
        logger.info("  [INFO] Banner %s/%s: %s", port, service, banner_s[:80])

        return {
            "type":      "Service Banner",
            "url":       self.host,
            "parameter": f"port {port}",
            "port":      port,
            "payload":   "N/A",
            "severity":  "INFO",
            "evidence":  f"Banner: {banner_s.strip()[:200]}",
            "banner":    banner_s.lower().strip(),   # kept for CVE matching
        }

    def _http_banner(self, port: int) -> str | None:
        """
        Extract the Server header from an HTTP response.

        Uses HTTPS for port 443/8443, HTTP otherwise.
        """
        scheme = "https" if port in (443, 8443) else "http"
        url    = f"{scheme}://{self.host}:{port}/"
        try:
            # verify=False (controlled probe). Suppress only the insecure TLS warning.
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp   = requests.head(url, timeout=self.timeout, verify=False,
                                   headers=config.DEFAULT_HEADERS,
                                   allow_redirects=True)
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            parts   = [p for p in [server, powered] if p]
            return " | ".join(parts) if parts else None
        except Exception:
            return None

    def _raw_banner(self, port: int) -> str | None:
        """
        Read raw bytes from the service immediately after connection.

        Some services (FTP, SMTP, Telnet) send the banner unprompted.
        Others (SSH) respond to an initial newline probe.
        """
        try:
            with socket.create_connection((self.host, port),
                                          timeout=self.timeout) as sock:
                # Try reading spontaneous banner first
                sock.settimeout(self.timeout)
                data = b""
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    pass

                # If nothing, send a gentle probe (newline)
                if not data:
                    sock.sendall(b"\r\n")
                    try:
                        data = sock.recv(1024)
                    except socket.timeout:
                        pass

            return data.decode("utf-8", errors="replace") if data else None

        except Exception:
            return None
