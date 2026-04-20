"""
scanner/network/portscan.py
===========================
TCP Connect Port Scanner.

Methodology
-----------
A TCP connect scan (as opposed to a raw SYN scan) completes the full TCP
three-way handshake:

  Client → SYN → Target
  Client ← SYN-ACK ← Target   (port is OPEN)
  Client → ACK → Target
  Client → FIN / RST → Target  (immediately close)

Advantages of TCP Connect:
  - Requires no root/admin privileges (unlike SYN scan).
  - Works from any unprivileged user account.
  - Compatible with all operating systems.

Disadvantages:
  - More easily detected by IDS/IPS due to the completed handshake.
  - Slightly slower than SYN scan.

Concurrency Model
-----------------
Each port check runs in a separate thread.  With the default 10 threads and
a 1-second timeout, 24 ports are checked in approximately 2-3 seconds total.

Output
------
Each open port produces a finding dict with service identification,
severity (based on service risk), and contextual evidence.
"""

from ..scan_logger import logger
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import config

# Services considered HIGH risk due to historical exploitation frequency
HIGH_RISK_SERVICES = {
    23: "Telnet (plaintext – CRITICAL)",
    21: "FTP (plaintext credentials)",
    445: "SMB (EternalBlue / WannaCry target)",
    3389: "RDP (BlueKeep target; brute-force risk)",
    5900: "VNC (remote desktop; often unauthenticated)",
    6379: "Redis (commonly unauthenticated by default)",
    27017: "MongoDB (commonly unauthenticated by default)",
}


class PortScanner:
    """
    Threaded TCP connect port scanner.

    Parameters
    ----------
    host : str
        Target IP address or hostname.
    timeout : int
        Per-port connection timeout in seconds.
    threads : int
        Number of parallel connection workers.
    """

    def __init__(self, host: str, timeout: int = 1, threads: int = 50):
        self.host    = host
        self.timeout = timeout
        self.threads = threads

    def scan(self) -> list[dict]:
        """
        Scan all TOP_PORTS and return findings for open ports.

        Returns
        -------
        list[dict]
            One finding per open port, including service name and risk level.
        """
        findings: list[dict] = []
        logger.info("  [*] Scanning %s ports on %s", len(config.TOP_PORTS), self.host)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_port, port): port
                for port in config.TOP_PORTS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        # Sort by port number for readable output
        findings.sort(key=lambda f: f.get("port", 0))
        return findings

    def _check_port(self, port: int) -> dict | None:
        """
        Attempt a TCP connect to (host, port).

        Returns
        -------
        dict | None
            A finding dict if the port is open, otherwise None.
        """
        try:
            with socket.create_connection((self.host, port),
                                          timeout=self.timeout):
                service  = config.PORT_SERVICE_MAP.get(port, "Unknown")
                severity = self._severity(port)
                note     = HIGH_RISK_SERVICES.get(port, service)

                logger.warning("  [%s] Port %s/tcp OPEN – %s", severity, port, note)

                return {
                    "type":      "Open Port",
                    "url":       self.host,
                    "parameter": f"port {port}/tcp",
                    "port":      port,
                    "payload":   "TCP connect",
                    "severity":  severity,
                    "evidence":  f"Port {port} open – service: {note}",
                }

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    @staticmethod
    def _severity(port: int) -> str:
        """
        Assign severity based on the inherent risk of the open service.

        Telnet (23) → CRITICAL (plaintext + remote shell)
        High-risk services → HIGH
        Standard but exposed services → MEDIUM
        """
        if port == 23:
            return "CRITICAL"
        if port in HIGH_RISK_SERVICES:
            return "HIGH"
        if port in (22, 21, 3306, 5432):
            return "MEDIUM"
        return "LOW"
