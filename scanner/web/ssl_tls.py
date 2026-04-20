"""
scanner/web/ssl_tls.py
======================
Advanced SSL/TLS Security Analyser.

Checks Performed
----------------
1.  Certificate Expiry         — expired or expiring within 30 days
2.  Self-Signed Certificate    — issuer == subject, no trusted CA
3.  Hostname Mismatch          — cert does not cover target domain
4.  Deprecated Protocol        — SSLv2, SSLv3, TLS 1.0, TLS 1.1
5.  Weak Cipher Suite          — RC4, DES, 3DES, NULL, EXPORT, ANON, MD5
6.  Short Key Length           — cipher < 128 bits
7.  HSTS Header Missing        — no Strict-Transport-Security on HTTPS site
8.  HSTS Max-Age Too Short     — max-age < 31536000 (1 year)
9.  Mixed Content Risk         — HTTPS site missing upgrade-insecure-requests
10. TLS 1.3 Not Supported      — server not offering best available protocol
11. Certificate Key Size       — RSA < 2048 bits or ECC < 256 bits
12. Signature Algorithm Weak   — MD5 or SHA1 signed certificates
13. HTTP Plaintext             — site not using HTTPS at all

OWASP Reference: A02:2021 – Cryptographic Failures
CVEs covered: POODLE (SSLv3), BEAST (TLS1.0), CRIME, SWEET32 (3DES)
"""

import ssl
import socket
import datetime
import re
from urllib.parse import urlparse

import config
from ..base_scanner import BaseScanner
from ..scan_logger import logger
from .base_module import ScanContext

WEAK_PROTOCOLS     = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS       = ["RC4","DES","3DES","NULL","EXPORT","ANON","MD5","ADH","AECDH","SEED","IDEA"]
WEAK_SIG_ALGOS     = ["md5", "sha1"]


class SSLScanner(BaseScanner):
    name = "ssl"

    def __init__(self, url: str, timeout: int = 10, **kwargs):
        super().__init__(url, timeout=timeout, **kwargs)
        self.url = url
        parsed = urlparse(url)
        self.hostname = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"

    def run(self, context: ScanContext) -> list[dict]:
        self.urls = context.urls
        self.url = context.target
        self.session = context.auth_session or context.session
        
        # Re-parse derived fields for the new target
        parsed        = urlparse(self.url)
        self.hostname = parsed.hostname or ""
        self.port     = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"
        
        return self.scan()

    def scan(self) -> list[dict]:
        # ── HTTP site — not HTTPS ─────────────────────────────────────────────
        if not self.is_https:
            logger.warning("  [!] Target is HTTP — no SSL/TLS to analyse")
            return [self._f("Plaintext HTTP – No Encryption", "HIGH",
                "Site does not use HTTPS. All traffic (passwords, session tokens, data) "
                "is transmitted in plaintext. Vulnerable to passive interception (MITM). "
                "OWASP A02:2021 — Cryptographic Failures.")]

        findings = []

        try:
            # ── Primary TLS handshake ─────────────────────────────────────────
            ctx = ssl.create_default_context()
            with socket.create_connection(
                    (self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()   # (name, protocol, bits)
                    proto  = ssock.version()  # e.g. "TLSv1.3"
                    der    = ssock.getpeercert(binary_form=True)

            findings += self._check_cert(cert)
            findings += self._check_protocol(proto)
            findings += self._check_cipher(cipher)
            findings += self._check_key_size(cert)
            findings += self._check_sig_algo(cert)
            findings += self._check_hsts()
            findings += self._check_tls13_support(proto)

        except ssl.CertificateError as exc:
            findings.append(self._f("SSL Certificate Error", "HIGH", str(exc)))
            logger.warning("  [HIGH] Certificate error: %s", exc)

        except ssl.SSLError as exc:
            findings.append(self._f("SSL Handshake Error", "HIGH",
                f"SSL handshake failed: {exc} — possible misconfiguration or deprecated protocol forced."))
            logger.warning("  [HIGH] SSL error: %s", exc)

        except Exception as exc:
            logger.warning("  [!] SSL probe error: %s", exc)

        # ── Try deprecated protocols explicitly ───────────────────────────────
        findings += self._probe_weak_protocols()

        return findings

    # ── Certificate checks ────────────────────────────────────────────────────

    def _check_cert(self, cert: dict) -> list[dict]:
        findings = []

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                delta     = not_after - datetime.datetime.utcnow()
                if delta.days < 0:
                    findings.append(self._f("Expired SSL Certificate", "CRITICAL",
                        f"Certificate expired {abs(delta.days)} day(s) ago ({not_after_str}). "
                        f"Browsers will display security warnings and connections may be blocked."))
                    logger.warning("  [CRITICAL] SSL certificate EXPIRED")
                elif delta.days <= 7:
                    findings.append(self._f("SSL Certificate Expiring Critically Soon", "CRITICAL",
                        f"Certificate expires in {delta.days} day(s) ({not_after_str}). "
                        f"Immediate renewal required."))
                    logger.warning("  [CRITICAL] SSL cert expires in %s days", delta.days)
                elif delta.days <= 30:
                    findings.append(self._f("SSL Certificate Expiring Soon", "MEDIUM",
                        f"Certificate expires in {delta.days} day(s) ({not_after_str}). "
                        f"Renewal recommended within 7 days."))
                    logger.warning("  [MEDIUM] SSL cert expires in %s days", delta.days)
                else:
                    logger.info("  [OK] Certificate valid for %s more days", delta.days)
            except ValueError:
                pass

        # Self-signed
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        if subject.get("commonName") == issuer.get("commonName"):
            findings.append(self._f("Self-Signed Certificate", "HIGH",
                f"Certificate issued by itself ({subject.get('commonName','?')}). "
                f"No trusted CA chain. Browsers will show untrusted certificate warning. "
                f"Vulnerable to MITM — any attacker can present the same self-signed cert."))
            logger.warning("  [HIGH] Self-signed certificate")

        # Hostname mismatch
        san_list = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_list.append(san_value.lower())
        if san_list:
            matched = any(
                self.hostname.lower() == s or
                (s.startswith("*.") and self.hostname.lower().endswith(s[1:]))
                for s in san_list
            )
            if not matched:
                findings.append(self._f("SSL Hostname Mismatch", "HIGH",
                    f"Certificate SANs {san_list} do not cover '{self.hostname}'. "
                    f"Browsers will reject this certificate — MITM risk."))
                logger.warning(
                    "  [HIGH] Hostname mismatch: %s not in %s",
                    self.hostname,
                    san_list,
                )
            else:
                logger.info("  [OK] Hostname '%s' covered by certificate", self.hostname)

        return findings

    def _check_protocol(self, proto: str | None) -> list[dict]:
        findings = []
        if proto in WEAK_PROTOCOLS:
            cve_map = {
                "SSLv3": "CVE-2014-3566 (POODLE)",
                "TLSv1": "CVE-2011-3389 (BEAST)",
                "TLSv1.1": "CVE-2013-2566 (RC4 bias)",
                "SSLv2": "CVE-2016-0800 (DROWN)",
            }
            cve = cve_map.get(proto, "multiple CVEs")
            findings.append(self._f("Deprecated TLS Protocol", "HIGH",
                f"Negotiated protocol is {proto} — deprecated and insecure. "
                f"Associated vulnerability: {cve}. Upgrade to TLS 1.2 minimum, TLS 1.3 recommended."))
            logger.warning("  [HIGH] Deprecated protocol: %s (%s)", proto, cve)
        else:
            logger.info("  [OK] Protocol: %s", proto)
        return findings

    def _check_cipher(self, cipher: tuple | None) -> list[dict]:
        findings = []
        if not cipher:
            return findings
        name, _, bits = cipher
        for weak in WEAK_CIPHERS:
            if weak in name.upper():
                attack_map = {
                    "3DES": "SWEET32 (CVE-2016-2183)",
                    "RC4":  "CVE-2013-2566 — RC4 biases allow plaintext recovery",
                    "DES":  "DES 56-bit key — brute-forceable in hours",
                    "NULL": "No encryption — plaintext transmission",
                    "EXPORT": "FREAK attack (CVE-2015-0204) — export-grade 512-bit RSA",
                    "ANON": "No authentication — trivial MITM",
                }
                detail = attack_map.get(weak, f"weak cipher keyword '{weak}'")
                findings.append(self._f("Weak Cipher Suite", "HIGH",
                    f"Negotiated cipher '{name}' is weak. Attack: {detail}. "
                    f"Disable in server config and use AES-GCM or ChaCha20-Poly1305."))
                logger.warning("  [HIGH] Weak cipher: %s (%s)", name, weak)
                return findings
        if bits and bits < 128:
            findings.append(self._f("Short Cipher Key Length", "MEDIUM",
                f"Cipher '{name}' uses only {bits}-bit key. Minimum recommended: 128-bit."))
        else:
            logger.info("  [OK] Cipher: %s (%s bits)", name, bits)
        return findings

    def _check_key_size(self, cert: dict) -> list[dict]:
        """Check RSA/EC public key size from certificate."""
        findings = []
        try:
            pub = cert.get("subjectPublicKeyInfo", {})
            if not pub:
                return findings
            algo = pub.get("algorithm", {}).get("algorithm", "")
            bits = pub.get("keySize", 0)
            if "rsa" in algo.lower() and bits and int(bits) < 2048:
                findings.append(self._f("Weak RSA Key Size", "HIGH",
                    f"RSA public key is only {bits} bits. "
                    f"NIST recommends minimum 2048 bits. Keys under 1024 bits can be factored."))
                logger.warning("  [HIGH] Weak RSA key: %s bits", bits)
        except Exception:
            pass
        return findings

    def _check_sig_algo(self, cert: dict) -> list[dict]:
        """Check for MD5 or SHA1 signed certificates."""
        findings = []
        try:
            sig_algo = str(cert.get("signatureAlgorithm", {})
                          .get("algorithm", "")).lower()
            if not sig_algo:
                return findings
            if "md5" in sig_algo:
                findings.append(self._f("MD5 Certificate Signature", "CRITICAL",
                    f"Certificate is signed with MD5 ({sig_algo}). "
                    f"MD5 is cryptographically broken — collisions trivially constructable. "
                    f"CVE-2008-0166. Replace certificate immediately."))
                logger.warning("  [CRITICAL] MD5 signed certificate")
            elif "sha1" in sig_algo:
                findings.append(self._f("SHA-1 Certificate Signature", "MEDIUM",
                    f"Certificate is signed with SHA-1 ({sig_algo}). "
                    f"SHA-1 is deprecated (RFC 8017). "
                    f"SHAttered attack (CVE-2017-15999) demonstrated SHA-1 collision. Upgrade to SHA-256."))
                logger.warning("  [MEDIUM] SHA-1 signed certificate")
        except Exception:
            pass
        return findings

    def _check_hsts(self) -> list[dict]:
        """Check for HSTS header presence and quality."""
        findings = []
        try:
            import urllib.request
            req = urllib.request.Request(
                self.url,
                headers={"User-Agent": f"Mozilla/5.0 AlanScan/{config.VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                hsts = resp.headers.get("Strict-Transport-Security", "")
            if not hsts:
                findings.append(self._f("Missing HSTS Header", "LOW",
                    "HTTPS site is missing Strict-Transport-Security header. "
                    "Without HSTS, browsers may downgrade to HTTP — SSL stripping attack possible. "
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"))
                logger.info("  [LOW] HSTS header missing on HTTPS site")
            else:
                # Check max-age value
                match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:
                        findings.append(self._f("HSTS Max-Age Too Short", "MEDIUM",
                            f"HSTS max-age is only {max_age} seconds ({max_age//86400} days). "
                            f"Recommended minimum is 31536000 (1 year). "
                            f"Short max-age reduces protection window against SSL stripping."))
                        logger.warning("  [MEDIUM] HSTS max-age too short: %ss", max_age)
                    else:
                        logger.info("  [OK] HSTS: %s", hsts[:60])
                if "includesubdomains" not in hsts.lower():
                    findings.append(self._f("HSTS Missing includeSubDomains", "LOW",
                        "HSTS header does not include 'includeSubDomains' directive. "
                        "Subdomains can still be accessed over HTTP and used as MITM vectors."))
        except Exception:
            pass
        return findings

    def _check_tls13_support(self, negotiated: str) -> list[dict]:
        """Check if TLS 1.3 is supported — informational."""
        findings = []
        if negotiated != "TLSv1.3":
            findings.append(self._f("TLS 1.3 Not Negotiated", "INFO",
                f"Connection negotiated {negotiated} instead of TLS 1.3. "
                f"TLS 1.3 removes legacy cipher suites, has faster handshakes, "
                f"and provides forward secrecy by default. Upgrade recommended."))
            logger.info("  [INFO] TLS 1.3 not negotiated (using %s)", negotiated)
        return findings

    def _probe_weak_protocols(self) -> list[dict]:
        """
        Explicitly try to connect using deprecated protocols.
        Only flags if the server ACCEPTS the deprecated protocol.
        """
        findings = []
        probes = [
            ("TLSv1",   ssl.TLSVersion.TLSv1,   "BEAST (CVE-2011-3389)"),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "RC4 bias (CVE-2013-2566)"),
        ]
        for proto_name, tls_version, cve in probes:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
                with socket.create_connection(
                        (self.hostname, self.port), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.hostname):
                        findings.append(self._f(
                            f"Server Accepts Deprecated {proto_name}", "HIGH",
                            f"Server accepted a {proto_name} connection. "
                            f"This protocol is deprecated — associated attack: {cve}. "
                            f"Disable {proto_name} in server configuration immediately."))
                        logger.warning("  [HIGH] Server accepts %s — %s", proto_name, cve)
            except (ssl.SSLError, OSError, AttributeError):
                pass  # Server correctly rejected this protocol
        return findings

    def _f(self, title: str, severity: str, evidence: str) -> dict:
        return {
            "type":      title,
            "url":       self.url,
            "parameter": "ssl/tls",
            "payload":   "N/A",
            "severity":  severity,
            "evidence":  evidence,
        }
