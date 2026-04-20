"""
scanner/scoring_engine.py  v2.1.0
===================================
Enhanced CVSS v3.1 Risk Scoring Engine with temporal/environmental metrics.
"""

from __future__ import annotations
import math
from .scan_logger import logger

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from .cvss31 import calculate_base_score, CVSSVectorError
try:
    from config import get_compliance_mapping, get_mitre_mapping
except ImportError:
    def get_compliance_mapping(t): return {}
    def get_mitre_mapping(t): return {}

CVSS_LABEL_MAP = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "INFO"),
]


def cvss_to_severity(score: float) -> str:
    """Return the standard severity label for a CVSS v3.1 base score."""
    for threshold, label in CVSS_LABEL_MAP:
        if score >= threshold:
            return label
    return "INFO"

# Enhanced temporal metrics
EXPLOIT_MATURITY = {
    "CRITICAL": 1.00,  # Functional exploit publicly available
    "HIGH": 0.97,      # Proof-of-concept exists
    "MEDIUM": 0.94,    # Unproven / theoretical
    "LOW": 0.91,
}

REMEDIATION_LEVEL = {
    "CRITICAL": 0.97,  # Workaround available
    "HIGH": 0.97,
    "MEDIUM": 0.96,    # Official fix available
    "LOW": 0.95,
}

CONFIDENCE_MAP = {
    "HIGH": 1.00,
    "MEDIUM": 0.96,
    "LOW": 0.92,
}

# Environmental metrics
COLLATERAL_DAMAGE = {
    "HIGH": 1.10,
    "MEDIUM": 1.00,
    "LOW": 0.90,
}

TARGET_DISTRIBUTION = {
    "HIGH": 1.00,   # 50-100% of assets affected
    "MEDIUM": 0.90, # 10-49% affected
    "LOW": 0.80,    # <10% affected
}

OWASP_WEIGHT = {
    "A01": 1.10,  # Broken Access Control
    "A02": 1.10,  # Cryptographic Failures
    "A03": 1.05,  # Injection
    "A04": 1.00,  # Insecure Design
    "A05": 0.95,  # Security Misconfiguration
    "A06": 1.00,  # Vulnerable Components
    "A07": 1.05,  # Authentication Failures
    "A08": 1.00,  # Software & Data Integrity
    "A09": 0.90,  # Logging Failures
    "A10": 1.00,  # SSRF
}

# HIGH is reserved for access-control impact or sensitive + clearly restricted behavior.
_SENSITIVE_SURFACE_KEYWORDS = (
    "admin",
    "root",
    "internal",
    "private",
    "api/",
    "/api",
    "graphql",
    "oauth",
    "token",
    "session",
    "login",
    "auth",
    "signin",
    "account",
    "payment",
    "checkout",
    "wallet",
    "transfer",
    "backup",
    ".env",
    "config",
    "secret",
    "credential",
    "password",
    "actuator",
    "debug",
    "upload",
    "execute",
    "sudo",
    "role",
    "permission",
    "tenant",
)

_RESTRICTED_BEHAVIOR_TYPES = (
    "injection",
    "sql",
    "xss",
    "csrf",
    "ssrf",
    "xxe",
    "lfi",
    "cmdi",
    "command injection",
    "deserial",
    "ssti",
    "template injection",
    "race",
    "authentication",
    "authorization",
    "session",
    "jwt",
    "oauth",
    "graphql",
    "idor",
    "insecure direct",
    "access control",
    "broken access",
    "privilege",
    "mass assignment",
    "path traversal",
    "open redirect",
    "request forgery",
    "remote code",
    "rce",
    "file inclusion",
    "upload",
    "misconfig",  # cloud / auth misconfigs with exploit paths
)

_INFO_STYLE_TYPES = (
    "waf",
    "informational",
    "missing hsts",
    "missing security header",
    "information disclosure (header)",
    "cookie without",
    "verbose server",
    "version disclosure",
    "banner",
    "directory listing",
    "exposed path",
    "favicon",
)


class ScoringEngine:
    """
    Enhanced CVSS v3.1 scoring engine.
    """

    def __init__(self, findings: list[dict]):
        self.findings = findings

    @staticmethod
    def _access_control_bypass_confirmed(finding: dict) -> bool:
        """Broken access / IDOR / privilege issues, or explicit scanner flag."""
        t = (finding.get("type") or "").lower()
        if any(
            x in t
            for x in (
                "idor",
                "insecure direct object",
                "broken access control",
                "access control bypass",
                "vertical privilege",
                "horizontal privilege",
                "privilege escalation",
                "authorization bypass",
                "unauthorized access",
                "mass assignment",
            )
        ):
            return True
        ex = finding.get("extra")
        if isinstance(ex, dict) and ex.get("access_control_bypass_confirmed"):
            return True
        return False

    @staticmethod
    def _active_exploit_confirmed(finding: dict) -> bool:
        """Confirmed serious server-side issues (treated as HIGH-eligible proof)."""
        val = finding.get("validation")
        if not isinstance(val, dict):
            return False
        if val.get("verification_status") != "Confirmed":
            return False
        t = (finding.get("type") or "").lower()
        return any(
            x in t
            for x in (
                "sql injection",
                "command injection",
                "remote code",
                "local file inclusion",
                "lfi",
                "path traversal",
                "xxe",
                "server-side request forgery",
                "ssrf",
                "deserialization",
                "ssti",
                "template injection",
            )
        )

    @staticmethod
    def _sensitive_plus_restricted_behavior(finding: dict) -> bool:
        """Sensitive surface in URL/evidence/type plus a restricted-behavior class."""
        url = (finding.get("url") or "").lower()
        ev = (finding.get("evidence") or "").lower()
        t = (finding.get("type") or "").lower()
        blob = f"{url} {ev} {t}"
        if not any(k in blob for k in _SENSITIVE_SURFACE_KEYWORDS):
            return False
        return any(rb in t for rb in _RESTRICTED_BEHAVIOR_TYPES)

    @classmethod
    def _finding_allows_high_severity(cls, finding: dict) -> bool:
        if cls._access_control_bypass_confirmed(finding):
            return True
        if cls._active_exploit_confirmed(finding):
            return True
        if cls._sensitive_plus_restricted_behavior(finding):
            return True
        return False

    def score_all(self) -> list[dict]:
        """Score all findings with enhanced metrics."""
        scored = []
        for finding in self.findings:
            scored.append(self._score_finding_enhanced(finding))

        # Print summary
        self._print_score_summary(scored)
        return scored

    def _score_finding_enhanced(self, finding: dict) -> dict:
        """Enhanced scoring with temporal and environmental factors."""
        f = dict(finding)

        if f.get("chain"):
            f["scoring"] = {
                "base_cvss": f.get("cvss_score", 8.0),
                "temporal_score": 8.0,
                "environmental_score": 8.0,
                "risk_score": self._chain_risk_score(f.get("severity", "HIGH")),
                "severity_band": f.get("severity", "HIGH"),
                "owasp_category": "Multiple",
                "exploitability": "Moderate",
                "note": "Chain finding — severity based on combined attack path",
            }
            return f

        meta = config.get_vuln_meta(f.get("type", ""))
        meta_vector = meta.get("cvss_vector", "N/A")
        base_cvss = float(meta.get("cvss", 5.0))

        # Enterprise consistency: compute base score from vector when possible
        vector_out = meta_vector
        if isinstance(meta_vector, str) and meta_vector.startswith(("CVSS:3.1/", "CVSS:3.0/")):
            try:
                calc = calculate_base_score(meta_vector)
                base_cvss = float(calc.score)
                vector_out = calc.vector
            except CVSSVectorError:
                vector_out = meta_vector

        # Temporal score
        sev = f.get("severity", "MEDIUM")
        conf_key = f.get("validation", {}).get("confidence_label", "MEDIUM")
        temporal = self._temporal_score_enhanced(base_cvss, sev, conf_key)

        # Environmental score
        env_weight = self._environmental_weight(f)
        environmental = min(10.0, round(temporal * env_weight, 1))

        # Anti–severity-inflation: typical reflected/DOM XSS (base ≤ 6.4) should
        # not drift into HIGH solely from environmental heuristics — aligns with
        # NVD-style Reflected XSS (~6.1 → MEDIUM band).
        ftype_l = str(f.get("type", "")).lower()
        if (
            base_cvss <= 6.4
            and "xss" in ftype_l
            and "stored" not in ftype_l
            and "ssti" not in ftype_l
        ):
            environmental = min(float(environmental), 6.9)

        # Final severity band — derived from CVSS, overrides raw scanner label.
        # FIX: scanner modules previously assigned labels independently of CVSS,
        # causing CVSS 5.3 to appear as both HIGH (Missing HSTS) and LOW
        # (Information Disclosure) in the same report.  The CVSS-derived band is
        # now the single source of truth for severity throughout the report.
        severity_band = self._cvss_to_severity(environmental)

        # HIGH only for access-control impact, confirmed serious exploit, or
        # sensitive surface + restricted-behavior finding class; else INFO/LOW.
        if severity_band == "HIGH" and not self._finding_allows_high_severity(f):
            ftype_l = str(f.get("type", "")).lower()
            if any(x in ftype_l for x in _INFO_STYLE_TYPES):
                severity_band = "INFO"
                environmental = min(float(environmental), 3.5)
            else:
                severity_band = "LOW"
                environmental = min(float(environmental), 6.9)

        ex = f.get("extra")
        if isinstance(ex, dict) and ex.get("infrastructure_cookie"):
            severity_band = "INFO"
            environmental = min(float(environmental), 3.5)

        # Normalised risk score (0-100)
        risk_score = int(round(environmental * 10))

        # Propagate the corrected severity label back onto the finding dict so
        # that all downstream consumers (HTML reporter, PDF reporter, reporter.py)
        # see a consistent value.
        f["severity"] = severity_band

        # Exploitability rating
        exploitability = self._exploitability_rating(base_cvss, sev, f)

        # Business impact
        business_impact = self._business_impact(severity_band, f)

        f["scoring"] = {
            "base_cvss": base_cvss,
            "cvss_vector": vector_out if vector_out else "N/A",
            "temporal_score": round(temporal, 1),
            "environmental_score": environmental,
            "risk_score": risk_score,
            "severity_band": severity_band,
            "owasp_category": meta.get("owasp", ""),
            "cwe": meta.get("cwe", ""),
            "exploitability": exploitability,
            "business_impact": business_impact,
            "description": meta.get("description", ""),
            "recommendation": meta.get("recommendation", ""),
            "compliance": get_compliance_mapping(f.get("type", "")),
            "mitre": get_mitre_mapping(f.get("type", "")),
        }

        return f

    def _temporal_score_enhanced(self, base: float, severity: str,
                                   confidence: str) -> float:
        """Enhanced temporal score calculation."""
        E = EXPLOIT_MATURITY.get(severity, 0.94)
        RL = REMEDIATION_LEVEL.get(severity, 0.96)
        RC = CONFIDENCE_MAP.get(confidence, 0.96)

        raw = base * E * RL * RC
        return round(math.ceil(raw * 10) / 10, 1)

    def _environmental_weight(self, finding: dict) -> float:
        """Calculate environmental weight based on context."""
        weight = 1.0

        # Check for sensitive data exposure
        evidence = str(finding.get("evidence", "")).lower()
        if any(kw in evidence for kw in ["password", "credit card", "ssn", "pii"]):
            weight *= 1.15

        # Check for authentication bypass
        if "login" in finding.get("url", "").lower() or "auth" in evidence:
            weight *= 1.10

        # Check for admin access
        if "admin" in finding.get("url", "").lower():
            weight *= 1.10

        # Check for OWASP category weight
        meta = config.get_vuln_meta(finding.get("type", ""))
        owasp = meta.get("owasp", "")
        if len(owasp) >= 3:
            weight *= OWASP_WEIGHT.get(owasp[:3], 1.0)

        return min(1.3, max(0.7, weight))

    def _exploitability_rating(self, cvss: float, severity: str,
                                 finding: dict) -> str:
        """Enhanced exploitability rating."""
        # Base rating from CVSS
        if cvss >= 9.0:
            rating = "Trivial"
        elif cvss >= 7.0:
            rating = "Easy"
        elif cvss >= 4.0:
            rating = "Moderate"
        else:
            rating = "Hard"

        # Adjust based on findings
        evidence = str(finding.get("evidence", "")).lower()
        if "public exploit" in evidence:
            rating = "Trivial"
        elif "proof of concept" in evidence:
            rating = "Easy"
        elif "theoretical" in evidence:
            rating = "Hard"

        # WAF presence reduces exploitability
        if "waf" in finding.get("type", "").lower():
            if rating == "Easy":
                rating = "Moderate"
            elif rating == "Trivial":
                rating = "Easy"

        return rating

    def _business_impact(self, severity: str, finding: dict) -> str:
        """Estimate business impact in monetary terms."""
        impacts = {
            "CRITICAL": "Immediate revenue impact ($100K+), customer churn, regulatory fines",
            "HIGH": "Significant revenue impact ($50K+), reputation damage, compliance violation",
            "MEDIUM": "Moderate impact ($10K+), operational disruption",
            "LOW": "Minor impact (<$5K), informational risk",
        }

        base_impact = impacts.get(severity, "Unknown impact")

        # Enhance with specific context
        evidence = str(finding.get("evidence", "")).lower()
        if "pii" in evidence or "personal data" in evidence:
            base_impact += "; GDPR fines up to €20M or 4% of global turnover"
        if "payment" in evidence or "credit card" in evidence:
            base_impact += "; PCI-DSS violation ($5K-100K monthly fines)"
        if "health" in evidence or "phi" in evidence:
            base_impact += "; HIPAA violation ($50K-1.5M per violation)"

        return base_impact

    def _chain_risk_score(self, severity: str) -> int:
        """Convert chain severity to risk score."""
        return {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 30}.get(severity, 50)

    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity band."""
        return cvss_to_severity(cvss)

    def _print_score_summary(self, scored_findings: list[dict]) -> None:
        """Print scoring summary."""
        counts = {}
        for f in scored_findings:
            band = f.get("scoring", {}).get("severity_band", f.get("severity", "INFO"))
            counts[band] = counts.get(band, 0) + 1
        logger.info(
            "Risk scoring complete",
            extra={"kind": "SCORE_SUMMARY", "counts": counts},
        )