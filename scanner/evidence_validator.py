"""
scanner/evidence_validator.py  v2.0.0
=======================================
Enhanced Evidence Validation & False-Positive Reduction Engine.

New in v2.0.0:
- Machine learning-inspired confidence scoring
- Pattern-based false positive detection
- Enhanced SQL injection validation with multiple tiers
- Time-based injection statistical validation
- Response similarity analysis for boolean-blind detection
"""

from __future__ import annotations
import hashlib
import re
import math
from urllib.parse import urlparse, urlunparse

from .scan_logger import logger, coerce_evidence_field

CONFIDENCE_THRESHOLD = 0.35
# Stricter bar for injection-style findings (fewer low-signal reports)
CONFIDENCE_THRESHOLD_INJECTION = 0.48
DEDUP_THRESHOLD = 0.85

# Enhanced SQL error tiers with more signatures
SQLI_ERROR_TIERS = {
    4: [  # EXTREME confidence — database dump evidence
        "column count doesn't match",
        "union select",
        "information_schema",
        "table_name",
        "column_name",
    ],
    3: [  # HIGH confidence — database-specific syntax errors
        "you have an error in your sql syntax",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "ora-01756", "ora-00933",  # Oracle
        "pg::syntaxerror", "postgresql error",  # PostgreSQL
        "sqlite3::exception", "sqlite error",  # SQLite
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "mysql_fetch_array", "mysql_num_rows",
        "supplied argument is not a valid mysql",
    ],
    2: [  # MEDIUM confidence — generic DB indicators (need corroboration for HIGH)
        "sql syntax",
        "warning: mysql",
        "invalid query",
        "sql error",
        "database error",
        "db error",
        "syntax error",
        "unexpected token",
        "parse error",
        "query error",
    ],
    1: [],  # reserved — generic single-keyword SQLi FPs removed
}

# Single-hit noise: never enough alone for a confirmed SQLi report
SQLI_SINGLE_KEYWORD_NOISE = frozenset({
    "database error", "db error", "invalid query", "syntax error",
    "unexpected token", "parse error", "query error",
})

# XSS: avoid ``on\w+=`` — it matches substrings like ``context=`` (``ontext=``).
_XSS_EVENT_HANDLER = (
    r"(?<![a-z])"  # not inside a longer word (e.g. "context")
    r"(?:on(?:click|load|error|focus|blur|submit|mouseover|mouseenter|toggle|start|"
    r"change|input|keydown|keyup|dblclick|scroll|paste|copy|cut|abort|canplay|"
    r"seeked|show|invalid))\s*="
)
# Enhanced XSS validation patterns
XSS_CONFIRMED_PATTERNS = [
    r"<script[^>]*>[^<]*</script>",
    r"(?i)javascript:\s*[^\s'\"<>]+",
    _XSS_EVENT_HANDLER,
    r"<img[^>]+onerror\s*=",
    r"<svg[^>]+onload\s*=",
    r"alert\s*\([^)]*\)",
    r"confirm\s*\([^)]*\)",
    r"prompt\s*\([^)]*\)",
    r"document\.cookie",
    r"window\.location",
]

# Enhanced LFI confirmation signatures
LFI_CONFIRMED_SIGNATURES = {
    "/etc/passwd": [r"root:[x*]:0:0:", r"daemon:[x*]:", r"/bin/bash"],
    "/etc/shadow": [r"\$[0-9]\$", r"root:\$", r":\*:"],
    "win.ini": [r"\[fonts\]", r"\[extensions\]"],
    "boot.ini": [r"\[boot loader\]", r"operating systems"],
    "web.config": [r"<configuration>", r"<system.web>"],
    ".env": [r"DATABASE_URL=", r"API_KEY=", r"SECRET_KEY="],
    "proc/self/environ": [r"PATH=", r"HOME=", r"USER="],
}

TIME_INJECTION_MIN_DELTA = 3.5  # seconds
TIME_INJECTION_BASELINE_VARIANCE = 0.5  # seconds

# Additive signal weights (sum capped at 100 → normalized to 0.0–1.0)
SIGNAL_WEIGHT_REFLECTION = 40
SIGNAL_WEIGHT_ERROR = 40
SIGNAL_WEIGHT_REPEATABILITY = 20


class EvidenceValidator:
    """
    Enhanced post-scan evidence validation engine.
    """

    def __init__(self, findings: list[dict],
                 confidence_threshold: float = CONFIDENCE_THRESHOLD):
        self.findings = findings
        self.confidence_threshold = confidence_threshold
        self._seen_fingerprints: dict[str, int] = {}

    @staticmethod
    def _as_text(val) -> str:
        """Flatten str, list, tuple, or other values into a single string."""
        return coerce_evidence_field(val)

    @staticmethod
    def _as_url_str(val) -> str:
        """First usable URL string; safe if finding stores url as a list."""
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        if isinstance(val, (list, tuple)):
            for x in val:
                if isinstance(x, str) and x.strip():
                    return x
            return EvidenceValidator._as_text(val)
        return str(val)

    @staticmethod
    def _finding_aux(finding: dict) -> dict:
        """Merge scanner ``details`` and ``extra`` blobs for validation."""
        out: dict = {}
        d = finding.get("details")
        e = finding.get("extra")
        if isinstance(d, dict):
            out.update(d)
        if isinstance(e, dict):
            out.update(e)
        return out

    def _signal_confidence_0_1(self, finding: dict) -> float:
        """
        Confidence from structural signals (max 100 points → 0.0–1.0):
        reflection +40, error +40, repeatability +20.
        """
        ev = self._as_text(finding.get("evidence")).lower()
        pay = self._as_text(finding.get("payload")).lower()
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}

        score = 0
        reflected = bool(details.get("reflected"))
        if pay and len(pay) > 1 and pay in ev:
            reflected = True
        if "reflected" in ev or "payload reflected" in ev or "reflected=true" in ev:
            reflected = True
        if reflected:
            score += SIGNAL_WEIGHT_REFLECTION

        err_markers = (
            "sql syntax", "syntax error", "mysql", "mssql", "sqlite",
            "postgresql", "ora-", "odbc", "sql server", "database error",
            "query failed", "warning: mysql", "unclosed quotation",
            "sqlexception", "jdbc", "xml parsing", "parser error",
        )
        if any(m in ev for m in err_markers):
            score += SIGNAL_WEIGHT_ERROR

        repeatable = False
        if ("two" in ev and "payload" in ev) or "payloads_confirmed" in ev:
            repeatable = True
        if details.get("canary_verified") or details.get("payloads_confirmed"):
            repeatable = True
        if "repeated" in ev or "twice" in ev or "confirm" in ev:
            repeatable = True
        if repeatable:
            score += SIGNAL_WEIGHT_REPEATABILITY

        return min(100, score) / 100.0

    def validate(self) -> tuple[list[dict], dict]:
        """Run enhanced validation on all findings."""
        validated = []
        stats = {
            "total_input": len(self.findings),
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0,
            "potential_fp": 0,
            "duplicates": 0,
        }

        for finding in self.findings:
            # Skip chain findings
            if finding.get("chain"):
                finding["validation"] = {
                    "confidence": 1.0,
                    "confidence_label": "HIGH",
                    "is_duplicate": False,
                    "false_positive": False,
                    "validation_note": "Chain finding — validated by components",
                }
                validated.append(finding)
                continue

            # Check for duplicates
            if self._check_duplicate(finding):
                stats["duplicates"] += 1
                continue

            # Enhanced validation
            confidence, notes = self._validate_finding_enhanced(finding)
            ftype_l = self._as_text(finding.get("type")).lower()
            thresh = self.confidence_threshold
            if (
                "xss" in ftype_l
                or "sqli" in ftype_l
                or "sql injection" in ftype_l
                or "command injection" in ftype_l
                or "cmdi" in ftype_l
                or "os command" in ftype_l
            ):
                thresh = CONFIDENCE_THRESHOLD_INJECTION

            is_cmdi = (
                "cmdi" in str(finding.get("type", "")).lower()
                or "command injection" in str(finding.get("type", "")).lower()
            )

            evidence_strength = self._calculate_evidence_strength(finding)
            prov_label = (
                "HIGH" if confidence >= 0.75 else
                "MEDIUM" if confidence >= 0.50 else "LOW"
            )
            if evidence_strength in ("INCONCLUSIVE", "WEAK") and prov_label == "HIGH":
                # Module validators can return strong scores with terse evidence strings.
                if confidence < 0.88:
                    confidence = min(confidence, 0.45)
            elif evidence_strength == "MODERATE" and prov_label == "HIGH" and not is_cmdi:
                confidence = min(confidence, 0.70)

            label = (
                "HIGH" if confidence >= 0.75 else
                "MEDIUM" if confidence >= 0.50 else "LOW"
            )
            false_positive = confidence < thresh

            if false_positive:
                stats["potential_fp"] += 1
            fp_counted = false_positive

            finding["validation"] = {
                "confidence": round(confidence, 3),
                "confidence_label": label,
                "is_duplicate": False,
                "false_positive": false_positive,
                "validation_note": "; ".join(notes[:3]),
                "evidence_strength": evidence_strength,
                "verification_status": (
                    "Confirmed"
                    if confidence >= 0.75 else
                    "Potential / needs manual verification"
                ),
            }

            # Strict CMDi rule:
            # Only keep as a vulnerability when output evidence is present
            # or timing-based execution is confirmed.
            if is_cmdi and not self._is_confirmed_cmdi(finding):
                finding["validation"]["false_positive"] = True
                finding["validation"]["verification_status"] = "Potential / needs manual verification"
                if not fp_counted:
                    stats["potential_fp"] += 1
                continue

            if false_positive:
                continue

            if label == "HIGH":
                stats["high_confidence"] += 1
            elif label == "MEDIUM":
                stats["medium_confidence"] += 1
            else:
                stats["low_confidence"] += 1

            validated.append(finding)

        stats["total_output"] = len(validated)

        # Print enhanced summary
        self._print_validation_summary(stats)

        return validated, stats

    def _validate_finding_enhanced(self, finding: dict) -> tuple[float, list]:
        """Enhanced validation with multiple signals."""
        ftype = self._as_text(finding.get("type")).lower()
        evidence = self._as_text(finding.get("evidence")).lower()
        payload = self._as_text(finding.get("payload")).lower()
        url = self._as_url_str(finding.get("url"))
        notes = []

        confidence = 0.60  # Start with moderate confidence

        # Module-specific validation (avoid matching unrelated types e.g. "mysql" in labels)
        if "sqli" in ftype or "sql injection" in ftype:
            confidence, notes = self._validate_sqli_enhanced(finding, evidence, payload, notes)
        elif "xss" in ftype:
            confidence, notes = self._validate_xss_enhanced(finding, evidence, payload, notes)
        elif "lfi" in ftype or "local file" in ftype or "path traversal" in ftype:
            confidence, notes = self._validate_lfi_enhanced(finding, evidence, payload, notes)
        elif "cmdi" in ftype or "command injection" in ftype or "os command" in ftype:
            confidence, notes = self._validate_cmdi_enhanced(finding, evidence, notes)
        elif "time" in ftype and ("blind" in ftype or "delay" in ftype):
            confidence, notes = self._validate_timing_enhanced(finding, evidence, notes)
        elif "header" in ftype or "cookie" in ftype:
            confidence = 0.95
            notes.append("Deterministic check — high confidence")
        elif "tls" in ftype or "ssl" in ftype or "hsts" in ftype or "cipher" in ftype:
            confidence = 0.95
            notes.append("Deterministic TLS/header check — high confidence")
        elif "waf detected" in ftype or ftype.strip() == "waf detected":
            confidence = 0.98
            notes.append("Security control detected — informational finding")
        elif "directory" in ftype or "exposed path" in ftype:
            confidence, notes = self._validate_directory_enhanced(finding, evidence, url, notes)
        elif "cve" in ftype:
            confidence, notes = self._validate_cve_enhanced(finding, evidence, notes)
        elif "chain" in ftype:
            confidence = 0.98
            notes.append("Attack chain — validated by component findings")

        # Additional confidence signals
        if "200 ok" in evidence or "http 200" in evidence:
            confidence = min(1.0, confidence + 0.05)
            notes.append("HTTP 200 response confirms vulnerability")
        if "critical" in evidence.lower() or "exploit" in evidence.lower():
            confidence = min(1.0, confidence + 0.05)

        # Penalize ambiguous evidence
        if "possible" in evidence or "may be" in evidence or "potential" in evidence:
            confidence = max(0.0, confidence - 0.10)
            notes.append("Ambiguous language in evidence")

        skip_signal = (
            "xss" in ftype
            or "sqli" in ftype
            or "sql injection" in ftype
        )
        signal = self._signal_confidence_0_1(finding)
        if signal > 0 and not skip_signal:
            confidence = min(1.0, max(confidence, signal))
            notes.append(
                f"Signal-based floor: reflection/error/repeatability → {int(signal * 100)}/100"
            )

        return min(1.0, max(0.0, confidence)), notes

    def _validate_sqli_enhanced(self, finding: dict, evidence: str,
                                  payload: str, notes: list) -> tuple[float, list]:
        """
        SQLi confidence: prefer scanner structural proof (two payloads, baselines),
        then tiered errors. Single generic keyword is not enough.
        """
        aux = self._finding_aux(finding)
        ev = evidence.lower()
        pl = payload.lower()

        pc = aux.get("payloads_confirmed")
        if isinstance(pc, list) and len(pc) >= 2:
            notes.append("SQLi: two distinct confirming payloads recorded by scanner")
            return 0.96, notes
        if "two payloads" in ev and ("signature" in ev or "signatures" in ev):
            notes.append("SQLi: dual-payload error signatures described in evidence")
            return 0.94, notes
        if "differential" in ev and ("baseline" in ev or "length" in ev):
            notes.append("SQLi: boolean differential vs baseline")
            return 0.88, notes
        if "baseline" in ev and any(
            x in ev for x in ("delay", "median", "exceeded", "time-based", "delta")
        ):
            notes.append("SQLi: timing/baseline statistical check described")
            return 0.90, notes
        if "independent" in ev and "true" in ev and "false" in ev:
            notes.append("SQLi: independent TRUE/FALSE pairs (boolean blind)")
            return 0.86, notes

        best_tier = 0
        hits: list[tuple[int, str]] = []
        for tier, patterns in sorted(SQLI_ERROR_TIERS.items(), reverse=True):
            if tier <= 1 or not patterns:
                continue
            for pattern in patterns:
                if pattern in ev:
                    hits.append((tier, pattern))
                    best_tier = max(best_tier, tier)

        if best_tier >= 4:
            tier4 = next((p for t, p in hits if t == 4), hits[0][1])
            notes.append(f"SQLi tier-4 schema/UNION indicator: {tier4!r}")
            return 0.97, notes
        if best_tier >= 3:
            notes.append("SQLi tier-3 database-specific error string")
            return 0.93, notes
        if best_tier >= 2:
            tier2_patterns = {p for t, p in hits if t == 2}
            sqlish = any(
                x in pl
                for x in ("'", '"', " or ", " union", "select", "1=1", "sleep", "benchmark")
            )
            if len(hits) >= 2 or len(tier2_patterns) >= 2:
                notes.append("SQLi: corroborated generic DB error indicators")
                return 0.76, notes
            if sqlish:
                notes.append("SQLi: one generic DB indicator + SQL metacharacters in payload")
                return 0.58, notes
            notes.append("SQLi: single generic error token — likely noise")
            return 0.30, notes

        if "boolean" in self._as_text(finding.get("type")).lower():
            if "differential" in ev or "length differs" in ev:
                notes.append("Boolean-blind differential described")
                return 0.84, notes
            if "true condition" in ev and "false condition" in ev:
                return 0.68, notes
            return 0.34, notes

        if "union" in pl:
            if any(x in ev for x in ("column", "null", "mysql", "syntax", "ora-", "postgres")):
                notes.append("UNION probe with structural/sql feedback")
                return 0.80, notes
            return 0.36, notes

        if any(x in pl for x in ("sleep", "delay", "waitfor", "benchmark", "pg_sleep")):
            if "delay" in ev and any(x in ev for x in ("second", "s;", "sec")):
                notes.append("Time-based delay documented in evidence")
                return 0.88, notes
            return 0.32, notes

        if any(n in ev for n in SQLI_SINGLE_KEYWORD_NOISE):
            notes.append("Generic error wording only — no SQLi-specific confirmation")
            return 0.18, notes

        notes.append("Weak SQLi evidence — manual verification recommended")
        return 0.28, notes

    def _validate_xss_enhanced(self, finding: dict, evidence: str,
                                 payload: str, notes: list) -> tuple[float, list]:
        """
        XSS confidence:
        HIGH — executable patterns or script context / stored marker.
        MEDIUM — dangerous attribute / handler context.
        LOW — plain HTML body reflection without execution primitives.
        """
        aux = self._finding_aux(finding)
        ctx = self._as_text(aux.get("context", ""))
        ctx_l = ctx.lower()
        proof = self._as_text(finding.get("response_proof"))
        full = f"{evidence} {proof} {ctx}".lower()
        pl = payload.lower()
        ftype_l = self._as_text(finding.get("type")).lower()

        for pattern in XSS_CONFIRMED_PATTERNS:
            if re.search(pattern, full, re.IGNORECASE):
                notes.append("XSS: executable HTML/JS pattern in response or context")
                return 0.95, notes

        if "javascript context" in ctx_l or (
            "<script" in ctx_l and "critical" in ctx_l
        ):
            notes.append("HIGH: payload reflected in script-executable context")
            return 0.92, notes

        if "attribute context" in ctx_l:
            if any(
                x in pl
                for x in (
                    "onerror",
                    "onload",
                    "onclick",
                    "onfocus",
                    "onmouseover",
                    "javascript:",
                    "<svg",
                    "<iframe",
                )
            ):
                notes.append("MEDIUM-HIGH: handler or JS URL payload in attribute context")
                return 0.78, notes
            notes.append("MEDIUM: attribute context — confirm attribute breakout")
            return 0.52, notes

        if "stored" in ftype_l and "alanscan_stored_" in full:
            notes.append("HIGH: stored XSS marker round-trip")
            return 0.93, notes

        if pl and pl in full:
            if "html body" in ctx_l:
                notes.append(
                    "LOW: reflection in HTML text/body only — not treated as confirmed XSS"
                )
                return 0.26, notes
            notes.append("LOW: reflection without confirmed execution context")
            return 0.34, notes

        notes.append("XSS: insufficient reflection/context evidence")
        return 0.20, notes

    def _validate_lfi_enhanced(self, finding: dict, evidence: str,
                                 payload: str, notes: list) -> tuple[float, list]:
        """Enhanced LFI validation."""
        confidence = 0.50

        for file_hint, patterns in LFI_CONFIRMED_SIGNATURES.items():
            if file_hint in payload.lower():
                for pattern in patterns:
                    if re.search(pattern, evidence, re.IGNORECASE):
                        confidence = 0.99
                        notes.append(f"LFI CONFIRMED: '{file_hint}' content detected")
                        return confidence, notes
                confidence = 0.70
                notes.append(f"LFI payload for '{file_hint}' sent, content not confirmed")

        # Check for traversal patterns
        if "../" in payload or "..%2f" in payload.lower():
            if "root:" in evidence or "system32" in evidence:
                confidence = 0.90
                notes.append("Path traversal with sensitive file content")
            else:
                confidence = 0.65
                notes.append("Path traversal payload sent")

        # Check for PHP wrapper usage
        if "php://" in payload:
            if "base64" in evidence:
                confidence = 0.95
                notes.append("PHP filter wrapper succeeded")
            elif "PD9waHA" in evidence:  # base64 encoded PHP
                confidence = 0.98
                notes.append("PHP source code disclosure via filter")

        return confidence, notes

    def _validate_timing_enhanced(self, finding: dict, evidence: str,
                                    notes: list) -> tuple[float, list]:
        """Enhanced time-based injection validation."""
        confidence = 0.50

        # Extract timing from evidence
        time_match = re.search(r"(\d+\.?\d*)\s*s(?:ec)?", evidence)
        if time_match:
            delay = float(time_match.group(1))

            if delay >= TIME_INJECTION_MIN_DELTA:
                confidence = 0.95
                notes.append(f"Time injection confirmed: {delay:.1f}s delay")
            elif delay >= 2.0:
                confidence = 0.70
                notes.append(f"Marginal delay ({delay:.1f}s) — possible network jitter")
            else:
                confidence = 0.40
                notes.append(f"Insufficient delay ({delay:.1f}s) — likely false positive")
        else:
            confidence = 0.60
            notes.append("Time-based injection reported — no timing data")

        return confidence, notes

    def _cmdi_evidence_blob(self, finding: dict) -> str:
        parts = [
            self._as_text(finding.get("evidence")),
            self._as_text(finding.get("response_proof")),
        ]
        aux = self._finding_aux(finding)
        for k in ("response_snippet", "body_snippet", "stdout", "output"):
            parts.append(self._as_text(aux.get(k)))
        return " ".join(parts).lower()

    def _validate_cmdi_enhanced(self, finding: dict, evidence: str,
                                  notes: list) -> tuple[float, list]:
        """
        CMDi: HIGH only when command-like output (uid/gid/passwd line) or
        strong timing differential is described. Generic words (linux, posix)
        are not confirmation.
        """
        blob = self._cmdi_evidence_blob(finding)
        if not blob.strip():
            blob = evidence.lower()

        if (
            "delta" in blob
            and "baseline" in blob
            and re.search(r"\d+\.?\d*\s*s", blob, re.I)
        ):
            notes.append("CMDi: measurable delay vs baseline (time-based)")
            return 0.88, notes

        if re.search(r"\buid=\d+", blob, re.I):
            notes.append("CMDi CONFIRMED: uid=… pattern in response")
            return 0.97, notes
        if re.search(r"\bgid=\d+", blob, re.I):
            notes.append("CMDi CONFIRMED: gid=… pattern in response")
            return 0.97, notes
        if re.search(r"\bgroups=\d+", blob, re.I):
            notes.append("CMDi CONFIRMED: groups=… pattern in response")
            return 0.96, notes
        if re.search(r"root:[x*!]:0:0:", blob, re.I):
            notes.append("CMDi CONFIRMED: root passwd line in response")
            return 0.97, notes
        if re.search(r"\[fonts\]", blob, re.I):
            notes.append("CMDi CONFIRMED: win.ini [fonts] marker")
            return 0.95, notes
        if re.search(r"nt authority\\", blob, re.I):
            notes.append("CMDi CONFIRMED: Windows NT AUTHORITY string")
            return 0.95, notes
        if re.search(r"volume serial number is", blob, re.I):
            notes.append("CMDi CONFIRMED: Windows volume serial output")
            return 0.93, notes

        # /etc/passwd line shape (not just the path string in a URL)
        if re.search(r"^[a-z_][a-z0-9_-]*[:*]:[^:\n]+:[^:\n]+:[^:\n]+:", blob, re.M):
            notes.append("CMDi: passwd-style line detected in response")
            return 0.94, notes

        # Secondary — shell hints only raise to MEDIUM (validator may still drop)
        weak_output = [
            "command output",
            "shell output",
            "bin/bash",
            "bin/sh",
        ]
        for sig in weak_output:
            if sig in blob:
                notes.append(f"CMDi: possible shell artefact {sig!r} — needs corroboration")
                return 0.52, notes

        payload = self._as_text(finding.get("payload")).lower()
        if any(cmd in payload for cmd in (";id", "&&id", "|id", ";whoami", "$(id)", "`id`")):
            notes.append("CMDi probe sent — no command output validated in response")
            return 0.28, notes

        notes.append("CMDi: insufficient output evidence")
        return 0.22, notes

    def _is_confirmed_cmdi(self, finding: dict) -> bool:
        ftype = self._as_text(finding.get("type")).lower()
        blob = self._cmdi_evidence_blob(finding)

        if re.search(r"\buid=\d+", blob, re.I):
            return True
        if re.search(r"\bgid=\d+", blob, re.I):
            return True
        if re.search(r"\bgroups=\d+", blob, re.I):
            return True
        if re.search(r"root:[x*!]:0:0:", blob, re.I):
            return True
        if re.search(r"\[fonts\]", blob, re.I):
            return True
        if re.search(r"nt authority\\", blob, re.I):
            return True
        if re.search(r"volume serial number is", blob, re.I):
            return True
        if re.search(r"^[a-z_][a-z0-9_-]*[:*]:[^:\n]+:[^:\n]+:[^:\n]+:", blob, re.M):
            return True
        if re.search(
            r"\b(?:daemon|apache|www-data|nobody)\b[^:\n]{0,20}:[x*!]:",
            blob,
            re.I,
        ):
            return True

        # Time-based: require explicit delay magnitude vs baseline
        if "time-based" in ftype or "blind" in ftype:
            if re.search(
                r"\b\d+\.?\d*\s*s(?:ec(?:onds)?)?\b",
                blob,
                re.I,
            ) and ("delay" in blob or "delta" in blob or "median" in blob):
                return True
        if "delta" in blob and "baseline" in blob and (
            "delay" in blob or "second" in blob or re.search(r"\d+\.?\d*\s*s\b", blob)
        ):
            return True

        return False

    def _validate_directory_enhanced(self, finding: dict, evidence: str,
                                       url: str, notes: list) -> tuple[float, list]:
        """Enhanced directory validation."""
        confidence = 0.60
        url = self._as_url_str(url)
        evidence = self._as_text(evidence)

        # Extract HTTP status
        status_match = re.search(r"HTTP\s+(\d{3})", evidence, re.IGNORECASE)
        if status_match:
            status = status_match.group(1)

            if status == "200":
                confidence = 0.95
                notes.append("HTTP 200 — path accessible")
            elif status == "403":
                confidence = 0.85
                notes.append("HTTP 403 — path exists (forbidden)")
            elif status == "401":
                confidence = 0.85
                notes.append("HTTP 401 — authenticated resource exists")
            elif status == "404":
                confidence = 0.20
                notes.append("HTTP 404 — path does not exist")
            elif status in ("301", "302", "307", "308"):
                # Enterprise rule: redirects are not evidence by themselves.
                # Only treat as valid if redirect was validated by module.
                http_meta = finding.get("http", {}) if isinstance(finding.get("http", {}), dict) else {}
                if http_meta.get("redirect_validated"):
                    confidence = 0.80
                    notes.append(f"Redirect validated — resource exists (final HTTP {http_meta.get('redirect_final_status')})")
                else:
                    confidence = 0.15
                    notes.append("Redirect only — ignored unless validated")
            else:
                confidence = 0.65
                notes.append(f"HTTP {status} — path likely exists")

        # Boost for sensitive paths
        sensitive_keywords = ["admin", "config", "backup", ".env", ".git",
                               "phpmyadmin", "wp-admin", "database"]
        url_lower = url.lower() if isinstance(url, str) else self._as_text(url).lower()
        for kw in sensitive_keywords:
            if kw in url_lower:
                confidence = min(1.0, confidence + 0.05)
                notes.append(f"Sensitive path keyword: '{kw}'")
                break

        return confidence, notes

    def _validate_cve_enhanced(self, finding: dict, evidence: str,
                                 notes: list) -> tuple[float, list]:
        """Enhanced CVE validation."""
        confidence = 0.55

        # Check for CVE ID format
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", evidence, re.IGNORECASE)
        version_match = re.search(r"\d+\.\d+[\.\d]*", evidence)

        if cve_match and version_match:
            confidence = 0.92
            notes.append(f"CVE {cve_match.group()} with version {version_match.group()}")
        elif cve_match:
            confidence = 0.80
            notes.append(f"CVE ID present: {cve_match.group()}")
        elif version_match:
            confidence = 0.65
            notes.append(f"Version {version_match.group()} — CVE match unconfirmed")

        # Check for known vulnerable version indicators
        vulnerable_versions = ["2.4.49", "2.4.50", "7.4", "1.3.5"]
        for version in vulnerable_versions:
            if version in evidence:
                confidence = 0.85
                notes.append(f"Known vulnerable version: {version}")

        return confidence, notes

    def _calculate_evidence_strength(self, finding: dict) -> str:
        """Calculate evidence strength rating."""
        evidence = self._as_text(finding.get("evidence"))
        payload = self._as_text(finding.get("payload"))

        # Count strong indicators
        strong_indicators = sum(1 for p in ["confirmed", "detected", "signature",
                                             "exploit", "vulnerable", "critical"]
                                if p in evidence.lower())

        if strong_indicators >= 3:
            return "STRONG"
        elif strong_indicators >= 1:
            return "MODERATE"
        elif payload and len(payload) > 10:
            return "WEAK"
        return "INCONCLUSIVE"

    def _check_duplicate(self, finding: dict) -> bool:
        """Check for duplicates with enhanced fingerprint."""
        ftype = self._as_text(finding.get("type"))
        url = self._normalise_url(finding.get("url"))
        param = self._as_text(finding.get("parameter"))
        key = f"{ftype}|{url}|{param}".lower()
        fp = hashlib.sha256(key.encode()).hexdigest()

        if fp in self._seen_fingerprints:
            return True
        self._seen_fingerprints[fp] = 1
        return False

    def _normalise_url(self, url) -> str:
        """Normalise URL for deduplication (safe for list or str)."""
        url = self._as_url_str(url)
        if not isinstance(url, str):
            url = str(url)
        url = url.strip()
        try:
            p = urlparse(url)
        except Exception:
            return url.rstrip("/").lower()
        netloc = (p.netloc or "").lower()
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        path = (p.path or "/").rstrip("/") or "/"
        q = p.query or ""
        pairs: list[tuple[str, str]] = []
        if q:
            for part in q.split("&"):
                if not part.strip():
                    continue
                if "=" in part:
                    k, v = part.split("=", 1)
                else:
                    k, v = part, ""
                pairs.append((k, v))
            pairs.sort(key=lambda kv: kv[0].lower())
            q = "&".join(f"{k}={v}" if v != "" else k for k, v in pairs)
        frag = ""
        norm = urlunparse((p.scheme.lower() or "http", netloc, path, "", q, frag))
        return norm

    def _print_validation_summary(self, stats: dict) -> None:
        """Log validation summary (colors via scan console handler)."""
        logger.info(f"\n  [VALIDATE] Enhanced validation complete:")
        logger.success(f"    HIGH confidence   : {stats['high_confidence']}")
        logger.warning(f"    MEDIUM confidence : {stats['medium_confidence']}")
        logger.warning(f"    LOW confidence    : {stats['low_confidence']}")
        if stats["potential_fp"]:
            logger.warning(f"    Potential FPs     : {stats['potential_fp']}")
        if stats["duplicates"]:
            logger.info(f"    Duplicates removed: {stats['duplicates']}")
        logger.info(f"    Total findings    : {stats['total_output']}/{stats['total_input']}")