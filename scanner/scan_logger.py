"""
scanner/scan_logger.py
======================
Structured logging for AlanScan: orchestration emits events + fields;
console formatting lives in ``StructuredConsoleHandler``. JSONL file I/O is
only in ``StructuredLogger`` (not inside logging handlers).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import datetime
import uuid
from typing import Any, Optional

from . import observability
from .events import ScanEventKind
from .schema import ENVELOPE_SCHEMA_ID, EVENT_VERSION, SCHEMA_VERSION

# SUCCESS sits between INFO (20) and WARNING (30) for colored console output.
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

# ── Optional colorama (CLI; never required for core logic) ──
try:
    from colorama import Fore, Style, init as _colorama_init  # type: ignore

    _COLORAMA_OK = True
except ImportError:
    _COLORAMA_OK = False

    class _DummyColor:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _DummyColor()  # type: ignore[misc, assignment]
    Style = _DummyColor()  # type: ignore[misc, assignment]

    def _colorama_init(**_kwargs: Any) -> None:
        pass


def init_terminal_colors() -> None:
    """Call once at application entry (e.g. AlanScan). Safe if colorama is missing."""
    if _COLORAMA_OK:
        _colorama_init(autoreset=True)


def _level_from_config() -> int:
    """Resolve SCAN_LOG_LEVEL from config (default INFO)."""
    try:
        import config as _cfg

        name = str(getattr(_cfg, "SCAN_LOG_LEVEL", "INFO")).upper().strip()
    except Exception:
        name = "INFO"
    return getattr(logging, name, logging.INFO)


def _format_structured_cli(message: str, ascan: dict, levelno: int) -> str:
    """
    Turn a semantic message + structured fields into human CLI lines.
    Controller must not build these strings—only pass ``extra`` / ``ascan``.
    """
    K = ScanEventKind
    kind = ascan.get("kind")

    if kind == K.MODULE_START.value:
        title = str(ascan.get("title", message))
        bar = "═" * 60
        return f"\n  ╔{bar}╗\n  ║  {title:<58}║\n  ╚{bar}╝"

    if kind == K.MODULE_PHASE_TIMER.value:
        return f"  [TIMER] {ascan.get('phase', message)}: {float(ascan.get('seconds', 0)):.2f}s"

    if kind == K.CRAWL_URLS_DISCOVERED.value:
        n = int(ascan.get("count", 0))
        return f"  [i] {n} URL(s) discovered"

    if kind == K.SCAN_ABORTED.value:
        return f"\n  [!] Scan aborted: {ascan.get('error', message)}"

    if kind in (K.MODULE_FAILED.value, K.NETWORK_MODULE_FAILED.value):
        return f"  {ascan.get('module', 'module')} failed: {ascan.get('error', '')}"

    if kind == K.THROTTLE_CIRCUIT_SKIP.value:
        return (
            f"  [SKIP] {ascan.get('module', '')} — "
            f"{ascan.get('reason', 'circuit-breaker or budget hit')}"
        )

    if kind == K.HTTP_MODULE_FAILED.value:
        return f"  {ascan.get('module', '')} failed: {ascan.get('error', '')}"

    if kind == K.AUTH_SESSION_ESTABLISHED.value:
        return "  [AUTH] Session established"

    if kind == K.AUTH_AUDIT_FAILED.value:
        return f"  [!] Auth audit failed: {ascan.get('error', '')}"

    if kind == K.WAF_DETECTION_FAILED.value:
        return f"  [!] WAF detection failed: {ascan.get('error', '')}"

    if kind == K.EVIDENCE_COLLECTION_FAILED.value:
        return f"  [EV] Evidence collection failed: {ascan.get('error', '')}"

    if kind == K.AI_ANALYSIS_FAILED.value:
        return f"  [!] AI analysis failed: {ascan.get('error', '')}"

    if kind == K.REPORT_SAVE_FAILED.value:
        fmt = str(ascan.get("format", "") or "")
        err = str(ascan.get("error", "") or "")
        detail = err or fmt or "unknown error"
        return f"  [ERROR] Report generation failed: {detail}"

    if kind == K.SCAN_COMPLETE.value:
        ds = float(ascan.get("duration_s", 0))
        sid = ascan.get("scan_id", "")
        rep = (
            str(ascan.get("report_save_summary_display", "")).strip()
            or str(ascan.get("report_save_summary", "")).strip()
        )
        out_dir = str(ascan.get("report_output_dir", "") or "").strip()
        if rep:
            parts = [
                f"\n  [✓] Scan completed in {ds:.2f}s",
                f"  {rep}",
            ]
            if out_dir:
                parts.append(f"  Output directory: {out_dir}")
            parts.append(f"      └── {sid}_events.jsonl  (structured log)")
            return "\n".join(parts)
        return (
            f"\n  [✓] Scan completed in {ds:.2f}s\n"
            "  [✓] Reports saved to output/\n"
            "      ├── alanscan_*.html  (interactive dashboard)\n"
            "      ├── alanscan_*.pdf   (professional print)\n"
            "      ├── alanscan_*.json  (machine-readable)\n"
            f"      └── {sid}_events.jsonl  (structured log)"
        )

    if kind == K.GUARD_SUMMARY_HEADER.value:
        return "\n  ─── Scan Budget Summary ───────────────────────────"

    if kind == K.GUARD_SUMMARY_HTTP_TOTAL.value:
        return f"  Total HTTP reqs : {ascan.get('count', 0)}"

    if kind == K.GUARD_SUMMARY_BUDGET.value:
        return f"  Budget exhausted: {ascan.get('exhausted', False)}"

    if kind == K.GUARD_SUMMARY_MODULE.value:
        tripped = bool(ascan.get("tripped"))
        tag = " [TRIPPED]" if tripped else ""
        return (
            f"  Module {str(ascan.get('module', '')):<18}: "
            f"{ascan.get('requests', 0)} reqs, "
            f"error-rate={float(ascan.get('error_rate', 0)):.0%}{tag}"
        )

    if kind == K.GUARD_SUMMARY_FOOTER.value:
        return "  ────────────────────────────────────────────────────"

    if kind == K.MODULE_PHASE_ERROR.value:
        return f"  [!] {ascan.get('phase', '')} error: {ascan.get('error', '')}"

    if kind == K.FINDING_REJECTED.value:
        return (
            f"  [i] Skipping invalid finding ({ascan.get('reason', '')}) "
            f"module={ascan.get('module', '')}"
        )

    # Generic vulnerability-style line (scanners / pentest engine)
    if ascan.get("severity") and ascan.get("type") and ascan.get("url") is not None:
        param = ascan.get("parameter")
        pfx = f" [{param}]" if param not in (None, "", "N/A") else ""
        return f"  [{ascan['severity']}] {ascan['type']}{pfx} → {ascan['url']}"

    if kind == K.HEADERS_MISSING_GROUP.value:
        return (
            f"  [{ascan.get('severity', 'LOW')}] Missing security headers: "
            f"{ascan.get('header_names', '')}"
        )

    if kind == K.HEADERS_VERSION_DISCLOSURE.value:
        return (
            f"  [LOW] Version disclosure: {ascan.get('header', '')}: "
            f"{ascan.get('value', '')}"
        )

    if kind == K.HEADERS_CSP_ISSUE.value:
        return f"  [MEDIUM] CSP issue: {ascan.get('issue', '')}"

    if kind == K.HEADERS_FETCH_FAILED.value:
        return f"  [!] Could not fetch {ascan.get('url', '')}: {ascan.get('error', '')}"

    if kind == K.SCAN_METRICS.value:
        return (
            f"  [i] Scan metrics: modules "
            f"{ascan.get('successful_modules', 0)}/{ascan.get('total_modules', 0)} ok, "
            f"failures={ascan.get('failed_modules', 0)}, "
            f"findings={ascan.get('total_findings', 0)}, "
            f"duration={float(ascan.get('scan_duration', 0)):.2f}s"
        )

    if kind == K.SCAN_START.value:
        return f"  [i] Scan started (scan_id={ascan.get('scan_id', '')})"

    _fcm = getattr(K, "FINDING_COUNT_MISMATCH", None)
    _fcm_val = _fcm.value if _fcm is not None else "finding_count_mismatch"
    if kind == _fcm_val:
        if "post_pipeline_findings_count" in ascan:
            return (
                f"  [WARN] Finding count mismatch: post_pipeline="
                f"{ascan.get('post_pipeline_findings_count')}, "
                f"final={ascan.get('final_findings_count')}"
            )
        if "validated_findings_count" in ascan:
            return (
                f"  [WARN] Finding count mismatch: validated="
                f"{ascan.get('validated_findings_count')}, "
                f"final={ascan.get('final_findings_count')}"
            )
        return f"  [WARN] Finding count mismatch ({ascan.get('phase', '')})"

    # Fallback: message plus compact fields (DEBUG shows full JSON)
    base = f"  {message}".rstrip()
    if ascan:
        skip = {"kind", "severity", "type", "url", "parameter"}
        rest = {k: v for k, v in ascan.items() if k not in skip}
        if rest and levelno <= logging.DEBUG:
            base += " " + json.dumps(rest, default=str)[:500]
    return base


def _ansi_for_structured(text: str, levelno: int, ascan: dict) -> str:
    """ANSI prefix from level + optional severity in structured fields."""
    if ascan.get("kind") == ScanEventKind.GUARD_SUMMARY_MODULE.value:
        if ascan.get("tripped"):
            return str(getattr(Fore, "RED", ""))
        return str(getattr(Fore, "GREEN", ""))
    sev = str(ascan.get("severity", "")).upper()
    # Severity ANSI mapping (aligned with industry conventions):
    # CRITICAL → RED + BRIGHT
    # HIGH     → YELLOW + BRIGHT (orange-like)
    # MEDIUM   → YELLOW
    # LOW      → GREEN
    # INFO     → BLUE / dim white
    if sev == "CRITICAL":
        return str(getattr(Fore, "RED", "")) + str(getattr(Style, "BRIGHT", ""))
    if sev == "HIGH":
        return str(getattr(Fore, "YELLOW", "")) + str(getattr(Style, "BRIGHT", ""))
    if sev == "MEDIUM":
        return str(getattr(Fore, "YELLOW", ""))
    if sev == "LOW":
        return str(getattr(Fore, "GREEN", ""))
    if sev == "INFO":
        return str(getattr(Fore, "BLUE", "")) or str(getattr(Fore, "WHITE", ""))

    m = text.lstrip()
    if levelno == SUCCESS_LEVEL or "✓" in m or "[OK]" in m:
        return str(getattr(Fore, "GREEN", ""))
    if levelno >= logging.ERROR or "aborted" in m.lower():
        return str(getattr(Fore, "RED", "")) + str(getattr(Style, "BRIGHT", ""))
    if levelno >= logging.WARNING or "[!]" in m or "SKIP" in m or "TRIPPED" in m:
        return str(getattr(Fore, "YELLOW", ""))
    if "[TIMER]" in m:
        return str(getattr(Fore, "WHITE", ""))
    if "[AUTH]" in m:
        return str(getattr(Fore, "GREEN", ""))
    if "╔" in m or "╚" in m or "Scan Budget" in m:
        return str(getattr(Fore, "CYAN", "")) + str(getattr(Style, "BRIGHT", ""))
    if "[i]" in m or "[*]" in m:
        return str(getattr(Fore, "CYAN", ""))
    if levelno <= logging.DEBUG:
        return str(getattr(Fore, "WHITE", ""))
    return ""


def _ansi_for_plain_message(msg: str, levelno: int) -> str:
    """Legacy scanners: color by tags in plain message."""
    m = msg.lstrip()
    bracket_tag = re.match(r"\[([A-Za-z0-9_]+)\]", m)
    tag = bracket_tag.group(1).upper() if bracket_tag else ""
    if tag == "CRITICAL":
        return str(getattr(Fore, "RED", "")) + str(getattr(Style, "BRIGHT", ""))
    if tag == "HIGH":
        return str(getattr(Fore, "YELLOW", "")) + str(getattr(Style, "BRIGHT", ""))
    if tag == "MEDIUM":
        return str(getattr(Fore, "YELLOW", ""))
    if tag == "LOW":
        return str(getattr(Fore, "GREEN", ""))
    if tag == "INFO":
        return str(getattr(Fore, "BLUE", "")) or str(getattr(Fore, "WHITE", ""))
    if levelno == SUCCESS_LEVEL:
        return str(getattr(Fore, "GREEN", ""))
    if m.startswith("[OK]"):
        return str(getattr(Fore, "GREEN", ""))
    if m.startswith("[*]") or m.startswith("[i]"):
        return str(getattr(Fore, "CYAN", ""))
    if m.startswith("[!]"):
        return str(getattr(Fore, "YELLOW", ""))
    if m.startswith("[+]"):
        return str(getattr(Fore, "WHITE", ""))
    if m.startswith("[EV]"):
        return str(getattr(Fore, "CYAN", ""))
    if "LIVE CHAIN" in msg:
        if "CRITICAL" in msg:
            return str(getattr(Fore, "LIGHTRED_EX", "")) + str(getattr(Style, "BRIGHT", ""))
        return str(getattr(Fore, "YELLOW", ""))
    if m.lstrip().startswith("Impact:"):
        return str(getattr(Fore, "WHITE", ""))
    if m.startswith("[TLS]"):
        low = m.lower()
        if "no weak ciphers" in low or "negotiated:" in low:
            return str(getattr(Fore, "GREEN", ""))
        if "weak cipher" in low or "failed" in low or "enumeration failed" in low:
            return str(getattr(Fore, "RED", ""))
        return str(getattr(Fore, "CYAN", ""))
    if m.startswith("[TIMER]"):
        return str(getattr(Fore, "WHITE", ""))
    if m.startswith("[AUTH]"):
        return str(getattr(Fore, "GREEN", ""))
    if "Scan aborted" in msg:
        return str(getattr(Fore, "RED", "")) + str(getattr(Style, "BRIGHT", ""))
    if "[✓]" in msg or "Scan completed" in msg or "Reports saved" in msg or "├──" in msg or "└──" in msg:
        return str(getattr(Fore, "GREEN", ""))
    if "╔" in msg or "╚" in msg:
        return str(getattr(Fore, "CYAN", "")) + str(getattr(Style, "BRIGHT", ""))
    if "─── Scan Budget" in msg or "Scan Budget Summary" in msg:
        return str(getattr(Fore, "CYAN", ""))
    if "Total HTTP reqs" in msg or "Budget exhausted" in msg:
        return str(getattr(Fore, "WHITE", ""))
    if levelno >= logging.ERROR:
        return str(getattr(Fore, "RED", ""))
    if levelno >= logging.WARNING:
        return str(getattr(Fore, "YELLOW", ""))
    return ""


class StructuredConsoleHandler(logging.StreamHandler):
    """Console handler: structured ``ascan`` → formatted lines; plain messages unchanged."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            raw_msg = record.getMessage()
            ascan = getattr(record, "ascan", None)
            if isinstance(ascan, dict) and ascan:
                text = _format_structured_cli(raw_msg, ascan, record.levelno)
                prefix = _ansi_for_structured(text, record.levelno, ascan)
            else:
                text = self.format(record)
                prefix = _ansi_for_plain_message(text, record.levelno)

            for i, line in enumerate(text.splitlines()):
                p = prefix if i == 0 else ""
                self.stream.write(p + line + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


class ProfessionalScanFileFormatter(logging.Formatter):
    """Plain timestamped lines for ``scan.log`` (no ANSI); mirrors structured CLI text."""

    def format(self, record: logging.LogRecord) -> str:
        ascan = getattr(record, "ascan", None)
        raw_msg = record.getMessage()
        if isinstance(ascan, dict) and ascan:
            asc_fmt = dict(ascan)
            plain = str(asc_fmt.get("report_save_summary_plain", "")).strip()
            if plain:
                asc_fmt["report_save_summary_display"] = plain
            text = _format_structured_cli(raw_msg, asc_fmt, record.levelno)
            text = " ".join(line.strip() for line in text.splitlines() if line.strip())
        else:
            text = raw_msg
        lvl = record.levelname
        if record.levelno == SUCCESS_LEVEL:
            lvl = "INFO"
        ts = self.formatTime(record, self.datefmt)
        return f"[{ts}] [{lvl}] {text}"


_SCAN_PROFESSIONAL_LOG_ATTR = "_alanscan_professional_scan_log"


def attach_professional_scan_log(output_dir: str) -> None:
    """
    Append ``scan.log`` under the scan output directory with timestamped INFO/WARN/ERROR lines.
    Does not change console handlers except via ``configure_scanner_console_logging`` (which
    preserves this handler).
    """
    log = logging.getLogger("scanner")
    for h in list(log.handlers):
        if getattr(h, _SCAN_PROFESSIONAL_LOG_ATTR, False):
            log.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
    try:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "scan.log")
        fh = logging.FileHandler(path, encoding="utf-8", mode="a")
        setattr(fh, _SCAN_PROFESSIONAL_LOG_ATTR, True)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            ProfessionalScanFileFormatter(datefmt="%Y-%m-%d %H:%M:%S"),
        )
        log.addHandler(fh)
    except Exception:
        # Logging must never break the scan.
        pass


def configure_scanner_console_logging(level: int | None = None) -> None:
    """
    Route ``scanner`` logger to structured console handler.
    If ``level`` is None, uses ``config.SCAN_LOG_LEVEL``.
    """
    init_terminal_colors()
    log = logging.getLogger("scanner")
    lvl = level if level is not None else _level_from_config()
    log.setLevel(lvl)
    if getattr(log, "_alanscan_console_configured", False):
        return
    for h in list(log.handlers):
        if isinstance(h, StructuredConsoleHandler):
            log.removeHandler(h)
    h = StructuredConsoleHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    log.propagate = False
    log._alanscan_console_configured = True  # type: ignore[attr-defined]


def coerce_evidence_field(val: Any) -> str:
    """
    Flatten finding/evidence field values to a plain string so callers can safely
    use startswith, ``in``, slicing, regex, and HTML escaping.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, (list, tuple)):
        parts: list[str] = []
        for x in val:
            if x is None:
                continue
            t = coerce_evidence_field(x)
            if t:
                parts.append(t)
        return " ".join(parts)
    if isinstance(val, dict):
        return str(val)
    return str(val)


def safe_str(value: Any) -> str:
    """
    Safe string helper for production rendering.

    Guarantees a non-null string return value (None -> "") and flattens
    list/tuple evidence values via ``coerce_evidence_field``.
    """
    return coerce_evidence_field(value)


# ── Finding contract (orchestrator validation) ───────────────────────────────

REQUIRED_FINDING_KEYS = ("type", "url", "severity", "evidence")
ALLOWED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


def _parse_validated_finding_core(f: dict) -> tuple[Optional[tuple[str, str, str, str, str]], str]:
    """
    Validate and coerce core string fields shared by chain and standard findings.
    Returns ((type, severity, url, evidence, parameter), "") or (None, reason_code).
    """
    sev = str(coerce_evidence_field(f.get("severity", ""))).upper().strip()
    if sev not in ALLOWED_SEVERITIES:
        return None, "invalid_severity"
    typ = str(coerce_evidence_field(f.get("type", ""))).upper().strip()
    if not typ:
        return None, "empty_type"
    url = str(coerce_evidence_field(f.get("url", ""))).strip()
    if not url:
        return None, "empty_url"
    ev = str(coerce_evidence_field(f.get("evidence", ""))).strip()
    if not ev:
        return None, "empty_evidence"
    param = str(coerce_evidence_field(f.get("parameter", "N/A"))).strip() or "N/A"
    return (typ, sev, url, ev, param), ""


def _apply_parsed_core_to_finding(base: dict, core: tuple[str, str, str, str, str]) -> dict:
    typ, sev, url, ev, param = core
    out = dict(base)
    out["type"] = typ
    out["severity"] = sev
    out["url"] = url
    out["evidence"] = ev
    out["parameter"] = param
    return out


def normalize_finding_row(f: dict) -> tuple[Optional[dict], str]:
    """
    Validate and normalize a finding to the strict schema:

    - type, severity: UPPERCASE strings
    - url, evidence: non-empty strings (after coercion)
    - parameter: string, default \"N/A\"
    - severity ∈ ALLOWED_SEVERITIES

    Chain findings (chain: True) use the same severity / evidence rules.
    Returns (normalized_dict, \"\") or (None, reason_code).
    """
    if not isinstance(f, dict):
        return None, "not_dict"

    if f.get("chain"):
        out = dict(f)
        core, err = _parse_validated_finding_core(out)
        if core is None:
            return None, err
        return _apply_parsed_core_to_finding(out, core), ""

    for k in REQUIRED_FINDING_KEYS:
        if k not in f:
            return None, f"missing_{k}"
        if f[k] is None:
            return None, f"null_{k}"

    core, err = _parse_validated_finding_core(f)
    if core is None:
        return None, err
    return _apply_parsed_core_to_finding(f, core), ""


def validate_standard_finding(f: dict) -> tuple[bool, str]:
    """Backward-compatible bool API; prefer ``normalize_finding_row`` for the dict."""
    nf, err = normalize_finding_row(f)
    return nf is not None, err


def enrich_finding_record(
    f: dict,
    *,
    scan_id: str,
    module: str,
) -> dict:
    """
    Attach required production fields to a finding.

    JSONL / report safety requirements:
    - NO None in required string fields
    - Always include `confidence` (float, defaults to 0.0)
    """
    out = dict(f)
    if not out.get("finding_id"):
        out["finding_id"] = str(uuid.uuid4())
    out["scan_id"] = scan_id
    out["module"] = (module or out.get("module") or "unknown").strip() or "unknown"
    out["schema_version"] = SCHEMA_VERSION
    out["event_version"] = EVENT_VERSION
    # Required payload fields: never emit None.
    out["type"] = safe_str(out.get("type", "")) or "UNKNOWN"
    out["severity"] = safe_str(out.get("severity", "")) or "INFO"
    out["url"] = safe_str(out.get("url", "")) or "N/A"
    out["parameter"] = safe_str(out.get("parameter", "N/A")) or "N/A"
    out["evidence"] = safe_str(out.get("evidence", "")) or "N/A"
    # Confidence: prefer validation.confidence if present.
    v = out.get("validation")
    conf = None
    if isinstance(v, dict):
        conf = v.get("confidence", None)
    if conf is None:
        conf = out.get("confidence", None)
    try:
        out["confidence"] = float(conf) if conf is not None else 0.0
    except Exception:
        out["confidence"] = 0.0
    return out


def enrich_chain_record(
    f: dict,
    *,
    scan_id: str,
    related_finding_ids: list[str] | None = None,
    module: str = "VULNERABILITY CHAINING",
) -> dict:
    """Attach ``chain_id``, ``scan_id``, ``related_finding_ids``, and version fields."""
    out = dict(f)
    if not out.get("chain_id"):
        out["chain_id"] = str(uuid.uuid4())
    out["scan_id"] = scan_id
    out.setdefault("module", module)
    out["schema_version"] = SCHEMA_VERSION
    out["event_version"] = EVENT_VERSION
    if related_finding_ids is not None:
        out["related_finding_ids"] = [str(x) for x in related_finding_ids if x]
    else:
        out.setdefault("related_finding_ids", [])
    return out


class AlanScanLogger:
    """
    Facade: ``info(message, extra={...})`` attaches structured fields on the record
    as ``ascan`` (safe for LogRecord). Use ``from scanner.scan_logger import logger``.
    """

    def __init__(self) -> None:
        self._log = logging.getLogger("scanner")

    def _ensure(self) -> None:
        log = logging.getLogger("scanner")
        if not getattr(log, "_alanscan_console_configured", False):
            try:
                configure_scanner_console_logging()
            except Exception:
                pass

    def _merge_extra(self, kwargs: dict[str, Any]) -> None:
        extra = kwargs.pop("extra", None)
        if extra is not None:
            asc = dict(extra)
            k = asc.get("kind")
            if isinstance(k, ScanEventKind):
                asc["kind"] = k.value
            asc.setdefault("event_id", str(uuid.uuid4()))
            sid = observability.get_scan_id()
            if sid:
                asc.setdefault("scan_id", sid)
            mod = observability.get_module()
            if mod:
                asc.setdefault("module", mod)
            asc.setdefault("schema_version", SCHEMA_VERSION)
            asc.setdefault("event_version", EVENT_VERSION)
            kwargs["extra"] = {"ascan": asc}

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._ensure()
        self._merge_extra(kwargs)
        self._log.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._ensure()
        self._merge_extra(kwargs)
        self._log.info(msg, *args, **kwargs)

    def success(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._ensure()
        self._merge_extra(kwargs)
        self._log.log(SUCCESS_LEVEL, msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._ensure()
        self._merge_extra(kwargs)
        self._log.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._ensure()
        self._merge_extra(kwargs)
        self._log.error(msg, *args, **kwargs)


logger = AlanScanLogger()


class StructuredLogger:
    """
    Append-only JSON Lines persistence for scan events and metrics.
    Console logging is separate (``AlanScanLogger``); no log handler writes here.
    """

    def __init__(self, scan_id: str, output_dir: str = "output", echo: bool = False):
        self.scan_id = scan_id
        self.output_dir = output_dir
        self.echo = echo
        os.makedirs(output_dir, exist_ok=True)
        safe_fn = str(scan_id).replace(os.sep, "_").replace("/", "_")
        self.path = os.path.join(output_dir, f"{safe_fn}_events.jsonl")
        self._seq = 0
        # Ensure JSONL file is never empty even if a scan aborts early.
        self._write("JSONL_INIT", {"message": "Structured logging initialised"}, module="")
        attach_professional_scan_log(output_dir)

    @staticmethod
    def _sanitize_payload(obj: Any) -> Any:
        """
        Recursively remove None values from payloads.

        Requirement: JSONL is the source of truth; payload MUST NOT contain None.
        """
        if obj is None:
            return ""
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                ks = safe_str(k) if k is not None else ""
                out[ks] = StructuredLogger._sanitize_payload(v)
            return out
        if isinstance(obj, list):
            return [StructuredLogger._sanitize_payload(x) for x in obj]
        if isinstance(obj, tuple):
            return [StructuredLogger._sanitize_payload(x) for x in obj]
        return obj

    def log_scan_start(self, target: str = "") -> None:
        self._write(
            "SCAN_START",
            {"target": safe_str(target)},
            module="",
        )

    def log_scan_complete(self) -> None:
        self._write("SCAN_COMPLETE", {}, module="")

    def log_scan_aborted(self, error: str) -> None:
        self._write(
            "SCAN_ABORTED",
            {"error": safe_str(error)},
            module="controller",
        )

    def log_module_complete(
        self,
        module_name: str,
        *,
        duration_s: float,
        findings_count: int,
        status: str,
    ) -> None:
        self._write(
            "MODULE_COMPLETE",
            {
                "module_name": safe_str(module_name),
                "duration": round(float(duration_s), 3),
                "findings_count": int(findings_count),
                "status": safe_str(status),
            },
            module=safe_str(module_name),
        )

    def log_module_failed(self, module_name: str, error: str) -> None:
        self._write(
            "MODULE_FAILED",
            {"module_name": safe_str(module_name), "error": safe_str(error)},
            module=safe_str(module_name),
        )

    def log_finding(self, finding: dict) -> None:
        mod = ""
        if isinstance(finding, dict):
            mod = str(finding.get("module") or "")
        self._write("finding", finding, module=mod)

    def log_findings(self, findings: list[dict]) -> None:
        for f in findings:
            self.log_finding(f)

    def log_chain(self, chain: dict) -> None:
        mod = ""
        if isinstance(chain, dict):
            mod = str(chain.get("module") or "")
        # Emit both legacy `chain` and required `chain_detected` event types.
        # Some consumers (LogConverter) still expect `chain`.
        self._write("chain_detected", chain, module=mod)
        self._write("chain", chain, module=mod)

    def log_state(self, old_state: str, new_state: str) -> None:
        self._write(
            "state_change",
            {
                "from": old_state,
                "to": new_state,
                "schema_version": SCHEMA_VERSION,
                "event_version": EVENT_VERSION,
            },
            module="",
        )

    def log_metric(self, name: str, value: Any, unit: str = "", module: str = "") -> None:
        p: dict[str, Any] = {
            "name": name,
            "value": value,
            "unit": unit,
            "schema_version": SCHEMA_VERSION,
            "event_version": EVENT_VERSION,
        }
        if module:
            p["module"] = module
        self._write("metric", p, module=module)

    def log_error(self, message: str, module: str = "") -> None:
        # Map log_error to MODULE_FAILED for JSONL stability.
        self.log_module_failed(module_name=module or "unknown", error=message)

    def log_phase_start(self, phase: str) -> None:
        self._write(
            "MODULE_START",
            {"module_name": safe_str(phase)},
            module=safe_str(phase),
        )

    def log_phase_end(
        self,
        phase: str,
        duration_s: float,
        finding_count: int,
        status: str = "",
    ) -> None:
        self._write(
            "MODULE_PHASE_TIMER",
            {
                "module_name": safe_str(phase),
                "duration": round(float(duration_s), 3),
                "findings_count": int(finding_count),
                "status": safe_str(status) if status else "",
            },
            module=safe_str(phase),
        )

    def log_scan_metrics(self, metrics: dict) -> None:
        """Persist final scan counters and duration to JSONL."""
        m = dict(metrics)
        m.setdefault("schema_version", SCHEMA_VERSION)
        m.setdefault("event_version", EVENT_VERSION)
        self._write("SCAN_METRICS", m, module="")

    def _write(self, event_type: str, payload: Any, module: str = "") -> None:
        self._seq += 1
        now = time.time()
        mod = safe_str(module or "")
        if isinstance(payload, dict):
            mod = mod or safe_str(payload.get("module") or "")
        record = {
            "schema": ENVELOPE_SCHEMA_ID,
            "schema_version": SCHEMA_VERSION,
            "event_version": EVENT_VERSION,
            "event_id": str(uuid.uuid4()),
            "event": safe_str(event_type),
            "scan_id": self.scan_id,
            "module": mod,
            "seq": self._seq,
            "timestamp": now,
            "ts_iso": datetime.datetime.utcfromtimestamp(now).isoformat() + "Z",
            "payload": self._sanitize_payload(payload),
        }

        line = json.dumps(record, default=str)
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception as exc:
            # Never silently drop events: record failure to console structured logger.
            try:
                logger.error(
                    "JSONL write failed",
                    extra={
                        "kind": "JSONL_WRITE_FAILED",
                        "error": str(exc),
                        "event": safe_str(event_type),
                    },
                )
            except Exception:
                pass


class LogConverter:
    """
    Converts JSONL event logs into standard AlanScan JSON reports.
    """

    def __init__(self, jsonl_path: str, output_dir: str):
        self.jsonl_path = jsonl_path
        self.output_dir = output_dir

    def convert_to_json(self) -> str:
        """
        Reads the JSONL log and produces a consolidated JSON report.
        Returns the path to the generated JSON file.
        """
        if not os.path.exists(self.jsonl_path):
            return ""

        findings: list = []
        metrics: dict = {}
        errors: list = []
        phases: list = []
        scan_metrics_rows: list = []
        scan_id_from_envelope: str = ""

        try:
            with open(self.jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        event = record.get("event")
                        payload = record.get("payload")
                        sid_e = record.get("scan_id")
                        if isinstance(sid_e, str) and sid_e and not scan_id_from_envelope:
                            scan_id_from_envelope = sid_e

                        if event in ("finding", "chain", "chain_detected"):
                            findings.append(payload)
                        elif event == "metric":
                            if isinstance(payload, dict):
                                metrics[payload.get("name")] = payload.get("value")
                        elif event in ("error", "MODULE_FAILED"):
                            errors.append(payload)
                        elif event in ("phase_end", "MODULE_PHASE_TIMER"):
                            phases.append(payload)
                        elif event in ("scan_metrics", "SCAN_METRICS"):
                            scan_metrics_rows.append(payload)
                    except Exception:
                        continue
        except Exception:
            return ""

        report = {
            "schema_version": SCHEMA_VERSION,
            "event_version": EVENT_VERSION,
            "scan_id": metrics.get("scan_id") or scan_id_from_envelope or "unknown",
            "target": metrics.get("target", "unknown"),
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": findings,
            "metrics": metrics,
            "phases": phases,
            "errors": errors,
            "scan_metrics": scan_metrics_rows,
        }

        target_clean = (
            metrics.get("target", "scan")
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
        )
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(
            self.output_dir, f"alanscan_{target_clean}_{timestamp_str}.json"
        )

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
            return report_path
        except Exception:
            return ""
