"""
Central scan event kinds for structured logging (``extra["kind"]``).

All orchestration and scanners should use these constants — not ad-hoc strings.
"""

from __future__ import annotations

from enum import Enum


class ScanEventKind(str, Enum):
    """Stable event type identifiers for CLI formatting and analytics."""

    # Scan lifecycle
    SCAN_START = "SCAN_START"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    SCAN_ABORTED = "SCAN_ABORTED"
    SCAN_METRICS = "SCAN_METRICS"

    # Module / phase
    MODULE_START = "MODULE_START"
    MODULE_PHASE_TIMER = "MODULE_PHASE_TIMER"
    MODULE_PHASE_ERROR = "MODULE_PHASE_ERROR"
    MODULE_FAILED = "MODULE_FAILED"
    NETWORK_MODULE_FAILED = "NETWORK_MODULE_FAILED"
    HTTP_MODULE_FAILED = "HTTP_MODULE_FAILED"
    CRAWL_URLS_DISCOVERED = "CRAWL_URLS_DISCOVERED"
    THROTTLE_CIRCUIT_SKIP = "THROTTLE_CIRCUIT_SKIP"

    # Auth / WAF / pipeline
    AUTH_SESSION_ESTABLISHED = "AUTH_SESSION_ESTABLISHED"
    AUTH_AUDIT_FAILED = "AUTH_AUDIT_FAILED"
    WAF_DETECTION_FAILED = "WAF_DETECTION_FAILED"
    EVIDENCE_COLLECTION_FAILED = "EVIDENCE_COLLECTION_FAILED"
    AI_ANALYSIS_FAILED = "AI_ANALYSIS_FAILED"
    REPORT_SAVE_FAILED = "REPORT_SAVE_FAILED"

    # Guard / budget
    GUARD_SUMMARY_HEADER = "GUARD_SUMMARY_HEADER"
    GUARD_SUMMARY_HTTP_TOTAL = "GUARD_SUMMARY_HTTP_TOTAL"
    GUARD_SUMMARY_BUDGET = "GUARD_SUMMARY_BUDGET"
    GUARD_SUMMARY_MODULE = "GUARD_SUMMARY_MODULE"
    GUARD_SUMMARY_FOOTER = "GUARD_SUMMARY_FOOTER"

    # Findings pipeline
    FINDING_ACCEPTED = "FINDING_ACCEPTED"
    FINDING_REJECTED = "FINDING_REJECTED"
    FINDING_COUNT_MISMATCH = "finding_count_mismatch"

    # Header scanner (domain-specific)
    HEADERS_FETCH_FAILED = "HEADERS_FETCH_FAILED"
    COOKIES_FETCH_FAILED = "COOKIES_FETCH_FAILED"
    HEADERS_PLUS_FETCH_FAILED = "HEADERS_PLUS_FETCH_FAILED"
    HTTP_RETRIES_EXHAUSTED = "HTTP_RETRIES_EXHAUSTED"
    HEADERS_MISSING_GROUP = "HEADERS_MISSING_GROUP"
    HEADERS_VERSION_DISCLOSURE = "HEADERS_VERSION_DISCLOSURE"
    HEADERS_CSP_ISSUE = "HEADERS_CSP_ISSUE"


def safe_scan_event_kind(name: str, fallback: str) -> str:
    """
    Resolve an enum member by attribute name without crashing if it is missing
    (e.g. mixed package versions). Returns the string ``value`` for JSONL/extra.
    """
    member = getattr(ScanEventKind, name, None)
    if isinstance(member, ScanEventKind):
        return str(member.value)
    return fallback
