"""
Tests for proof-based injection logic (SQLi, CMDi, XXE).

Uses mocking for HTTP and timing; does not hit the network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import config
from scanner.web.cmdi import CMDiScanner
from scanner.web.sqli import SQLiScanner
from scanner.web.xxe import XXE_PAYLOADS, XML_CONTENT_TYPES, XXEScanner


# --- Helpers -----------------------------------------------------------------

def _mk_resp(text: str = "", status: int = 200) -> MagicMock:
    r = MagicMock()
    r.text = text
    r.status_code = status
    r.headers = {}
    return r


def _measure_from_id_param(
    url: str, *, pair2_same: bool
) -> tuple[int, int, float, str] | None:
    """Drive SQLi boolean _measure_get from encoded ``id`` query value."""
    from urllib.parse import parse_qs, urlparse

    q = parse_qs(urlparse(url).query, keep_blank_values=True)
    v = (q.get("id") or ["__base__"])[0]
    short_len, long_len, st = 1000, 1200, 200
    short_body = "a" * short_len
    long_body = "b" * long_len
    if v == "1":
        return (short_len, st, 0.01, short_body)
    if "' OR '1'='1' --" in v:
        return (long_len, st, 0.01, long_body)
    if "' OR '1'='2' --" in v:
        return (short_len, st, 0.01, short_body)
    if "' OR 1=1--" in v:
        return (long_len, st, 0.01, long_body)
    if "' OR 1=2--" in v:
        return (short_len, st, 0.01, short_body)
    if "' OR 7=7--" in v:
        return (long_len, st, 0.01, long_body)
    if "' OR 7=8--" in v:
        if not pair2_same:
            return (short_len, st, 0.01, short_body)
        return (long_len, st, 0.01, long_body)
    return (short_len, st, 0.01, short_body)


# --- SQLi boolean (3 pairs) --------------------------------------------------


def test_sqli_boolean_requires_three_pairs_two_only_differs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only two TRUE/FALSE pairs show a response split → no boolean finding."""
    monkeypatch.setattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", False)
    url = "http://example.test/page?id=1"
    scanner = SQLiScanner("http://example.test", threads=2, timeout=5)
    scanner.scan_intensity = "medium"

    def _mg(self, full_url: str):
        return _measure_from_id_param(full_url, pair2_same=True)

    with patch.object(SQLiScanner, "_measure_get", _mg):
        with patch.object(SQLiScanner, "_safe_request") as sr:
            sr.side_effect = lambda u: _mk_resp("you have an error in your sql syntax")
            findings = scanner._boolean_blind(url)

    assert not any(f.get("technique") == "Boolean-Blind SQLi" for f in findings)


def test_sqli_boolean_three_pairs_reports_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """All three pairs diverge consistently → boolean finding."""
    monkeypatch.setattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", False)
    url = "http://example.test/page?id=1"
    scanner = SQLiScanner("http://example.test", threads=2, timeout=5)
    scanner.scan_intensity = "medium"

    def _mg(self, full_url: str):
        return _measure_from_id_param(full_url, pair2_same=False)

    with patch.object(SQLiScanner, "_measure_get", _mg):
        with patch.object(SQLiScanner, "_safe_request") as sr:
            sr.side_effect = lambda u: _mk_resp("you have an error in your sql syntax")
            findings = scanner._boolean_blind(url)

    assert any(f.get("type") == "Boolean-Blind SQLi" for f in findings)


# --- SQLi pipeline after error-based -----------------------------------------


def test_sqli_does_not_stop_after_error_when_skip_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", False)
    scanner = SQLiScanner("http://example.test", threads=2, timeout=5)
    scanner.scan_intensity = "medium"

    err_hit = [{"type": "Error-Based SQLi", "url": "http://x", "param": "id"}]

    with patch.object(SQLiScanner, "_error_based", return_value=err_hit):
        with patch.object(SQLiScanner, "_boolean_blind", return_value=[]) as bb:
            with patch.object(SQLiScanner, "_time_blind", return_value=[]) as tb:
                out = scanner._test_url("http://example.test/x?id=1")

    bb.assert_called_once()
    tb.assert_called_once()
    assert out == err_hit


def test_sqli_stops_after_error_when_skip_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", True)
    scanner = SQLiScanner("http://example.test", threads=2, timeout=5)
    scanner.scan_intensity = "medium"
    err_hit = [{"type": "Error-Based SQLi"}]

    with patch.object(SQLiScanner, "_error_based", return_value=err_hit):
        with patch.object(SQLiScanner, "_boolean_blind", return_value=[]) as bb:
            with patch.object(SQLiScanner, "_time_blind", return_value=[]) as tb:
                out = scanner._test_url("http://example.test/x?id=1")

    bb.assert_not_called()
    tb.assert_not_called()
    assert out == err_hit


# --- CMDi output (2 payloads) -------------------------------------------------


def test_cmdi_output_single_payload_no_finding() -> None:
    """One shell-output hit is not enough for a finding."""
    scanner = CMDiScanner(["http://example.test"], threads=2, timeout=5)
    scanner.session = MagicMock()
    url = "http://example.test/vuln?q=abc"

    calls = {"n": 0}

    def se(*_a, **_kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return _mk_resp("uid=0(root) gid=0(root) groups=0(root)")
        return _mk_resp("ok")

    scanner.session.get.side_effect = se
    findings = scanner._test_url(url)
    assert not findings


def test_cmdi_output_two_distinct_payloads_finding() -> None:
    scanner = CMDiScanner(["http://example.test"], threads=2, timeout=5)
    scanner.session = MagicMock()
    url = "http://example.test/vuln?q=abc"

    def se(u, **_kw):
        u_s = str(u)
        # urlencode: abc;id -> abc%3Bid, abc| id -> abc%7C+id
        if "%3Bid" in u_s:
            return _mk_resp("uid=0(root) gid=0(root)")
        if "%7C+id" in u_s or "%7C%20id" in u_s:
            return _mk_resp("uid=0(root) groups=0(root)")
        return _mk_resp("")

    scanner.session.get.side_effect = se
    findings = scanner._test_url(url)
    assert len(findings) == 1
    assert findings[0]["type"] == "OS Command Injection (Output-Based)"


# --- CMDi time (2 payloads × 2 delays) ----------------------------------------


def test_cmdi_time_only_one_payload_no_finding() -> None:
    scanner = CMDiScanner(["http://example.test"], threads=2, timeout=5)
    scanner.session = MagicMock()
    url = "http://example.test/t?q=x"

    scanner.session.get.return_value = _mk_resp("")

    with patch.object(CMDiScanner, "_median_baseline_get", return_value=0.05):
        with patch.object(CMDiScanner, "_elapsed_get") as eg:
            def _el(full_url: str, _to: float):
                fs = str(full_url)
                if "sleep" in fs and "sleep 3" in fs:
                    return 5.0
                return 0.08

            eg.side_effect = _el
            findings = scanner._test_url(url)

    assert not findings


def test_cmdi_time_two_payloads_two_probes_finding() -> None:
    scanner = CMDiScanner(["http://example.test"], threads=2, timeout=5)
    scanner.session = MagicMock()
    url = "http://example.test/t?q=x"
    scanner.session.get.return_value = _mk_resp("")

    with patch.object(CMDiScanner, "_median_baseline_get", return_value=0.05):
        with patch.object(CMDiScanner, "_elapsed_get") as eg:
            def _el(full_url: str, _to: float):
                fs = str(full_url).lower()
                if "sleep" in fs or "timeout" in fs or "ping" in fs:
                    return 5.0
                return 0.08

            eg.side_effect = _el
            findings = scanner._test_url(url)

    assert len(findings) == 1
    assert findings[0]["type"] == "OS Command Injection (Time-Based Blind)"


# --- XXE continues all payloads ----------------------------------------------


def test_xxe_attempts_all_payload_posts_after_first_proof() -> None:
    scanner = XXEScanner(["http://example.test/a"], threads=2, timeout=5)
    scanner.session = MagicMock()
    url = "http://example.test/a"

    passwd_body = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )

    def post_side_effect(*_a, **_kw):
        r = MagicMock()
        r.status_code = 200
        r.headers = {"Content-Type": "application/xml"}
        r.text = passwd_body
        return r

    scanner.session.post.side_effect = post_side_effect

    with patch.object(XXEScanner, "_preflight_xml_context", return_value=True):
        scanner._test_url(url)

    expected_exploit_posts = len(XXE_PAYLOADS) * len(XML_CONTENT_TYPES)
    assert scanner.session.post.call_count == expected_exploit_posts


# --- Injection proof logging -------------------------------------------------


def test_injection_proof_log_contains_kind_payload_snippet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM", False)
    url = "http://example.test/page?id=1"
    scanner = SQLiScanner("http://example.test", threads=2, timeout=5)
    scanner.scan_intensity = "medium"

    def _mg(self, full_url: str):
        return _measure_from_id_param(full_url, pair2_same=False)

    with patch.object(SQLiScanner, "_measure_get", _mg):
        with patch.object(SQLiScanner, "_safe_request") as sr:
            sr.side_effect = lambda u: _mk_resp("you have an error in your sql syntax")
            with patch("scanner.web.sqli.logger.info") as log_info:
                scanner._boolean_blind(url)

    proof_calls = []
    for c in log_info.call_args_list:
        kwargs = c.kwargs if c.kwargs else {}
        extra = kwargs.get("extra") or {}
        if extra.get("kind") == "INJECTION_PROOF":
            proof_calls.append(c)
    assert proof_calls, "expected INJECTION_PROOF log"
    extra = proof_calls[0][1]["extra"]
    assert "payload" in extra
    assert "response_snippet" in extra
    assert extra["payload"]
    assert isinstance(extra["response_snippet"], str)
