"""Tests for scanner.scoring_engine."""

from __future__ import annotations

from unittest import mock

from scanner.scoring_engine import ScoringEngine


@mock.patch("scanner.scoring_engine.config.get_vuln_meta")
def test_infrastructure_cookie_downgrade(mock_get_vuln_meta: mock.MagicMock) -> None:
    """Infrastructure cookies must cap at INFO and low environmental score."""
    mock_get_vuln_meta.return_value = {
        "cwe": "CWE-614",
        "cvss": 10.0,
        "cvss_vector": "N/A",
        "description": "Sensitive cookie exposure",
        "recommendation": "Review cookie flags",
        "owasp": "A01:2021",
    }
    finding = {
        "type": "Cookie Without Secure Flag",
        "severity": "CRITICAL",
        "url": "https://example.com/admin/login",
        "evidence": "Set-Cookie session=abc; password reset flow",
        "validation": {"confidence_label": "HIGH"},
        "extra": {"infrastructure_cookie": True},
    }
    engine = ScoringEngine([])
    scored = engine._score_finding_enhanced(finding)

    assert scored["scoring"]["severity_band"] == "INFO"
    assert float(scored["scoring"]["environmental_score"]) <= 3.5
    # Would be CRITICAL / high environmental without infrastructure_cookie
    mock_get_vuln_meta.assert_called()

    without_flag = {**finding, "extra": {}}
    high_env = engine._score_finding_enhanced(without_flag)
    assert high_env["scoring"]["severity_band"] in ("CRITICAL", "HIGH")
    assert float(high_env["scoring"]["environmental_score"]) > 3.5
