"""Tests for scanner.web.version_disclosure_header."""

from __future__ import annotations

from scanner.web import version_disclosure_header


def test_sample_header() -> None:
    assert version_disclosure_header.is_reportable_version_disclosure_header(
        "server",
        "nginx/1.22.1",
        "https://example.com",
    )


def test_x_powered_by_version() -> None:
    assert version_disclosure_header.is_reportable_version_disclosure_header(
        "x-powered-by",
        "PHP/8.2.12",
        "https://example.com/",
    )


def test_aspnet_version() -> None:
    assert version_disclosure_header.is_reportable_version_disclosure_header(
        "x-aspnet-version",
        "4.0.30319",
        "https://example.com/app",
    )


def test_aspnet_mvc_version() -> None:
    assert version_disclosure_header.is_reportable_version_disclosure_header(
        "x-aspnetmvc-version",
        "5.2.3",
        "https://example.com/",
    )


def test_non_reportable_header_no_version() -> None:
    assert not version_disclosure_header.is_reportable_version_disclosure_header(
        "server",
        "cloudflare",
        "https://example.com",
    )
    assert not version_disclosure_header.is_reportable_version_disclosure_header(
        "x-powered-by",
        "Express",
        "https://example.com",
    )


def test_reflected_payload_skipped() -> None:
    url = "https://example.com/page?q=nginx/1.22.1"
    assert not version_disclosure_header.is_reportable_version_disclosure_header(
        "server",
        "nginx/1.22.1",
        url,
    )
    frag_url = "https://example.com/page#Apache/2.4.49"
    assert not version_disclosure_header.is_reportable_version_disclosure_header(
        "server",
        "Apache/2.4.49 (Unix)",
        frag_url,
    )
