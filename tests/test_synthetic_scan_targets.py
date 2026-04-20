"""Synthetic scan targets when crawl finds no GET query parameters."""

from scanner.web.base import normalize_url
from scanner.web.scan_targets import build_synthetic_injection_get_targets, dedupe_scan_targets


def test_synthetic_targets_include_common_params_and_api_paths() -> None:
    out = build_synthetic_injection_get_targets(
        "https://app.example.com/dashboard",
        ["https://app.example.com/static/x"],
    )
    assert out
    urls = {t["url"] for t in out}
    assert any("app.example.com" in u for u in urls)
    assert any("/api" in u for u in urls)
    for t in out:
        assert t["method"] == "GET"
        assert set(t["params"].keys()) >= {"id", "q", "search"}
        assert t.get("source") == "synthetic_fallback"


def test_synthetic_dedupes_root_with_identical_params() -> None:
    existing = [
        {
            "url": "https://z.test/",
            "method": "GET",
            "params": {"id": ["1"], "q": ["test"], "search": ["test"]},
            "field_details": [],
            "source": "query",
        }
    ]
    synth = build_synthetic_injection_get_targets("https://z.test/", [])
    merged = dedupe_scan_targets(existing + synth)
    root_like = [
        t
        for t in merged
        if normalize_url(t["url"]).lower() == "https://z.test"
    ]
    assert len(root_like) == 1
    assert len(merged) > len(root_like)
