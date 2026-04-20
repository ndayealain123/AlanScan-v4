"""Unit tests for SPA JavaScript URL extraction."""

from scanner.web.spa_url_extract import extract_urls_from_javascript


def test_fetch_and_axios_paths() -> None:
    js = """
    fetch("/api/v1/users");
    axios.get('/graphql');
    axios.post("https://ex.com/other", {});
    """
    out = extract_urls_from_javascript(
        js,
        origin="https://ex.com",
        referer="https://ex.com/",
    )
    assert "https://ex.com/api/v1/users" in out
    assert "https://ex.com/graphql" in out
    assert "https://ex.com/other" in out


def test_dynamic_route_instantiated() -> None:
    js = 'path: "/orders/:orderId/detail"'
    out = extract_urls_from_javascript(
        js,
        origin="https://app.example",
        referer="https://app.example/",
    )
    assert any("/orders/1/detail" in u for u in out)


def test_xhr_open() -> None:
    js = 'xhr.open("GET", "/internal/status");'
    out = extract_urls_from_javascript(
        js,
        origin="https://x.test",
        referer="https://x.test/",
    )
    assert "https://x.test/internal/status" in out
