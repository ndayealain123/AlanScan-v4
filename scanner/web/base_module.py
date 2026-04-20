from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Iterable
import requests
import config
from .base import make_session, normalize_url


# HTML control types that get full / primary injection passes (text-like + choices).
_FULL_INJECTION_TYPES = frozenset(
    {
        "text",
        "search",
        "email",
        "tel",
        "url",
        "password",
        "number",
        "range",
        "date",
        "datetime-local",
        "time",
        "week",
        "month",
        "color",
        "textarea",
        "select-one",
        "select-multiple",
        "checkbox",
        "radio",
        "checkbox-unchecked",
    },
)


def _field_type_tier(html_type: str) -> int:
    """0 = primary (text-like, password, selects, checkbox/radio), 1 = structural, 2 = hidden (last)."""
    t = (html_type or "text").lower()
    if t == "hidden":
        return 2
    if t in _FULL_INJECTION_TYPES:
        return 0
    return 1


def synthetic_field_details_from_fields(fields: dict[str, Any]) -> list[dict[str, Any]]:
    """When refetching HTML without rich metadata, treat each key as a text-like input."""
    out: list[dict[str, Any]] = []
    for k, v in (fields or {}).items():
        out.append(
            {
                "name": k,
                "value": "" if v is None else str(v),
                "type": "text",
                "tag": "input",
            },
        )
    return out


def _coalesce_field_value(typ: str, detail_val: str, current: str | None) -> str:
    """Fill missing/blank submission values using field type + crawler metadata (never drop a named control)."""
    t = (typ or "text").lower()
    cur = "" if current is None else str(current)
    dv = detail_val if detail_val is not None else ""
    if cur.strip():
        return cur
    if t == "file":
        return cur
    if t == "hidden":
        return dv
    if t in ("checkbox", "radio"):
        return dv if dv.strip() else "on"
    if t == "checkbox-unchecked":
        return "on"
    if t in ("submit", "button", "image"):
        return dv if dv.strip() else "submit"
    return dv if dv.strip() else "test"


def merge_fields_with_details(
    fields: dict[str, Any],
    details: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """
    Ensure every non-file control in ``field_details`` has a key in ``fields``.
    Blank ``fields`` entries are replaced using the detail row (checkbox/radio → ``on``, etc.).
    """
    out: dict[str, str] = {k: "" if v is None else str(v) for k, v in (fields or {}).items()}
    for d in details or []:
        if not isinstance(d, dict):
            continue
        name = (d.get("name") or "").strip()
        if not name:
            continue
        typ = str(d.get("type") or "text").lower()
        if typ == "file":
            continue
        dv_raw = d.get("value")
        dv = "" if dv_raw is None else str(dv_raw)
        cur = out.get(name, "")
        out[name] = _coalesce_field_value(typ, dv, cur)
    return out


def finalize_post_target(raw: dict[str, Any]) -> dict[str, Any] | None:
    """
    Build a normalised POST target: ``url``, ``fields``, ``field_details``.
    Merges crawler ``field_details`` with ``fields`` so empty/missing values still submit.
    """
    url = (raw.get("url") or "").strip()
    if not url:
        return None
    fields_in = raw.get("fields") or raw.get("parameters") or {}
    if not isinstance(fields_in, dict):
        fields_in = {}
    details = raw.get("field_details")
    if not isinstance(details, list) or not details:
        details = synthetic_field_details_from_fields(fields_in)
    merged = merge_fields_with_details(fields_in, details)
    if not merged:
        return None
    return {"url": url, "fields": merged, "field_details": list(details)}


def post_param_injection_order(
    field_details: list[dict[str, Any]] | None,
    field_names: Iterable[str],
) -> list[str]:
    """
    Order parameter names for injection: text/search/password/selects/checkbox/radio first,
    then submit-like controls, then hidden (still scanned, lower priority).
    """
    names = list(field_names)
    dom_index: dict[str, int] = {}
    type_by_name: dict[str, str] = {}
    for i, d in enumerate(field_details or []):
        if not isinstance(d, dict):
            continue
        n = (d.get("name") or "").strip()
        if not n:
            continue
        dom_index.setdefault(n, i)
        type_by_name[n] = str(d.get("type") or "text").lower()
    for j, n in enumerate(names):
        type_by_name.setdefault(n, "text")
        dom_index.setdefault(n, 10_000 + j)

    def sort_key(n: str) -> tuple[int, int]:
        return (
            _field_type_tier(type_by_name.get(n, "text")),
            dom_index.get(n, 99_999),
        )

    return sorted(names, key=sort_key)


def lookup_url_query_params(
    url_query_params: dict[str, dict[str, list[str]]] | None,
    url: str,
) -> dict[str, list[str]] | None:
    """Resolve crawler ``url_query_params`` for a URL (exact or ``normalize_url`` match)."""
    if not url_query_params or not url:
        return None
    u = str(url).strip()
    if u in url_query_params:
        raw = url_query_params[u]
        return {k: list(v) for k, v in (raw or {}).items()} if raw else None
    nu = normalize_url(u)
    if nu in url_query_params:
        raw = url_query_params[nu]
        return {k: list(v) for k, v in (raw or {}).items()} if raw else None
    return None


@dataclass
class ScanContext:
    """Central state for the entire penetration test."""
    target: str
    urls: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    payloads: dict[str, list[str]] = field(default_factory=dict)
    session: requests.Session | None = None
    auth_session: requests.Session | None = None
    waf_detected: bool = False
    extra_evidence: dict[str, Any] = field(default_factory=dict)
    
    def __init__(
        self,
        target: str,
        proxy: str | None = None,
        timeout: int | None = None,
        bearer_token: str | None = None,
    ):
        self.target = target
        self.urls = [target] if isinstance(target, str) else target
        self.findings = []
        self.payloads = {}
        to = int(timeout if timeout is not None else getattr(config, "TIMEOUT", 15))
        self.session = make_session(proxy, to)
        if bearer_token:
            self.session.headers["Authorization"] = f"Bearer {bearer_token.strip()}"
        self.auth_session = None
        self.waf_detected = False
        self.extra_evidence = {}
        self.crawl_forms: list[dict] = []
        self.crawl_stats: dict[str, Any] = {}
        self.crawl_url_query_params: dict[str, dict[str, list[str]]] = {}
        self.scan_targets: list[dict[str, Any]] = []

    @property
    def unified_session(self) -> requests.Session:
        """
        Single outbound ``requests.Session`` for all modules.

        After authentication, ``auth_session`` and ``session`` refer to the same
        object; this accessor documents the canonical choice and keeps call sites
        consistent.
        """
        s = self.auth_session if self.auth_session is not None else self.session
        if s is None:
            raise RuntimeError("ScanContext has no HTTP session")
        return s


class BaseModule:
    """Interface for all AlanScan security modules."""
    name = "base"

    def run(self, context: ScanContext) -> list[dict]:
        raise NotImplementedError("Module must implement run()")
