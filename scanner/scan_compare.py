"""
Optional delta between a previous AlanScan JSON report and the current run.
Fingerprints: normalized URL + parameter + vulnerability type (non-chain).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def _norm_url(url: str) -> str:
    if not url:
        return ""
    p = urlparse(str(url))
    try:
        qs = sorted(parse_qsl(p.query, keep_blank_values=True))
        q = urlencode(qs)
    except Exception:
        q = p.query or ""
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    scheme = (p.scheme or "http").lower()
    netloc = (p.netloc or "").lower()
    base = f"{scheme}://{netloc}{path}"
    return f"{base}?{q}" if q else base


def finding_fingerprint(f: dict[str, Any]) -> str:
    if not isinstance(f, dict):
        return ""
    if f.get("chain"):
        cid = str(f.get("chain_id") or f.get("id") or "")
        return f"chain:{str(f.get('type', '')).lower()}:{cid}"
    u = _norm_url(str(f.get("url", "")))
    param = str(f.get("parameter") or f.get("param") or "").strip().lower()
    typ = str(f.get("type", "")).strip().lower()
    return f"{u}|{param}|{typ}"


def _brief(k: str, prev_map: dict, curr_map: dict) -> dict[str, Any]:
    src = curr_map.get(k) or prev_map.get(k) or {}
    return {
        "type": src.get("type", ""),
        "severity": src.get("severity", ""),
        "url": str(src.get("url", ""))[:220],
        "parameter": src.get("parameter") or src.get("param") or "",
    }


def compare_scan_findings(previous: list[dict], current: list[dict]) -> dict[str, Any]:
    prev_reg = [f for f in previous if isinstance(f, dict) and not f.get("chain")]
    curr_reg = [f for f in current if isinstance(f, dict) and not f.get("chain")]
    pm = {finding_fingerprint(f): f for f in prev_reg}
    cm = {finding_fingerprint(f): f for f in curr_reg}
    pk, ck = set(pm), set(cm)
    new_k = ck - pk
    resolved_k = pk - ck
    common = pk & ck

    severity_changed: list[dict[str, Any]] = []
    for k in common:
        ps = str(pm[k].get("severity", ""))
        cs = str(cm[k].get("severity", ""))
        if ps != cs:
            severity_changed.append(
                {
                    "fingerprint": k,
                    "previous_severity": ps,
                    "current_severity": cs,
                    "type": cm[k].get("type", ""),
                    "url": str(cm[k].get("url", ""))[:220],
                    "parameter": cm[k].get("parameter") or cm[k].get("param") or "",
                }
            )

    unchanged = len(common) - len(severity_changed)
    new_findings = [_brief(k, pm, cm) for k in sorted(new_k)]
    resolved_findings = [_brief(k, pm, cm) for k in sorted(resolved_k)]

    return {
        "previous_findings_count": len(prev_reg),
        "current_findings_count": len(curr_reg),
        "new_count": len(new_k),
        "resolved_count": len(resolved_k),
        "unchanged_count": unchanged,
        "severity_changed_count": len(severity_changed),
        "new_findings": new_findings[:100],
        "resolved_findings": resolved_findings[:100],
        "severity_changed": severity_changed[:100],
        "summary_line": (
            f"Versus baseline: +{len(new_k)} new, -{len(resolved_k)} resolved, "
            f"{len(severity_changed)} severity change(s), {unchanged} unchanged."
        ),
    }


def load_previous_report(path: str) -> tuple[list[dict], dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        return [], {}
    findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
    chains = [c for c in (data.get("chains") or []) if isinstance(c, dict)]
    meta = {
        k: data.get(k)
        for k in ("timestamp", "target", "scan_id", "version", "tool")
        if data.get(k) is not None
    }
    return findings + chains, meta
