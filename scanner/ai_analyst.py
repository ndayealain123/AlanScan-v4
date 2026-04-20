"""
scanner/ai_analyst.py  v4.0.0
==============================
AI-powered vulnerability narrative layering.

§1.3  LLM layer: local **Ollama** (``/api/generate``, default model ``llama3``) via
      ``scanner.ai.ollama_client.generate_ai_analysis``. On any failure, the scan
      continues with deterministic templates only (no exceptions).
§1.3  Error type detection (for controller / legacy helpers): AUTH_ERROR | …
§1.3  Fallback chain:
        1. Ollama local generate (single attempt, bounded timeout)
        2. Cached deterministic templates (always available)
        3. Deterministic narrative builder (final safety net)
§5    Chain confidence score, step-by-step attack flow,
      business impact (ATO / data exfiltration / privilege escalation),
      deduplicated chain descriptions
§8    Narrative processing seconds logged per attempt
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse, urlunparse

from .scan_logger import logger
from .ai.ollama_client import generate_ai_analysis

_MIN_NARRATIVE_SECONDS = 0.02

MAX_TOKENS = 4096  # legacy module constant (reports / limits elsewhere)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_CLIP_TECH = 320
_CLIP_PAY  = 260
_CLIP_EV   = 400


# ── §1.3 Error classification ─────────────────────────────────────────────────
def classify_ai_api_error(exc: Exception) -> str:
    """
    Classify an HTTP/API error for logging and user-facing messages.

    Returns one of: AUTH_ERROR | RATE_LIMIT | INSUFFICIENT_CREDITS | BAD_REQUEST |
    NETWORK_ERROR | UNKNOWN_ERROR
    """
    resp = getattr(exc, "response", None)
    if resp is not None:
        try:
            code = int(getattr(resp, "status_code", 0) or 0)
        except (TypeError, ValueError):
            code = 0
        if code in (401, 403):
            return "AUTH_ERROR"
        if code == 429:
            return "RATE_LIMIT"
        if code == 402:
            return "INSUFFICIENT_CREDITS"
        if code == 400:
            return "BAD_REQUEST"
        if code >= 500:
            return "NETWORK_ERROR"
    msg = str(exc).lower()
    if any(
        k in msg
        for k in (
            "insufficient credit",
            "not enough credit",
            "billing",
            "payment required",
            "balance too low",
            "exceeded your credit",
        )
    ):
        return "INSUFFICIENT_CREDITS"
    if any(k in msg for k in ("401", "403", "authentication", "unauthorized", "forbidden", "api_key", "invalid key")):
        return "AUTH_ERROR"
    if any(k in msg for k in ("429", "rate limit", "too many", "quota")):
        return "RATE_LIMIT"
    if any(k in msg for k in ("400", "bad request", "invalid_request", "malformed")):
        return "BAD_REQUEST"
    if any(k in msg for k in ("timeout", "connect", "network", "connection", "refused", "unreachable")):
        return "NETWORK_ERROR"
    return "UNKNOWN_ERROR"


# Console / report-facing lines (no raw vendor JSON in the primary message)
_AI_USER_FACING: dict[str, str] = {
    "INSUFFICIENT_CREDITS": "[AI] Skipped (insufficient API credits) → fallback used",
    "AUTH_ERROR": "[AI] Skipped (API authentication failed) → fallback used",
    "RATE_LIMIT": "[AI] Skipped (rate limited) → fallback used",
    "BAD_REQUEST": "[AI] Skipped (invalid API request) → fallback used",
    "NETWORK_ERROR": "[AI] Skipped (API unreachable) → fallback used",
    "UNKNOWN_ERROR": "[AI] Skipped (API error) → fallback used",
}


def user_facing_ai_status(err_type: str) -> str:
    return _AI_USER_FACING.get(err_type, _AI_USER_FACING["UNKNOWN_ERROR"])


def user_facing_ai_message_from_exc(exc: BaseException) -> str:
    if isinstance(exc, Exception):
        return user_facing_ai_status(classify_ai_api_error(exc))
    return _AI_USER_FACING["UNKNOWN_ERROR"]


def _as_str(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return str(v)
    if isinstance(v, (dict, list)):
        return str(v)
    return str(v)


def _clip(s: str, n: int) -> str:
    t = s.strip()
    if len(t) <= n:
        return t
    if n <= 3:
        return t[:n]
    return t[: n - 3] + "..."


def _observable_behavior(evidence: str, finding: dict) -> str:
    if not evidence or not str(evidence).strip():
        return ""
    ev    = evidence.lower()
    ftype = _as_str(finding.get("type")).lower()
    if "sql" in ftype or " sqli" in ftype:
        if any(x in ev for x in ("mysql", "syntax", "odbc", "ora-", "postgres", "sqlite", "sql server", "warning:", "mysqli")):
            return (
                "Database engine diagnostics or query errors appeared in the HTTP layer, "
                "which is consistent with user-controlled SQL reaching the interpreter."
            )
        if "sleep" in ev or "benchmark" in ev or "waitfor" in ev or "time-based" in ftype:
            return (
                "Measurable latency correlated with timing-oriented payloads — consistent with "
                "blind SQL inference when errors are suppressed."
            )
    if any(x in ftype for x in ("cmdi", "command injection", "os command")):
        if any(x in ev for x in ("uid=", "gid=", "root:", "www-data", "apache", "volume in drive", "directory of")):
            return (
                "Shell-like or host-environment output was reflected, indicating user input influenced "
                "OS command execution."
            )
    if "xss" in ftype or "cross-site" in ftype:
        if "<script" in ev or "onerror=" in ev or "javascript:" in ev:
            return (
                "Executable browser context received attacker-controlled markup or handlers "
                "without sufficient encoding or policy enforcement."
            )
    if "redirect" in ftype:
        if "location:" in ev or "302" in ev or "301" in ev:
            return (
                "The application issued an HTTP redirect influenced by the manipulated parameter, "
                "demonstrating an open-redirect primitive."
            )
    if "lfi" in ftype or "path traversal" in ftype or "traversal" in ftype:
        if "/etc/" in ev or "boot.ini" in ev or "[extensions]" in ev:
            return (
                "Filesystem disclosure patterns in the response suggest successful file inclusion "
                "or path traversal."
            )
    return ""


def _type_param_merge_key(f: dict) -> tuple[str, str]:
    """Group duplicates by vulnerability class + parameter (case-insensitive)."""
    t = _clean_type(str(f.get("type") or "Unknown")).strip().lower()
    p = _as_str(f.get("parameter")).strip().lower() or "(no parameter)"
    return (t, p)


def _unique_urls_from_findings(items: list[dict]) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for it in items:
        u = _as_str(it.get("url")).strip()
        if u and u.upper() != "N/A" and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def _unique_evidence_strings_from_findings(items: list[dict]) -> list[str]:
    chunks: list[str] = []
    seen: set[str] = set()
    for it in items:
        e = _as_str(it.get("evidence")).strip()
        if e and e not in seen:
            seen.add(e)
            chunks.append(e)
    return chunks


def _merge_non_chain_by_type_and_parameter(non_chain: list[dict]) -> list[dict]:
    """
    Merge findings that share the same type + parameter into one row.
    Affected URLs are collected in ``affected_endpoints``; severity keeps the worst in the group.
    """
    if not non_chain:
        return []
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in non_chain:
        if not isinstance(f, dict):
            continue
        groups[_type_param_merge_key(f)].append(f)

    merged: list[dict] = []
    max_evidence_len = 8000
    for _key, items in groups.items():
        if len(items) == 1:
            merged.append(dict(items[0]))
            continue
        items_sorted = sorted(
            items,
            key=lambda x: _SEV_ORDER.get(str(x.get("severity", "INFO")).upper(), 4),
        )
        rep = dict(items_sorted[0])
        urls = _unique_urls_from_findings(items_sorted)
        rep["affected_endpoints"] = urls
        rep["merged_from_count"] = len(items)
        if urls:
            rep["url"] = urls[0]
        ev_chunks = _unique_evidence_strings_from_findings(items_sorted)
        combined_ev = "\n\n---\n\n".join(ev_chunks)
        if len(combined_ev) > max_evidence_len:
            combined_ev = combined_ev[: max_evidence_len - 40] + "\n... [evidence truncated]"
        rep["evidence"] = combined_ev
        merged.append(rep)

    merged.sort(
        key=lambda f: (
            _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 4),
            _type_param_merge_key(f)[0],
        )
    )
    return merged


class AIAnalyst:
    def __init__(self, findings: list[dict], api_key: str | None = None) -> None:
        self.findings = findings or []
        self.api_key  = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    # ── Public ────────────────────────────────────────────────────────────────

    def analyse(self) -> dict:
        t0       = time.perf_counter()
        all_rows = [f for f in self.findings if isinstance(f, dict)]

        if not all_rows:
            out = self._empty_scan_narrative()
            self._ensure_min_duration(t0)
            out["narrative_processing_seconds"] = round(time.perf_counter() - t0, 2)
            logger.info("AI narrative analysis complete (no validated findings)",
                        extra={"kind": "AI_ANALYSIS_DONE", "findings_count": 0,
                               "seconds": out["narrative_processing_seconds"]})
            return out

        logger.info("AI narrative analysis started",
                    extra={"kind": "AI_ANALYSIS_START", "findings_count": len(all_rows)})

        non_chain_raw = [f for f in all_rows if not f.get("chain")]
        chain_rows    = [f for f in all_rows if f.get("chain")]
        non_chain     = _merge_non_chain_by_type_and_parameter(non_chain_raw)
        narrative_rows = non_chain + chain_rows

        enriched_non = [self._enrich_finding(f) for f in non_chain]
        enriched_chain = [self._enrich_chain_finding(f) for f in chain_rows]
        merged       = enriched_non + enriched_chain

        overall_risk = self._calculate_risk(narrative_rows)
        attack_chain_text = self._build_attack_chain_description(chain_rows)

        out = {
            "executive_summary":        self._build_executive_summary(narrative_rows),
            "vulnerability_summary":    self._build_vulnerability_summary(narrative_rows),
            "risk_explanation":         self._build_risk_explanation(narrative_rows, overall_risk),
            "attack_chain_description": attack_chain_text,
            "stakeholder_summary":      self._build_stakeholder_summary(narrative_rows, overall_risk),
            "top_3_priorities":         self._build_top3_priorities(narrative_rows),
            "attacker_perspective":     self._build_attacker_perspective(narrative_rows),
            "remediation_roadmap":      self._build_remediation_roadmap(narrative_rows),
            "compliance_impact":        self._compliance_impact(narrative_rows),
            "overall_risk":             overall_risk,
            "total_fix_effort":         self._total_fix_effort(narrative_rows),
            "findings":                 merged,
            "priority_order":           list(range(len(merged))),
        }
        # §1.3 Try Ollama (local); on failure keep deterministic narrative in ``out``
        self._merge_llm_narrative_with_retry(out, narrative_rows)
        self._ensure_min_duration(t0)
        out["narrative_processing_seconds"] = round(time.perf_counter() - t0, 2)
        logger.info("AI narrative analysis complete",
                    extra={"kind": "AI_ANALYSIS_DONE",
                           "findings_count": len(narrative_rows),
                           "raw_findings_count": len(all_rows),
                           "seconds": out["narrative_processing_seconds"]})
        return out

    @staticmethod
    def _ensure_min_duration(t0: float) -> None:
        elapsed = time.perf_counter() - t0
        pad = _MIN_NARRATIVE_SECONDS - elapsed
        if pad > 0:
            time.sleep(pad)

    # ── §1.3 LLM narrative with retry + fallback chain ────────────────────────

    def _merge_llm_narrative_with_retry(self, out: dict, all_rows: list[dict]) -> None:
        """
        §1.3 Fallback chain:
          1. Local Ollama ``/api/generate`` (via ``generate_ai_analysis``)
          2. Deterministic narrative already populated in ``out``

        Never raises. On failure, logs ``[AI] Ollama unavailable`` and leaves ``out`` unchanged.
        """
        brief = []
        for f in all_rows[:45]:
            if not isinstance(f, dict):
                continue
            brief.append({
                "type":      f.get("type"),
                "severity":  f.get("severity"),
                "url":       _clip(_as_str(f.get("url")), 140),
                "parameter": f.get("parameter"),
            })

        user_prompt = (
            "You are a senior penetration tester. Given this JSON array of validated findings, "
            "write two sections separated by a single line containing exactly three dashes: ---\n"
            "First section — Attack paths: 3-6 sentences naming classes of issues and entry points; "
            "do not provide weaponised exploit steps or full payloads.\n"
            "Second section — Business impact: 3-5 sentences for executives (risk, liability, urgency).\n"
            f"Findings JSON: {json.dumps(brief, ensure_ascii=False, default=str)}"
        )

        logger.info(
            "[AI] Using Ollama (local)",
            extra={"kind": "AI_OLLAMA_START"},
        )

        try:
            text = generate_ai_analysis(user_prompt)
        except Exception:
            logger.warning(
                "[AI] Ollama unavailable",
                extra={"kind": "AI_OLLAMA_FALLBACK"},
            )
            out.setdefault("ai_narrative_status", "[AI] Ollama unavailable")
            return

        text = (text or "").strip()
        if not text:
            logger.warning(
                "[AI] Ollama unavailable",
                extra={"kind": "AI_OLLAMA_FALLBACK"},
            )
            out.setdefault("ai_narrative_status", "[AI] Ollama unavailable")
            return

        if "---" in text:
            left, right = text.split("---", 1)
            out["llm_attack_paths"] = left.strip()
            out["llm_business_impact"] = right.strip()
        else:
            out["llm_executive_narrative"] = text
        if out.get("llm_attack_paths"):
            out["executive_summary"] = (
                f"{out['llm_attack_paths']}\n\n"
                f"Scanner summary: {out.get('executive_summary', '')}"
            ).strip()
        if out.get("llm_business_impact"):
            out["stakeholder_summary"] = (
                f"{out['llm_business_impact']}\n\n"
                f"{out.get('stakeholder_summary', '')}"
            ).strip()

        logger.info(
            "[AI] Ollama response generated",
            extra={"kind": "AI_OLLAMA_SUCCESS"},
        )

    # ── Per-finding enrichment ────────────────────────────────────────────────

    def _enrich_finding(self, f: dict) -> dict:
        base = self._get_ai_analysis(f.get("type", ""), f)
        return {**f, "ai_analysis": self._finalize_ai_block(base, f, is_chain=False)}

    def _enrich_chain_finding(self, f: dict) -> dict:
        """§5: Narrative block for multi-step chains with confidence score and step-by-step flow."""
        name  = _clean_type(str(f.get("type", "Vulnerability chain")))
        if name.upper().startswith("VULNERABILITY CHAIN:"):
            name = name.split(":", 1)[-1].strip()
        steps = f.get("attack_steps") or []
        path  = " -> ".join(str(s) for s in steps) if steps else ""
        if not path:
            ev = str(f.get("evidence", ""))
            if "ATTACK PATH:" in ev.upper():
                path = ev
        impact = str(f.get("impact_description", "") or "")
        amp    = str(f.get("risk_amplification", "") or "")
        rem    = str(f.get("remediation", "") or "")

        # §5 Confidence score
        conf_raw = f.get("confidence") or f.get("chain_confidence") or 0
        try:
            conf_score = float(conf_raw)
        except (TypeError, ValueError):
            conf_score = 0.0
        conf_label = (
            "High" if conf_score >= 0.8 else
            "Medium" if conf_score >= 0.5 else
            "Low"
        )

        # §5 Business impact classification
        biz_keywords = [
            ("account takeover",       ["xss", "csrf", "session", "login", "auth"]),
            ("data exfiltration",      ["sql", "sqli", "lfi", "xxe", "ssrf"]),
            ("privilege escalation",   ["cmdi", "command", "admin", "root"]),
        ]
        impacts_detected = []
        ev_lower = (path + " " + impact + " " + str(steps)).lower()
        for label, kws in biz_keywords:
            if any(k in ev_lower for k in kws):
                impacts_detected.append(label)

        biz = impact or (
            "Chained vulnerabilities compound impact: "
            + (", ".join(impacts_detected) + " possible. " if impacts_detected else "")
            + "Attackers can move from initial access to meaningful compromise "
              "without resolving each issue in isolation."
        )

        # §5 Step-by-step attack flow (formatted)
        if steps and isinstance(steps, list):
            step_lines = "\n".join(
                f"  Step {i+1}: {str(s)}" for i, s in enumerate(steps[:10])
            )
            plain = (
                f"Validated attack chain «{name}» (confidence: {conf_label} / {conf_score:.0%}) "
                + (f"chains {len(steps)} steps into an end-to-end path:\n{step_lines}" if steps else ".")
                + (f"\n{amp}" if amp else "")
            )
        else:
            plain = (
                f"Validated attack chain «{name}» chains existing weaknesses into an end-to-end path"
                + (f": {path}" if path else ".")
                + (f" {amp}" if amp else "")
            ).strip()

        steps_hint: list[str]
        if rem:
            steps_hint = [rem]
        else:
            steps_hint = [
                "Remediate each prerequisite finding in the chain to break the path.",
                "Validate fixes with a follow-up scan focused on the same entry points.",
            ]

        block = {
            "plain_english":       plain,
            "business_impact":     biz,
            "remediation_steps":   steps_hint,
            "remediation_code":    "# Break the chain: patch each linked finding, then re-test.",
            "fix_priority":        {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 6, "LOW": 4, "INFO": 2}.get(
                str(f.get("severity", "HIGH")).upper(), 8
            ),
            "fix_effort":          "High — multiple coordinated remediations",
            "chain_confidence":    conf_score,
            "chain_confidence_label": conf_label,
            "business_impacts":    impacts_detected,
        }
        return {**f, "ai_analysis": self._finalize_ai_block(block, f, is_chain=True)}

    # ── Senior narrative layering ────────────────────────────────────────────

    def _finalize_ai_block(self, base: dict, finding: dict, *, is_chain: bool) -> dict:
        out = dict(base)
        merged_steps: list[str] = []
        for key in ("remediation_steps", "fix_steps"):
            raw = out.get(key)
            if isinstance(raw, list):
                merged_steps.extend(str(x).strip() for x in raw if str(x).strip())
        seen: set[str] = set()
        uniq_steps: list[str] = []
        for s in merged_steps:
            if s not in seen:
                seen.add(s)
                uniq_steps.append(s)
        out["remediation_steps"] = uniq_steps
        out.pop("fix_steps", None)
        if out.get("remediation_code") and not str(out["remediation_code"]).strip():
            out.pop("remediation_code", None)

        bi = out.get("business_impact", "")
        if isinstance(bi, dict):
            out["business_impact"] = str(
                bi.get(finding.get("severity", "MEDIUM"), "")
                or next(iter(bi.values()), "")
            )

        if is_chain:
            out["technical_context"] = self._chain_technical_context(finding)
        else:
            out["technical_context"] = self._technical_context_block(finding)

        out["stakeholder_impact"]    = self._stakeholder_impact_lines(finding, out)
        cvss_txt = self._cvss_reasoning_text(finding)
        if cvss_txt:
            out["cvss_reasoning"] = cvss_txt
        out["confidence_explanation"] = self._confidence_explanation_text(finding)
        return out

    def _technical_context_block(self, finding: dict) -> str:
        url      = _clip(_as_str(finding.get("url")), _CLIP_TECH)
        param    = _as_str(finding.get("parameter")).strip()
        payload  = _as_str(finding.get("payload")).strip()
        evidence = _as_str(finding.get("evidence"))
        lines: list[str] = []
        ae = finding.get("affected_endpoints")
        if isinstance(ae, list) and len(ae) > 1:
            shown = [_clip(_as_str(u), 180) for u in ae[:40]]
            tail = ""
            if len(ae) > 40:
                tail = f" … (+{len(ae) - 40} more)"
            lines.append(
                f"Merged finding — {len(ae)} affected endpoint(s): "
                + "; ".join(shown)
                + tail
            )
        elif url and url.upper() not in ("N/A", ""):
            lines.append(f"Engagement-specific target: {url}")
        if param and param.upper() not in ("N/A", "", "CHAIN ANALYSIS"):
            lines.append(f"Affected input surface: «{_clip(param, 120)}»")
        if payload and payload.upper() not in ("N/A", ""):
            lines.append(
                "Payload / probe behavior (excerpt): "
                f"{_clip(payload.replace(chr(10), ' '), _CLIP_PAY)}"
            )
        beh = _observable_behavior(evidence, finding)
        if beh:
            lines.append(f"Observable behavior: {beh}")
        elif evidence:
            lines.append(
                "Evidence snapshot (excerpt): "
                f"{_clip(evidence.replace(chr(10), ' '), _CLIP_EV)}"
            )
        return "\n".join(lines) if lines else ""

    def _chain_technical_context(self, finding: dict) -> str:
        parts: list[str] = []
        req = _as_str(finding.get("payload"))
        if req:
            parts.append(
                "Chained prerequisites (finding types that must coexist): "
                f"{_clip(req, _CLIP_PAY)}"
            )
        steps = finding.get("attack_steps") or []
        if isinstance(steps, list) and steps:
            path = " → ".join(_clip(_as_str(s), 120) for s in steps[:10])
            parts.append(f"Documented kill chain: {path}")
        rfa = finding.get("risk_amplification")
        if rfa:
            parts.append(f"Risk amplification: {_clip(_as_str(rfa), 220)}")
        conf = finding.get("chain_confidence") or finding.get("confidence")
        if conf is not None:
            try:
                parts.append(f"Chain confidence score: {float(conf):.0%}")
            except Exception:
                pass
        return "\n".join(parts)

    def _stakeholder_impact_lines(self, finding: dict, ai_block: dict) -> str:
        ftype  = _as_str(finding.get("type")).lower()
        sev    = _as_str(finding.get("severity")).upper()
        url_l  = _as_str(finding.get("url")).lower()
        bullets: list[str] = []

        if any(k in ftype for k in ("sql", "cmdi", "command injection", "os command")):
            bullets.append(
                "Material risk of data breach, data integrity loss, or total application "
                "compromise — custodial databases and OS shells are high-value targets."
            )
        if "xss" in ftype or "cross-site" in ftype:
            bullets.append(
                "Account takeover and session theft: stolen cookies or tokens enable action "
                "on behalf of legitimate users without their knowledge."
            )
        if "csrf" in ftype:
            bullets.append(
                "Fraudulent state-changing actions (transfers, profile or password changes) "
                "can be driven through the victim's existing authenticated session."
            )
        if "open redirect" in ftype:
            bullets.append(
                "Brand-trust abuse: attackers use your domain in phishing URLs, increasing "
                "click-through and enabling wire-fraud / credential-harvesting campaigns."
            )
        if "swagger" in ftype or "openapi" in ftype or "api exposure" in ftype:
            bullets.append(
                "Accelerated targeted attacks: detailed API maps shorten the path from "
                "reconnaissance to exploitation for competitors and criminal groups."
            )
        if finding.get("chain"):
            # §5 business impact labels
            bi_labels = (ai_block.get("business_impacts") or [])
            if bi_labels:
                bullets.append(
                    "Chained attack enables: " + ", ".join(bi_labels) + ". "
                    "Compounded impact often produces executive-visible outcomes faster than isolated bugs."
                )
            else:
                bullets.append(
                    "Compounded business impact: chained issues often reach executive-visible "
                    "outcomes (widespread outage, major incident, regulatory scrutiny) "
                    "faster than isolated bugs."
                )
        if "admin" in url_l:
            bullets.append(
                "Administrative surfaces disproportionately affect confidentiality, integrity, "
                "and availability for the entire tenant or customer base."
            )
        if not bullets:
            if sev in ("CRITICAL", "HIGH"):
                bullets.append(
                    "Elevated likelihood of unauthorised access or meaningful misuse — prioritise "
                    "validation and remediation in line with your incident-response playbooks."
                )
            else:
                bullets.append(
                    "May increase organizational risk when combined with other findings or "
                    "weak detective controls; track through risk register and security roadmap."
                )

        prefix = str(ai_block.get("business_impact") or "").strip()
        lines_out: list[str] = []
        if prefix:
            lines_out.append(prefix)
        lines_out.extend(f"• {b}" for b in bullets[:6])
        return "\n".join(lines_out)

    def _cvss_reasoning_text(self, finding: dict) -> str:
        sev = _as_str(finding.get("severity")).upper()
        sc  = finding.get("scoring")
        if finding.get("chain"):
            cv_raw = finding.get("cvss_score", 0)
            try:
                cv = float(cv_raw)
            except (TypeError, ValueError):
                cv = 0.0
            if cv >= 9.0 or sev == "CRITICAL":
                return (
                    "Chain severity reflects combined attack-path impact: multiple validated "
                    f"weaknesses form one operational exploit sequence (aggregate score {cv_raw}). "
                    "Compounding effects justify executive prioritisation alongside standalone CVSS items."
                )
            return ""
        if not isinstance(sc, dict):
            return ""
        base = sc.get("base_cvss")
        try:
            base_f = float(base)
        except (TypeError, ValueError):
            base_f = 0.0
        if sev != "CRITICAL" and base_f < 9.0:
            return ""
        parts = [
            f"The base CVSS v3.1 score ({base_f}) encodes how confidentiality, integrity, and "
            "availability would be affected if the flaw is successfully exploited."
        ]
        vec = sc.get("cvss_vector")
        if vec and str(vec).upper() not in ("N/A", "NONE", ""):
            parts.append(
                f"The vector string ({vec}) records privileges required, user interaction, scope, "
                "and the underlying impact metrics."
            )
        band = sc.get("severity_band") or sev
        env  = sc.get("environmental_score")
        temp = sc.get("temporal_score")
        if env is not None and temp is not None:
            parts.append(
                f"Temporal score ({temp}) and environmental score ({env}) adjust the base score; "
                f"the reported band ({band}) aligns with this adjusted view."
            )
        exp = sc.get("exploitability")
        if exp:
            parts.append(
                f"Exploitability is rated «{exp}» based on how clearly the scanner could reproduce "
                "a security-relevant differential with the supplied payload and evidence."
            )
        return " ".join(parts)

    def _confidence_explanation_text(self, finding: dict) -> str:
        val   = finding.get("validation")
        if not isinstance(val, dict):
            val = {}
        label  = _as_str(val.get("confidence_label", "MEDIUM")).upper()
        evs    = _as_str(val.get("evidence_strength", "")).strip()
        verify = _as_str(val.get("verification_status", "")).strip()
        try:
            num = float(finding.get("confidence", 0.0))
        except (TypeError, ValueError):
            num = 0.0
        label_phrase = {
            "HIGH": (
                "HIGH confidence: the scanner observed a strong, repeatable signal (clear error, "
                "consistent timing delta, deterministic response differentiation, or direct "
                "proof-of-concept behavior)."
            ),
            "MEDIUM": (
                "MEDIUM confidence: evidence is indicative but may share causes with "
                "application logic, WAF behaviors, or flaky inputs — manual verification is appropriate."
            ),
            "LOW": (
                "LOW confidence: the signal is weak, inconsistent, or heuristic — treat as a "
                "lead for manual testing rather than a standalone production claim."
            ),
        }.get(label) or "Confidence reflects automated validation labels and scanner-side heuristics."
        parts = [label_phrase]
        if num > 0:
            parts.append(
                f"Numeric confidence from the detector workflow: {num:.2f} "
                "(higher = stronger agreement between probes / validators)."
            )
        if evs:
            parts.append(f"Evidence strength note: {evs}")
        if verify:
            parts.append(f"Validation category: {verify}")
        return " ".join(parts)

    def _get_ai_analysis(self, ftype: str, finding: dict) -> dict:
        """Return a finding-specific AI analysis block. No raw internal type strings surfaced verbatim."""
        fl       = ftype.lower()
        url      = finding.get("url", "")
        param    = finding.get("parameter", "")
        evidence = str(finding.get("evidence", ""))

        if "open redirect" in fl:
            return {
                "plain_english": (
                    "The application redirects users to attacker-controlled URLs without validation. "
                    "This is commonly abused in phishing campaigns because the initial URL belongs to a "
                    "trusted domain — victims are far more likely to click a link to a known brand."
                ),
                "business_impact": (
                    f"Enables highly convincing phishing attacks using {_host(url)} as a trusted intermediary. "
                    "Credential theft can lead to account compromise, data breach, and reputational damage."
                ),
                "fix_steps": [
                    "Validate the redirect destination against an explicit allowlist of permitted domains.",
                    "Use relative paths instead of absolute URLs wherever possible.",
                    "Display an interstitial warning page before redirecting to external sites.",
                    "Log and alert on redirect attempts to unexpected domains.",
                ],
                "fix_priority": 6,
                "time_to_exploit": "Minutes — URL crafting only",
                "skill_required": "Low — no special tools needed",
            }

        if "method tamper" in fl or "trace" in fl:
            return {
                "plain_english": (
                    "The server responds to non-standard HTTP methods (TRACE, DELETE, PUT) that should not be "
                    "exposed publicly. TRACE can be used in Cross-Site Tracing (XST) attacks to steal "
                    "HttpOnly cookies. Dangerous method exposure can allow unintended data modification."
                ),
                "business_impact": (
                    "TRACE enables cookie theft bypassing HttpOnly protection. PUT/DELETE on endpoints can "
                    "allow unauthorised data modification or deletion."
                ),
                "remediation_steps": [
                    "Disable TRACE at the web server level (Apache: TraceEnable off; Nginx: limit_except).",
                    "Remove PUT/DELETE from Allow header on endpoints that do not require them.",
                    "Audit all OPTIONS responses to confirm only required methods are listed.",
                ],
                "remediation_code": (
                    "# Nginx:\nlimit_except GET POST { deny all; }\n\n"
                    "# Apache:\nTraceEnable off\n"
                    "<LimitExcept GET POST>\n  Deny from all\n</LimitExcept>"
                ),
                "fix_priority": 4,
                "fix_effort": "Low (0.5 dev day — config change)",
            }

        if "sql" in fl:
            subtype = ("error-based" if "error" in fl else
                       "blind" if ("blind" in fl or "boolean" in fl) else
                       "time-based" if "time" in fl else "generic")
            plain = {
                "error-based": "Database error messages are returned in HTTP responses, "
                               "allowing an attacker to extract the full schema and bypass "
                               "authentication without any specialised tools.",
                "blind":       "The application behaves differently for true/false SQL conditions, "
                               "allowing full database extraction character by character.",
                "time-based":  "The database introduces measurable delays when injected — an attacker "
                               "can infer all data even when errors and response differences are suppressed.",
                "generic":     "SQL injection lets an attacker manipulate the database query, enabling "
                               "authentication bypass, data theft, and potentially remote code execution.",
            }[subtype]
            return {
                "plain_english": plain,
                "business_impact": (
                    f"Potential database compromise on {_host(url)}. Authentication bypass means any "
                    "account — including admins — can be accessed without credentials. GDPR/HIPAA "
                    "fines up to €20M or 4% of global annual turnover for data exposure."
                ),
                "remediation_steps": [
                    "Replace all string-concatenated queries with parameterised statements (prepared statements).",
                    "Apply least-privilege to database accounts — remove FILE/EXEC grants.",
                    "Disable verbose database error messages in production (map to generic HTTP 500).",
                    "Deploy a WAF rule for SQLi payloads as a defence-in-depth layer.",
                ],
                "remediation_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "fix_priority": 10,
                "fix_effort": "Medium (2–3 dev days per affected endpoint)",
            }

        if "xss" in fl or "cross-site script" in fl:
            is_dom    = "dom" in fl
            is_stored = "stored" in fl or "persistent" in fl
            xss_type  = "DOM-based" if is_dom else ("Stored" if is_stored else "Reflected")
            scale = " Every visitor to the page is affected." if is_stored else ""
            return {
                "plain_english": (
                    f"{xss_type} XSS on the `{param}` parameter allows an attacker to inject JavaScript "
                    f"that executes in victims' browsers.{scale}"
                ),
                "business_impact": (
                    f"Session token theft, credential harvesting, or silent redirection to phishing pages "
                    f"affecting users of {_host(url)}."
                ),
                "remediation_steps": [
                    "Apply context-aware output encoding at every render point (HTML, attribute, JS, URL).",
                    "Implement a strict Content-Security-Policy (nonce- or hash-based).",
                    "Set HttpOnly and SameSite=Strict on all session cookies.",
                    "Use framework auto-escaping — never disable it for user-controlled data.",
                ],
                "remediation_code": (
                    "// Safe — use textContent, not innerHTML:\n"
                    "el.textContent = userInput;\n\n"
                    "// Or with DOMPurify for HTML content:\n"
                    "el.innerHTML = DOMPurify.sanitize(userInput);"
                ),
                "fix_priority": 9 if is_stored else 8,
                "fix_effort": "Medium (1–2 dev days per affected parameter)",
            }

        if "csrf" in fl:
            is_origin = "origin" in fl or "referer" in fl
            action    = ("does not validate the Origin/Referer header" if is_origin
                         else "has no anti-CSRF token")
            return {
                "plain_english": (
                    f"The endpoint `{url}` {action}, allowing a malicious website to silently "
                    "trigger authenticated actions on behalf of any logged-in user."
                ),
                "business_impact": (
                    "An attacker can change passwords, transfer data, or perform any privileged action "
                    "the victim's session permits — without user awareness."
                ),
                "remediation_steps": [
                    "Implement the Synchronizer Token Pattern: generate a cryptographically random CSRF token per session.",
                    "Set SameSite=Strict (or Lax) on all session cookies.",
                    "Validate the Origin and Referer headers against an explicit allowlist.",
                ],
                "remediation_code": (
                    '<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">\n'
                    "# Server-side:\n"
                    'if request.form["csrf_token"] != session["csrf_token"]: abort(403)'
                ),
                "fix_priority": 7,
                "fix_effort": "Low (0.5–1 dev day — framework middleware available for most stacks)",
            }

        if "cmdi" in fl or "command injection" in fl or "os command" in fl:
            confirmed = any(sig in evidence.lower() for sig in ["apache", "www-data", "uid=", "root:"])
            conf_note = (
                " The scanner confirmed this by observing real command output in the HTTP response — "
                "this is actively exploitable, not theoretical."
                if confirmed else ""
            )
            return {
                "plain_english": (
                    f"User-controlled input on the `{param}` parameter is passed directly to a system "
                    f"shell call, allowing arbitrary OS commands to execute with the web-server's privileges.{conf_note}"
                ),
                "business_impact": (
                    f"Potential server compromise on {_host(url)}: an attacker can read/write arbitrary files, "
                    "establish a reverse shell, pivot to internal networks, and exfiltrate all data."
                ),
                "remediation_steps": [
                    "Never pass user input to shell execution functions (os.system, subprocess with shell=True, exec, popen).",
                    "Use language-native APIs instead of shelling out.",
                    "If a shell call is unavoidable, use a strict allowlist for every argument.",
                    "Run the web server under a least-privilege OS account.",
                ],
                "remediation_code": (
                    "# UNSAFE:\nos.system(f'convert {user_input} output.png')\n\n"
                    "# SAFE — list form, shell=False:\n"
                    "subprocess.run(['convert', user_input, 'output.png'], shell=False, check=True)"
                ),
                "fix_priority": 10,
                "fix_effort": "Medium (1–3 dev days depending on shell call count)",
            }

        if "hsts" in fl:
            return {
                "plain_english": (
                    "The site serves HTTPS but omits the Strict-Transport-Security header, "
                    "allowing browsers to downgrade connections to plaintext HTTP — enabling SSL-stripping attacks."
                ),
                "business_impact": (
                    "An attacker on the same network can silently intercept session tokens and "
                    "credentials by stripping TLS before the browser enforces it."
                ),
                "remediation_steps": [
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    "Submit the domain to hstspreload.org once the header is stable.",
                    "Ensure no mixed HTTP content is served.",
                ],
                "remediation_code": (
                    "# Nginx:\nadd_header Strict-Transport-Security "
                    "'max-age=31536000; includeSubDomains; preload' always;\n\n"
                    "# Apache:\nHeader always set Strict-Transport-Security "
                    "'max-age=31536000; includeSubDomains; preload'"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (< 1 hour — single server config line)",
            }

        if (
            "missing security header" in fl
            or ("header" in fl and "missing" in fl)
            or ("security header" in fl)
        ):
            missing = _extract_missing_headers(evidence)
            return {
                "plain_english": (
                    f"Several HTTP security headers are absent from responses on {_host(url)}, "
                    "weakening the browser's built-in defences against XSS, clickjacking, and MIME-sniffing."
                ),
                "business_impact": (
                    "Missing CSP amplifies XSS (no browser-side mitigation). "
                    "Missing X-Frame-Options enables clickjacking. "
                    "Missing X-Content-Type-Options enables MIME-sniffing attacks."
                ),
                "remediation_steps": [
                    f"Add these headers to every response: {', '.join(missing) if missing else 'CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy'}.",
                    "Use a nonce- or hash-based CSP — avoid 'unsafe-inline'.",
                    "Set X-Frame-Options: DENY.",
                    "Automate header auditing in CI/CD (securityheaders.com).",
                ],
                "remediation_code": (
                    "# Nginx:\nadd_header Content-Security-Policy \"default-src 'self'\" always;\n"
                    "add_header X-Frame-Options DENY always;\n"
                    "add_header X-Content-Type-Options nosniff always;"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (1–2 hours — server config, no code changes needed)",
            }

        if "exposed path" in fl or "exposed path / file" in fl:
            is_admin = "admin" in url.lower()
            return {
                "plain_english": (
                    f"{'The admin panel at' if is_admin else 'A sensitive path at'} `{url}` is "
                    "publicly reachable. Even if access-controlled, its existence aids attacker reconnaissance."
                ),
                "business_impact": (
                    "Admin panel exposure enables credential brute-forcing and CSRF-based takeover."
                    if is_admin else
                    "Exposed paths may contain backup files, credentials, or source code."
                ),
                "remediation_steps": [
                    "Remove files and directories that should not be in the web root.",
                    "Configure the server to return a genuine 404 (not 403) for sensitive paths.",
                    "Restrict admin interfaces to trusted IP ranges.",
                    "Implement MFA and account lockout on all admin login forms.",
                ],
                "remediation_code": (
                    "# Nginx — restrict admin to internal IPs:\nlocation /admin {\n"
                    "  allow 10.0.0.0/8;\n  deny all;\n}"
                ),
                "fix_priority": 6,
                "fix_effort": "Low (< 1 day — config + file cleanup)",
            }

        if "swagger" in fl or "openapi" in fl or "api exposure" in fl:
            return {
                "plain_english": (
                    f"The Swagger/OpenAPI documentation UI is publicly accessible on {_host(url)}. "
                    "It enumerates every API endpoint, parameter, and expected data type — "
                    "providing attackers a complete map of the application's attack surface."
                ),
                "business_impact": (
                    "Exposed API docs dramatically accelerate targeted attacks by eliminating the "
                    "reconnaissance phase."
                ),
                "remediation_steps": [
                    "Restrict the Swagger UI and spec file to authenticated users or internal IPs only.",
                    "Disable the Swagger UI entirely in production environments.",
                    "If public API docs are required, remove sensitive endpoints and example credentials from the spec.",
                ],
                "remediation_code": (
                    "# Spring Boot — disable in production:\n"
                    "springdoc.swagger-ui.enabled=${SWAGGER_ENABLED:false}\n\n"
                    "# Nginx — block in prod:\n"
                    "location ~* ^/swagger { deny all; return 404; }"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (< 1 hour — config change)",
            }

        if "waf" in fl and ("detected" in fl or "status" in fl):
            no_waf = "no waf" in fl or "not detected" in fl
            if no_waf:
                return {
                    "plain_english": (
                        f"No Web Application Firewall was detected in front of {_host(url)}. "
                        "All malicious requests reach the application directly with no intermediary filtering."
                    ),
                    "business_impact": (
                        "Without a WAF, exploitation of the injection and XSS findings in this report "
                        "is trivially automated."
                    ),
                    "remediation_steps": [
                        "Deploy a managed WAF (Cloudflare, AWS WAF, ModSecurity + OWASP CRS).",
                        "Enable OWASP Core Rule Set at minimum — tune before enforcing.",
                        "Treat the WAF as defence-in-depth, not a substitute for fixing vulnerabilities.",
                    ],
                    "remediation_code": (
                        "# ModSecurity + OWASP CRS (Nginx):\n"
                        "modsecurity on;\n"
                        "Include /etc/nginx/modsec/crs/rules/*.conf;"
                    ),
                    "fix_priority": 5,
                    "fix_effort": "Medium (1–2 days for initial WAF deployment and tuning)",
                }
            else:
                return {
                    "plain_english": (
                        f"A Web Application Firewall is active and protecting {_host(url)}. "
                        "This is a positive security control."
                    ),
                    "business_impact": (
                        "The WAF may delay or mitigate some findings. However, WAFs can be bypassed "
                        "and do not substitute for fixing underlying vulnerabilities."
                    ),
                    "remediation_steps": [
                        "Keep WAF rule sets updated — subscribe to vendor security advisories.",
                        "Regularly test bypass techniques to validate rule effectiveness.",
                        "Monitor WAF logs for blocked requests.",
                    ],
                    "remediation_code": (
                        "# Review WAF audit logs:\n"
                        "tail -f /var/log/modsec_audit.log | grep -i 'CRITICAL\\|ERROR'"
                    ),
                    "fix_priority": 3,
                    "fix_effort": "Low (ongoing maintenance — no immediate action required)",
                }

        if "information disclosure" in fl or ("disclosure" in fl and "header" in fl):
            return {
                "plain_english": (
                    "The server response header reveals the web-server software and version. "
                    "This gives attackers a precise target for CVE database lookups."
                ),
                "business_impact": (
                    "Version fingerprinting is the first step in targeted exploitation."
                ),
                "remediation_steps": [
                    "Remove or suppress the Server, X-Powered-By, and X-AspNet-Version headers.",
                    "Configure the server to return a generic or empty server banner.",
                    "Ensure error pages do not disclose software versions or stack traces.",
                ],
                "remediation_code": (
                    "# Nginx:\nserver_tokens off;\n\n"
                    "# Apache:\nServerTokens Prod\nServerSignature Off\n\n"
                    "# Tomcat (server.xml):\n<Connector server=\" \" />"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (< 1 hour — single config line)",
            }

        if "tls" in fl or "ssl" in fl or "cipher" in fl:
            return {
                "plain_english": (
                    "The server negotiates TLS 1.2 instead of TLS 1.3 or uses older cipher suites. "
                    "TLS 1.3 removes all legacy cipher suites and eliminates several known protocol attacks."
                ),
                "business_impact": (
                    "PCI-DSS 4.0 requires TLS 1.2 as a minimum and recommends TLS 1.3."
                ),
                "remediation_steps": [
                    "Configure the server to prefer TLS 1.3 and disable TLS 1.0 and 1.1.",
                    "Use a modern cipher suite list — consult Mozilla's SSL Configuration Generator.",
                    "Test with testssl.sh or Qualys SSL Labs after changes.",
                ],
                "remediation_code": (
                    "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;\n"
                    "ssl_ciphers ECDH+AESGCM:ECDH+CHACHA20:!aNULL:!MD5;\n\n"
                    "# Apache:\nSSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (< 1 hour — server config)",
            }

        if "cookie" in fl:
            return {
                "plain_english": (
                    f"The session cookie ({param or 'session token'}) lacks the SameSite attribute, "
                    "meaning it is sent with cross-site requests — enabling CSRF attacks."
                ),
                "business_impact": (
                    "Without SameSite, cross-site requests silently carry the session cookie. "
                    "This compounds every CSRF finding in this report."
                ),
                "remediation_steps": [
                    "Set SameSite=Strict on all session cookies.",
                    "Add the Secure flag to prevent transmission over HTTP.",
                    "Add the HttpOnly flag to prevent JavaScript access to session tokens.",
                ],
                "remediation_code": (
                    "# Python Flask:\n"
                    "app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'\n"
                    "app.config['SESSION_COOKIE_SECURE']   = True\n"
                    "app.config['SESSION_COOKIE_HTTPONLY'] = True"
                ),
                "fix_priority": 5,
                "fix_effort": "Low (< 1 hour — framework config change)",
            }

        if "dom" in fl and "xss" in fl:
            return {
                "plain_english": (
                    f"A dangerous DOM sink (innerHTML or equivalent) was identified in a JavaScript "
                    f"file served from {_host(url)}. If any user-controlled value reaches this sink, "
                    "client-side XSS is possible without any server involvement."
                ),
                "business_impact": (
                    "DOM XSS bypasses server-side output encoding entirely. "
                    "It can be exploited through URL fragments, postMessage data, or stored values."
                ),
                "remediation_steps": [
                    "Replace innerHTML with element.textContent for plain text.",
                    "Use DOMPurify for HTML content that must be rendered.",
                    "Audit all JavaScript for dangerous sinks: innerHTML, outerHTML, document.write, eval.",
                    "Add eslint-plugin-no-unsanitized to your CI linting pipeline.",
                ],
                "remediation_code": (
                    "// UNSAFE:\ndiv.innerHTML = userControlledData;\n\n"
                    "// SAFE:\ndiv.textContent = userControlledData;\n\n"
                    "// Or for HTML:\nimport DOMPurify from 'dompurify';\n"
                    "div.innerHTML = DOMPurify.sanitize(userControlledData);"
                ),
                "fix_priority": 8,
                "fix_effort": "Medium (review all JS files — 1–3 dev days)",
            }

        # Generic fallback — no raw ftype in plain_english
        sev = finding.get("severity", "MEDIUM")
        sev_context = {
            "CRITICAL": "This is a critical-severity finding — active exploitation is likely possible without authentication and requires immediate action.",
            "HIGH":     "This high-severity finding should be addressed within 7 days.",
            "MEDIUM":   "This medium-severity finding should be remediated within 30 days.",
            "LOW":      "This low-severity finding should be addressed within 90 days.",
            "INFO":     "This is informational — no immediate action required.",
        }.get(sev, "This finding requires investigation and remediation.")
        return {
            "plain_english": (
                f"A {sev.lower()}-severity security issue was identified at `{_host(url) or url}` "
                f"affecting the `{param}` parameter. {sev_context}"
            ),
            "business_impact": {
                "CRITICAL": "Immediate risk of complete application or server compromise.",
                "HIGH":     "Significant risk of data exposure or unauthorised access.",
                "MEDIUM":   "Exploitable under specific conditions — contributes to attack chains.",
                "LOW":      "Limited direct impact but may assist reconnaissance.",
                "INFO":     "Informational — no direct security impact.",
            }.get(sev, "Security risk requiring assessment."),
            "remediation_steps": [
                "Review the evidence and PoC in the full finding detail.",
                "Apply appropriate input validation and output encoding for the affected parameter.",
                "Consult the relevant OWASP guidance for this vulnerability class.",
            ],
            "remediation_code": "# See the full finding detail for specific remediation guidance.",
            "fix_priority": {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1}.get(sev, 5),
            "fix_effort":   {"CRITICAL": "Medium–High", "HIGH": "Medium",
                             "MEDIUM": "Low–Medium", "LOW": "Low", "INFO": "Low"}.get(sev, "Medium"),
        }

    # ── Global AI summary builders ────────────────────────────────────────────

    def _build_vulnerability_summary(self, findings: list) -> str:
        if not findings:
            return ""
        counts = _count_sevs(findings)
        bits   = [f"{counts[s]} {s}" for s in counts if counts.get(s, 0)]
        sev_part = ", ".join(bits) if bits else "0 issues"
        types = Counter(_clean_type(str(f.get("type", "Unknown"))) for f in findings)
        top   = ", ".join(f"{n} ({c})" for n, c in types.most_common(12))
        tgt   = _extract_target(findings) or "the assessed target"
        return (
            f"{len(findings)} validated issue(s) against {tgt} ({sev_part}). "
            f"Issue classes observed: {top}."
        )

    def _build_risk_explanation(self, findings: list, overall_risk: str) -> str:
        counts = _count_sevs(findings)
        n      = len(findings)
        parts  = [f"The highest observed severity across {n} validated finding(s) is {overall_risk}."]
        if counts.get("CRITICAL", 0) or counts.get("HIGH", 0):
            parts.append(
                "Critical or high-severity issues materially raise the likelihood of targeted exploitation "
                "and shorten the time an attacker needs to obtain a meaningful foothold."
            )
        elif counts.get("MEDIUM", 0):
            parts.append(
                "Medium-severity findings often require more constrained conditions to exploit, "
                "but can still combine with other weaknesses or misconfiguration."
            )
        else:
            parts.append(
                "Lower-severity or informational items may still aid reconnaissance or compliance gaps "
                "and should be tracked to closure where relevant."
            )
        chains = sum(1 for f in findings if f.get("chain"))
        if chains:
            parts.append(
                f"{chains} validated multi-step attack chain(s) were detected — combined issues "
                "often produce greater business impact than the same bugs assessed in isolation."
            )
        parts.append(
            "Residual exposure depends on scan scope (coverage, authentication, and environment); "
            "manual validation remains essential for production systems."
        )
        return " ".join(parts)

    def _build_attack_chain_description(self, chain_findings: list) -> str:
        """§5: Step-by-step attack flow with confidence scores, deduplication, and business impact."""
        if not chain_findings:
            return (
                "No multi-step attack chains were identified from the validated finding set "
                "for this run."
            )

        # §5 Deduplicate similar chains by type
        seen_types: set[str] = set()
        deduped: list[dict]  = []
        for c in chain_findings:
            t = _clean_type(str(c.get("type", "Chain"))).lower()
            if t not in seen_types:
                seen_types.add(t)
                deduped.append(c)

        blocks = []
        for i, c in enumerate(deduped, 1):
            title  = _clean_type(str(c.get("type", "Chain")))
            if title.upper().startswith("VULNERABILITY CHAIN:"):
                title = title.split(":", 1)[-1].strip()

            steps = c.get("attack_steps") or []
            if steps and isinstance(steps, list):
                path = "\n".join(f"  Step {j+1}: {str(s)}" for j, s in enumerate(steps[:10]))
            else:
                path = "  See evidence for path detail."

            sev  = str(c.get("severity", ""))
            imp  = str(c.get("impact_description", "") or "").strip()
            rel  = c.get("related_finding_ids") or []
            rel_n = len(rel) if isinstance(rel, list) else 0

            # §5 confidence
            conf_raw = c.get("confidence") or c.get("chain_confidence") or 0
            try:
                conf_pct = f"{float(conf_raw):.0%}"
            except Exception:
                conf_pct = "N/A"

            # §5 business impacts
            ai_bl = c.get("ai_analysis") or {}
            bi_labels = ai_bl.get("business_impacts") or []
            impact_line = f" Potential outcomes: {', '.join(bi_labels)}." if bi_labels else ""
            tail = f"\n  Impact: {imp}" if imp else ""

            blocks.append(
                f"{i}. [{sev}] {title} (confidence: {conf_pct})\n"
                f"{path}{tail}{impact_line}\n"
                f"  Linked findings: {rel_n}"
            )
        return (
            "Validated attack paths (ordered, deduplicated):\n\n"
            + "\n\n".join(blocks)
        )

    def _build_stakeholder_summary(self, findings: list, overall_risk: str) -> str:
        if not findings:
            return (
                "Leadership takeaway: no issues met the validated finding bar in this pass. "
                "Investment should continue in coverage and control monitoring."
            )
        crit   = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs  = [f for f in findings if f.get("severity") == "HIGH"]
        chains = sum(1 for f in findings if f.get("chain"))
        tgt    = _extract_target(findings) or "in-scope applications"
        parts  = [
            f"Executive view — assessed posture for {tgt}: highest severity band observed is "
            f"{overall_risk} across {len(findings)} validated issue(s). "
            "Discuss funding and ownership with engineering and GRC while fixes are tracked."
        ]
        if crit:
            parts.append(
                f"{len(crit)} CRITICAL finding(s) can justify breach-response preparedness: scenarios "
                "include mass credential compromise, privileged account takeover, and regulatory notification."
            )
        if highs:
            parts.append(
                f"{len(highs)} HIGH finding(s) should be on departmental OKRs or risk registers with "
                "a clear deadline — attackers routinely chain these into incidents within days."
            )
        if chains:
            parts.append(
                f"{chains} validated attack chain(s) show how several «medium» issues become one "
                "«critical» business event; prioritise breaking the chain, not only the easiest control."
            )
        if not crit and not highs:
            parts.append(
                "No CRITICAL/HIGH labels in this report lowers emergency incident likelihood, but "
                "medium and informational items can still create audit findings and technical debt."
            )
        return " ".join(parts)

    def _build_executive_summary(self, findings: list) -> str:
        counts = _count_sevs(findings)
        total  = len(findings)
        crits  = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs  = [f for f in findings if f.get("severity") == "HIGH"]
        crit_types = _unique_types(crits, limit=3)
        high_types = _unique_types(highs, limit=2)
        crit_sentence = ""
        if crit_types:
            crit_sentence = (
                f" Critical findings include {_join_types(crit_types)}, "
                f"which {'are' if len(crit_types) > 1 else 'is'} directly exploitable "
                "without authentication and represent an immediate risk of potential compromise."
            )
        high_sentence = ""
        if high_types:
            high_sentence = (
                f" High-severity findings include {_join_types(high_types)}, "
                "which should be addressed within 7 days."
            )
        no_waf   = any("no waf" in str(f.get("type", "")).lower() for f in findings)
        has_sqli = any("sql" in str(f.get("type", "")).lower() for f in findings)
        has_cmdi = any(("cmdi" in str(f.get("type", "")).lower() or
                        "command injection" in str(f.get("type", "")).lower()) for f in findings)
        risk_amplifier = ""
        if no_waf and (has_sqli or has_cmdi):
            risk_amplifier = (
                " No Web Application Firewall was detected — all injection payloads reach "
                "the application directly with no intermediary filtering, maximising exploitation risk."
            )
        crit_high_recommendation = ""
        if crits or highs:
            crit_high_recommendation = (
                f" Immediate remediation of all "
                f"{'CRITICAL ' if crits else ''}"
                f"{'and ' if crits and highs else ''}"
                f"{'HIGH ' if highs else ''}"
                "findings is strongly recommended to prevent active exploitation and data breach."
            )
        target = _extract_target(findings)
        return (
            f"AlanScan identified {total} security findings across {_sev_summary_str(counts)} "
            f"severity levels on {target or 'the target application'}."
            f"{crit_sentence}"
            f"{high_sentence}"
            f"{risk_amplifier}"
            f"{crit_high_recommendation}"
        )

    def _build_top3_priorities(self, findings: list) -> str:
        sorted_f = sorted(
            findings,
            key=lambda f: (
                _SEV_ORDER.get(f.get("severity", "INFO"), 4),
                -float(f.get("scoring", {}).get("base_cvss", 0)
                       if isinstance(f.get("scoring"), dict) else 0),
            )
        )
        unique_sorted: list[dict] = []
        seen: set = set()
        for f in sorted_f:
            ftype = _clean_type(f.get("type", "")).lower()
            if f.get("chain"):
                cid = str(f.get("chain_id", "") or f.get("finding_id", "") or "")
                key: Any = ("chain", ftype, cid)
            else:
                burl = _base_url_only(f.get("url", ""))
                key = (ftype, burl)
            if key in seen:
                continue
            seen.add(key)
            unique_sorted.append(f)

        lines = []
        for i, f in enumerate(unique_sorted[:3], 1):
            ftype   = _clean_type(f.get("type", "Unknown"))
            url     = f.get("url", "")
            sev     = f.get("severity", "")
            scoring = f.get("scoring", {})
            cvss    = scoring.get("base_cvss", "") if isinstance(scoring, dict) else ""
            cvss_str = f" (CVSS {cvss})" if cvss else ""
            lines.append(f"{i}. [{sev}] {ftype}{cvss_str} — {_host(url) or url}")
        return "\n".join(lines) if lines else "No findings to prioritise."

    def _build_attacker_perspective(self, findings: list) -> str:
        """§5: Attacker path — real-world scenario from attacker's viewpoint."""
        has_sqli  = any("sql" in str(f.get("type", "")).lower() for f in findings)
        has_cmdi  = any(("cmdi" in str(f.get("type", "")).lower() or
                         "command injection" in str(f.get("type", "")).lower()) for f in findings)
        has_xss   = any("xss" in str(f.get("type", "")).lower() for f in findings)
        has_csrf  = any("csrf" in str(f.get("type", "")).lower() for f in findings)
        has_admin = any("admin" in str(f.get("url", "")).lower() for f in findings)
        no_waf    = any("no waf" in str(f.get("type", "")).lower() for f in findings)
        chain_n   = sum(1 for f in findings if f.get("chain"))
        parts: list[str] = []
        if chain_n:
            parts.append(
                f"{chain_n} validated multi-step attack chain(s) were identified: adversaries can "
                "operationalise several weaknesses as one end-to-end exploit story rather than isolated bugs."
            )
        if no_waf:
            parts.append("There is no WAF in place — automated exploitation tools can probe every endpoint unimpeded.")
        if has_sqli:
            parts.append(
                "SQL injection on the login form is the highest-value initial target: "
                "it enables authentication bypass and full database extraction in a single step, "
                "without requiring any existing credentials."
            )
        if has_cmdi:
            parts.append(
                "OS command injection provides direct code execution, giving immediate shell access "
                "and the ability to pivot to internal systems."
            )
        if has_xss and has_csrf:
            parts.append(
                "The combination of Reflected XSS and missing CSRF tokens creates a bypass chain: "
                "XSS can steal the CSRF token from the DOM and forge authenticated requests."
            )
        elif has_xss:
            parts.append("Reflected XSS on public-facing pages enables session token theft via crafted URLs.")
        if has_admin:
            parts.append(
                "The admin panel is reachable from the public internet, making it a target "
                "for credential brute-forcing and CSRF-based takeover."
            )
        if not parts:
            parts.append(
                "The application presents multiple exploitable entry points (attacker path). An attacker would begin "
                "by mapping all endpoints, then targeting the highest-CVSS findings for initial access."
            )
        return " ".join(parts)

    def _build_remediation_roadmap(self, findings: list) -> str:
        crits   = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs   = [f for f in findings if f.get("severity") == "HIGH"]
        mediums = [f for f in findings if f.get("severity") == "MEDIUM"]
        lows    = [f for f in findings if f.get("severity") == "LOW"]
        roadmap = []
        if crits:
            roadmap.append(
                f"Phase 1 — Immediate (0–72 hours): Remediate {len(crits)} CRITICAL "
                f"finding(s): {_join_types(_unique_types(crits, 5))}."
            )
        if highs:
            roadmap.append(
                f"Phase 2 — Short-term (within 7 days): Remediate {len(highs)} HIGH "
                f"finding(s): {_join_types(_unique_types(highs, 5))}."
            )
        if mediums:
            roadmap.append(
                f"Phase 3 — Medium-term (within 30 days): Remediate {len(mediums)} MEDIUM "
                f"finding(s): {_join_types(_unique_types(mediums, 5))}."
            )
        if lows:
            roadmap.append(
                f"Phase 4 — Long-term (within 90 days): Address {len(lows)} LOW finding(s) "
                "and informational items."
            )
        roadmap.append(
            "Phase 5 — Ongoing: Deploy WAF, schedule quarterly re-scans, "
            "integrate SAST/DAST into CI/CD pipeline."
        )
        return " | ".join(roadmap)

    def _compliance_impact(self, findings: list) -> str:
        has_sqli = any("sql" in str(f.get("type", "")).lower() for f in findings)
        parts    = ["OWASP Top 10:2021 — multiple categories violated (A01, A03, A05)."]
        if has_sqli:
            parts.append("GDPR Article 32 — data breach risk; fines up to €20M or 4% of global annual turnover.")
            parts.append("PCI-DSS v4.0 Requirements 6.2, 6.3 — injection and XSS must be remediated.")
        parts.append("ISO 27001 Annex A.14 — system acquisition and secure development controls required.")
        return " ".join(parts)

    def _total_fix_effort(self, findings: list) -> str:
        crits   = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        highs   = sum(1 for f in findings if f.get("severity") == "HIGH")
        mediums = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        days    = crits * 2 + highs * 1 + mediums * 0.5
        return (
            f"Estimated {int(days)}–{int(days * 1.5)} developer-days across all severity levels "
            "(excludes WAF deployment and re-testing time)."
        )

    def _calculate_risk(self, findings: list) -> str:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if any(f.get("severity") == sev for f in findings):
                return sev
        return "INFO"

    def _empty_scan_narrative(self) -> dict:
        return {
            "executive_summary": (
                "AlanScan completed this assessment with no validated security findings. "
                "This does not guarantee absence of vulnerabilities — only that none met "
                "the confirmation threshold under this scan configuration."
            ),
            "vulnerability_summary": "No validated vulnerabilities were recorded for this target in this run.",
            "risk_explanation": (
                "Residual risk remains from unassessed URLs, authentication states, business logic, "
                "and components out of scope."
            ),
            "attack_chain_description": "No attack chains were derived because the validated finding set is empty.",
            "stakeholder_summary": (
                "No technical debt items were validated; leadership should confirm coverage adequacy "
                "and maintain investment in preventive controls."
            ),
            "top_3_priorities": (
                "1. Expand coverage (authenticated test, API routes, admin surfaces) if in scope.\n"
                "2. Re-run after remediation or major releases.\n"
                "3. Manually review informational items and defence-in-depth controls (WAF, headers)."
            ),
            "attacker_perspective": (
                "With no validated issues in this pass, an attacker would rely on out-of-scope "
                "techniques or insufficiently covered paths — coverage gaps are the primary residual concern."
            ),
            "remediation_roadmap": (
                "Phase 1: Confirm scan scope and credentials | "
                "Phase 2: Re-scan with broader coverage | "
                "Phase 3: Maintain secure SDLC and monitoring."
            ),
            "compliance_impact": (
                "No finding-driven compliance gaps were flagged; maintain baseline controls "
                "per OWASP ASVS and organizational policy."
            ),
            "overall_risk":     "INFO",
            "total_fix_effort": "None for validated findings — focus effort on coverage and verification.",
            "findings":         [],
            "priority_order":   [],
        }


# ── Module-level helpers ──────────────────────────────────────────────────────

def _host(url: str) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _base_url_only(url: str) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url.split("?", 1)[0]


def _extract_target(findings: list) -> str:
    for f in findings:
        h = _host(f.get("url", ""))
        if h:
            return h
    return ""


def _count_sevs(findings: list) -> dict:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.get("severity", "INFO")
        if s in c:
            c[s] += 1
    return c


def _sev_summary_str(counts: dict) -> str:
    parts = [f"{counts[s]} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if counts.get(s, 0)]
    if not parts:
        return "multiple"
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def _unique_types(findings: list, limit: int = 3) -> list:
    seen: list = []
    for f in findings:
        t = _clean_type(f.get("type", ""))
        if t and t not in seen:
            seen.append(t)
        if len(seen) >= limit:
            break
    return seen


def _clean_type(ftype: str) -> str:
    t = re.sub(
        r'\s*\((?:POST|GET|Output-Based|Blind|Boolean|Time-Based)\)',
        '', str(ftype), flags=re.IGNORECASE
    )
    return t.strip()


def _join_types(types: list) -> str:
    if not types:
        return "unknown issues"
    if len(types) == 1:
        return types[0]
    return ", ".join(types[:-1]) + f", and {types[-1]}"


def _extract_missing_headers(evidence: str) -> list:
    return [h for h in [
        "Strict-Transport-Security", "X-Frame-Options",
        "X-Content-Type-Options", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy",
    ] if re.search(h, evidence, re.IGNORECASE)]
