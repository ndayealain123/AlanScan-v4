"""
Per-response false-positive guards for injection scanners.

Only consulted when a module is about to record a finding on the same
endpoint/response. Does not change crawl scope, other modules, or global rules.

Web scans log ``[INFO] injection_fp_guard active: …`` once when any of
sqli, cmdi, or xxe is enabled; suppressed probe hits log at ``[i]``.
"""

from __future__ import annotations

# Strong SQL error / parser strings — if present, do not suppress (likely real injection).
_SQLI_STRONG_SYNTAX = (
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysqli_sql_exception",
    "pg::syntaxerror",
    "postgresql error",
    "sqlite3.operationalerror",
    "sqlite error",
    "ora-00933",
    "ora-01756",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sql server native client",
)

# ORM / driver hints that input is bound or parameterized (FP-prone error pages).
_SQLI_PARAMETERIZED_MARKERS = (
    "must declare the scalar variable",
    "expects parameter",
    "sqlparameter",
    "sql parameter",
    "named parameter",
    "bind variable",
    "bound parameter",
    "commandparameter",
    "use a parameterized query",
    "parameterized query",
    "parameterised query",
    "prepared statement",
    "positional parameter",
    "invalid parameter binding",
    "npgsql.postgresexception",
    "could not determine data type of parameter",
)

# Application / shell hardening visible in HTML or error text.
_CMDI_SAFE_MARKERS_CLEAN = (
    "escapeshellarg",
    "escapeshellcmd",
    "shell_exec() has been disabled",
    "proc_open() has been disabled",
    "illegal shell metacharacter",
    "invalid shell metacharacter",
    "command contains invalid characters",
    "meta-characters were stripped",
    "characters were escaped",
    "forbidden shell character",
    "angle brackets are not allowed",
)

# Parser / framework messages that external entities or DTDs are blocked.
_XXE_SAFE_MARKERS = (
    "external entities are disabled",
    "external dtd is disabled",
    "dtd processing is prohibited",
    "dtdprocessing.prohibit",
    "resolveexternalresources",
    "forbidden doctype",
    "doctype declaration is not allowed",
    "doctype is prohibited",
    "xxe is disabled",
    "entity resolution is disabled",
    "disallow doctype",
    "secure xml",
    "xml_disallow_doctype",
    "external entities not allowed",
)


def suppress_sqli_fp(*response_bodies: str) -> bool:
    """
    True if responses suggest bound/parameterized queries without strong SQLi syntax proof.
    """
    blob = "\n".join(b for b in response_bodies if b).lower()
    if not blob.strip():
        return False
    if any(s in blob for s in _SQLI_STRONG_SYNTAX):
        return False
    return any(m in blob for m in _SQLI_PARAMETERIZED_MARKERS)


def suppress_cmdi_fp(body: str, payload: str) -> bool:
    """
    True if the response indicates shell escaping, disabled exec, or similar hardening.
    """
    b = (body or "").lower()
    if not b.strip():
        return False
    if any(m in b for m in _CMDI_SAFE_MARKERS_CLEAN):
        return True
    pl = payload or ""
    if ";" in pl and "&#59;" in b:
        return True
    if "|" in pl and "&#124;" in b:
        return True
    if "`" in pl and "&#96;" in b:
        return True
    return False


def suppress_xxe_fp(body: str) -> bool:
    """
    True if the parser/stack reports disabled external entities / DTD, without file proof.
    """
    b = (body or "").lower()
    if not b.strip():
        return False
    if "root:x:0:0" in b or "[fonts]" in b:
        return False
    if "ami-id" in b and "instance-id" in b:
        return False
    return any(m in b for m in _XXE_SAFE_MARKERS)