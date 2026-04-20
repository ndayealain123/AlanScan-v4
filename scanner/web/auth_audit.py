"""
scanner/web/auth_audit.py
=========================
Lightweight authentication audit:
- Attempts login with provided/default credentials
- Reuses authenticated session for downstream modules
- Checks basic username-enumeration differentials
"""

from __future__ import annotations

from ..scan_logger import logger
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("test", "test"),
    ("guest", "guest"),
]


def _looks_like_login_url(url: str) -> bool:
    u = (url or "").lower()
    return any(k in u for k in ["login", "signin", "dologin", "/admin"])


def _extract_login_form(html: str):
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return None
    for form in soup.find_all("form"):
        pw = form.find("input", {"type": "password"})
        if not pw:
            continue
        user_field = None
        pass_field = pw.get("name") or "password"
        for inp in form.find_all("input"):
            n = (inp.get("name") or "").lower()
            t = (inp.get("type") or "text").lower()
            if t in ("text", "email") and any(x in n for x in ["user", "login", "email", "uid"]):
                user_field = inp.get("name")
                break
        if not user_field:
            user_field = "uid"
        action = form.get("action") or ""
        method = (form.get("method") or "post").lower()
        hidden = {}
        for inp in form.find_all("input", {"type": "hidden"}):
            n = inp.get("name")
            if n:
                hidden[n] = inp.get("value", "")
        return {
            "action": action,
            "method": method,
            "user_field": user_field,
            "pass_field": pass_field,
            "hidden": hidden,
        }
    return None


from ..base_scanner import BaseScanner
from .base_module import ScanContext


class AuthAudit(BaseScanner):
    name = "auth"

    def __init__(self, base_url: str, urls: list[str], timeout: int = 10, proxy: str | None = None, threads: int = 10, credentials: str | None = None, **kwargs):
        super().__init__(urls, timeout=timeout, proxy=proxy, threads=threads, **kwargs)
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials or ""

    def run(self, context: ScanContext) -> list[dict]:
        """
        Module interface override.
        Performs authentication audit and updates context with the session.
        """
        self.urls = context.urls
        self.session = context.session
        
        findings, session = self._execute_audit()
        
        if session:
            context.auth_session = session
            
        return findings

    def audit(self) -> dict:
        """Deprecated: Use run(context) instead. Maintained for legacy controller support."""
        findings, session = self._execute_audit()
        return {"findings": findings, "session": session}

    def _execute_audit(self) -> tuple[list[dict], object | None]:
        findings: list[dict] = []
        login_targets = sorted({u for u in self.urls if _looks_like_login_url(u)})
        if f"{self.base_url}/admin/login.jsp" not in login_targets:
            login_targets.append(f"{self.base_url}/admin/login.jsp")
        if f"{self.base_url}/admin" not in login_targets:
            login_targets.append(f"{self.base_url}/admin")

        creds = []
        if self.credentials and ":" in self.credentials:
            u, p = self.credentials.split(":", 1)
            creds.append((u, p))
        creds.extend(DEFAULT_CREDS)

        for login_url in login_targets[:10]:
            try:
                r = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            except Exception:
                continue
            form = _extract_login_form(r.text)
            if not form:
                continue

            action_url = urljoin(r.url, form["action"]) if form["action"] else r.url
            method = "post" if form["method"] != "get" else "get"

            enum_finding = self._check_enumeration(action_url, form, method)
            if enum_finding:
                findings.append(enum_finding)

            for user, passwd in creds:
                data = dict(form["hidden"])
                data[form["user_field"]] = user
                data[form["pass_field"]] = passwd
                try:
                    if method == "post":
                        lr = self.session.post(action_url, data=data, timeout=self.timeout, allow_redirects=True)
                    else:
                        lr = self.session.get(action_url, params=data, timeout=self.timeout, allow_redirects=True)
                except Exception:
                    continue

                if self._is_login_success(lr.url, lr.text, lr.status_code):
                    findings.append({
                        "type": "Default Credentials Accepted",
                        "url": action_url,
                        "parameter": form["user_field"],
                        "payload": f"{user}:{passwd}",
                        "severity": "CRITICAL",
                        "evidence": f"Successful authentication with credential pair '{user}:{passwd}'.",
                    })
                    logger.warning(
                        "  [CRITICAL] Default creds accepted -> %s (%s:%s)",
                        action_url,
                        user,
                        passwd,
                    )
                    return findings, self.session

        return findings, None

    def _check_enumeration(self, action_url: str, form: dict, method: str) -> dict | None:
        candidate_users = ["admin", "test", "user", "root"]
        baseline = None
        for user in candidate_users[:2]:
            bad_user = f"{user}__notfound"
            wrong_pw = "WrongPass123!"
            req1 = dict(form["hidden"])
            req1[form["user_field"]] = bad_user
            req1[form["pass_field"]] = wrong_pw

            req2 = dict(form["hidden"])
            req2[form["user_field"]] = user
            req2[form["pass_field"]] = wrong_pw
            try:
                if method == "post":
                    r1 = self.session.post(action_url, data=req1, timeout=self.timeout, allow_redirects=True)
                    r2 = self.session.post(action_url, data=req2, timeout=self.timeout, allow_redirects=True)
                else:
                    r1 = self.session.get(action_url, params=req1, timeout=self.timeout, allow_redirects=True)
                    r2 = self.session.get(action_url, params=req2, timeout=self.timeout, allow_redirects=True)
            except Exception:
                continue

            diff = abs(len(r1.text) - len(r2.text))
            msg_diff = ("invalid user" in (r1.text or "").lower() and "invalid password" in (r2.text or "").lower())
            status_diff = r1.status_code != r2.status_code
            if diff > 120 or msg_diff or status_diff:
                return {
                    "type": "Username Enumeration via Login Responses",
                    "url": action_url,
                    "parameter": form["user_field"],
                    "payload": f"{bad_user} vs {user}",
                    "severity": "HIGH",
                    "evidence": f"Login responses differ for non-existent vs existing username (len delta={diff}, status {r1.status_code}/{r2.status_code}).",
                }
            baseline = (len(r1.text), len(r2.text))
        return None

    @staticmethod
    def _is_login_success(final_url: str, body: str, status_code: int) -> bool:
        u = (final_url or "").lower()
        b = (body or "").lower()
        if status_code in (301, 302, 303, 307, 308) and "login" not in u:
            return True
        success_markers = ["logout", "sign out", "welcome", "my account", "admin home", "dashboard"]
        fail_markers = ["invalid", "incorrect", "try again", "login failed", "authentication failed"]
        return any(m in b for m in success_markers) and not any(f in b for f in fail_markers)

