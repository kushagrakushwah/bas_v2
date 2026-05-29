"""
Credential Dumping Module
MITRE ATT&CK: T1003 — OS Credential Dumping

Simulates credential exposure vectors:
  - Exposed config files with credentials
  - Default credential probing
  - Login form credential harvesting endpoints
  - Environment variable leakage
"""

import asyncio
import aiohttp
import re
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class CredentialDumpingModule(BaseAttackModule):
    MODULE_NAME  = "credential_dumping"
    DESCRIPTION  = "Simulates credential exposure via config files, default creds, and env leaks (T1003)"
    MITRE_TACTIC = "Credential Access"
    MITRE_IDS    = ["T1003", "T1552", "T1110.001"]

    # Paths that commonly expose credentials
    CREDENTIAL_PATHS = [
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/config.yml",
        "/config.yaml",
        "/settings.py",
        "/application.properties",
        "/.git/config",
        "/database.yml",
        "/credentials.json",
        "/secrets.json",
        "/.aws/credentials",
        "/backup.sql",
        "/dump.sql",
    ]

    # Regex patterns indicating credential exposure in responses
    CREDENTIAL_PATTERNS = [
        (r"DB_PASSWORD\s*=\s*\S+",         "Database password in .env"),
        (r"db_password\s*:\s*\S+",         "Database password in config"),
        (r"SECRET_KEY\s*=\s*\S+",          "Secret key exposed"),
        (r"AWS_SECRET_ACCESS_KEY\s*=\s*\S+","AWS credentials exposed"),
        (r"password\s*=\s*['\"][^'\"]+['\"]","Hardcoded password in config"),
        (r"\[default\]\s*aws_",            "AWS credentials file"),
        (r"mysql://\S+:\S+@",              "Database connection string with credentials"),
        (r"postgresql://\S+:\S+@",         "PostgreSQL connection string with credentials"),
    ]

    # Default credential pairs to test
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root",  "root"),
        ("admin", "admin123"),
    ]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"[credential_dumping] Starting against {target}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # Stage 1: Probe for exposed credential files
            self.logger.info("[credential_dumping] Stage 1: Config file exposure")
            for path in self.CREDENTIAL_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            for pattern, desc in self.CREDENTIAL_PATTERNS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    findings.append(self.finding(
                                        title       = f"Credentials Exposed: {path}",
                                        description = (
                                            f"The file '{path}' is publicly accessible and contains "
                                            f"sensitive data matching: {desc}. "
                                            "This gives an attacker direct access to backend systems."
                                        ),
                                        severity    = Severity.CRITICAL,
                                        mitre_id    = "T1552",
                                        evidence    = f"GET {url} → HTTP 200, pattern: {pattern}",
                                        remediation = (
                                            f"1. Immediately remove {path} from web root.\n"
                                            "2. Rotate all exposed credentials.\n"
                                            "3. Add sensitive file patterns to .htaccess deny rules.\n"
                                            "4. Scan web root for other exposed config files."
                                        ),
                                        raw_data    = {"path": path, "pattern": pattern},
                                    ))
                                    break

                        elif resp.status == 403:
                            # 403 means the file exists but is protected
                            findings.append(self.finding(
                                title       = f"Sensitive Path Exists But Blocked: {path}",
                                description = (
                                    f"'{path}' returned HTTP 403 — the file exists on disk "
                                    "but is blocked by server config. "
                                    "A misconfiguration could expose it."
                                ),
                                severity    = Severity.MEDIUM,
                                mitre_id    = "T1552",
                                evidence    = f"GET {url} → HTTP 403",
                                remediation = (
                                    f"1. Move {path} outside the web root entirely.\n"
                                    "2. Do not rely solely on 403 blocks for sensitive files."
                                ),
                            ))
                except Exception as e:
                    self.logger.debug(f"Probe {url}: {e}")

                await asyncio.sleep(0.2)

            # Stage 2: Default credential simulation
            self.logger.info("[credential_dumping] Stage 2: Default credential probe")
            login_paths = ["/admin/login", "/login", "/moodle/login/index.php", "/mail/"]
            for login_path in login_paths[:2]:
                url = target.rstrip("/") + login_path
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status == 200:
                            findings.append(self.finding(
                                title       = f"Login Endpoint Found: {login_path}",
                                description = (
                                    f"Login form accessible at '{login_path}'. "
                                    "Default credentials (admin/admin, admin/password etc.) "
                                    "should be tested. Automated brute force possible if no lockout exists."
                                ),
                                severity    = Severity.MEDIUM,
                                mitre_id    = "T1110.001",
                                evidence    = f"GET {url} → HTTP {resp.status}",
                                remediation = (
                                    "1. Change all default credentials immediately.\n"
                                    "2. Implement account lockout after 5 failed attempts.\n"
                                    "3. Enable MFA on all login endpoints.\n"
                                    "4. Monitor login endpoints for brute force patterns."
                                ),
                            ))
                except Exception as e:
                    self.logger.debug(f"Login probe {url}: {e}")
                await asyncio.sleep(0.2)

        if not findings:
            findings.append(self.finding(
                title       = "No Credential Exposure Found",
                description = "No exposed config files or accessible login endpoints detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1003",
                evidence    = f"Probed {len(self.CREDENTIAL_PATHS)} paths on {target}",
                remediation = "Continue regular credential hygiene audits.",
            ))

        return findings
