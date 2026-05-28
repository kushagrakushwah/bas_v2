"""
Data Exfiltration Module
MITRE ATT&CK: T1041 — Exfiltration Over C2 Channel
              T1020 — Automated Exfiltration

Simulates data exfiltration vectors:
  - Exposed sensitive files (PII, backups, exports)
  - API endpoints returning excessive data
  - Directory listing exposure
  - Large file download probes
"""

import asyncio
import aiohttp
import re
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class DataExfiltrationModule(BaseAttackModule):
    MODULE_NAME  = "data_exfiltration"
    DESCRIPTION  = "Simulates data exfiltration via exposed files, APIs, and directory listings (T1041)"
    MITRE_TACTIC = "Exfiltration"
    MITRE_IDS    = ["T1041", "T1020", "T1530"]

    # Paths commonly targeted for data exfiltration
    EXFIL_PATHS = [
        "/exports",
        "/reports",
        "/downloads",
        "/data",
        "/api/users",
        "/api/v1/users",
        "/api/students",
        "/users.csv",
        "/users.json",
        "/students.csv",
        "/backup.zip",
        "/database_backup.sql",
        "/logs",
        "/log",
        "/access.log",
        "/error.log",
    ]

    # Patterns indicating sensitive data in responses
    PII_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email addresses"),
        (r"\b\d{10,16}\b",                                          "Numeric IDs / card numbers"),
        (r"password['\"]?\s*[:=]\s*['\"]?\w+",                     "Password fields in API response"),
        (r"\"email\"\s*:",                                          "Email field in JSON response"),
        (r"\"ssn\"\s*:",                                            "SSN field in API response"),
        (r"Index of /",                                             "Directory listing exposed"),
    ]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"[data_exfiltration] Starting against {target}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            for path in self.EXFIL_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status == 200:
                            body         = await resp.text(errors="replace")
                            content_type = resp.headers.get("Content-Type", "")
                            body_size    = len(body)

                            # Check for directory listing
                            if "Index of /" in body:
                                findings.append(self.finding(
                                    title       = f"Directory Listing Exposed: {path}",
                                    description = (
                                        f"The path '{path}' has directory listing enabled. "
                                        "An attacker can browse and download all files in this directory."
                                    ),
                                    severity    = Severity.HIGH,
                                    mitre_id    = "T1041",
                                    evidence    = f"GET {url} → HTTP 200 with 'Index of /'",
                                    remediation = (
                                        "1. Disable directory listing in Apache (Options -Indexes) "
                                        "or Nginx (autoindex off).\n"
                                        "2. Ensure no sensitive files are in publicly accessible directories."
                                    ),
                                ))

                            # Check for PII patterns
                            for pattern, desc in self.PII_PATTERNS:
                                matches = re.findall(pattern, body[:5000], re.IGNORECASE)
                                if matches:
                                    findings.append(self.finding(
                                        title       = f"Sensitive Data Exposed via {path}",
                                        description = (
                                            f"The endpoint '{path}' returned {body_size} bytes "
                                            f"containing potentially sensitive data: {desc}. "
                                            "This data could be exfiltrated by an attacker."
                                        ),
                                        severity    = Severity.CRITICAL,
                                        mitre_id    = "T1041",
                                        evidence    = f"Pattern '{pattern}' matched in response from {url}",
                                        remediation = (
                                            "1. Restrict access to this endpoint with authentication.\n"
                                            "2. Implement data masking for sensitive fields in API responses.\n"
                                            "3. Apply rate limiting to prevent bulk data extraction.\n"
                                            "4. Audit all API endpoints for excessive data exposure."
                                        ),
                                        raw_data    = {"path": path, "pattern": pattern, "size": body_size},
                                    ))
                                    break

                            # Flag large unauthenticated responses
                            if body_size > 50000 and not findings:
                                findings.append(self.finding(
                                    title       = f"Large Unauthenticated Response: {path}",
                                    description = (
                                        f"'{path}' returned {body_size:,} bytes without authentication. "
                                        "Large unauthenticated responses are a data exfiltration risk."
                                    ),
                                    severity    = Severity.MEDIUM,
                                    mitre_id    = "T1020",
                                    evidence    = f"GET {url} → HTTP 200, {body_size:,} bytes",
                                    remediation = (
                                        "1. Add authentication to this endpoint.\n"
                                        "2. Implement pagination to limit response sizes.\n"
                                        "3. Add rate limiting."
                                    ),
                                ))

                except Exception as e:
                    self.logger.debug(f"Probe {url}: {e}")

                await asyncio.sleep(0.2)

        if not findings:
            findings.append(self.finding(
                title       = "No Data Exfiltration Vectors Found",
                description = "No exposed data endpoints, directory listings, or PII leakage detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1041",
                evidence    = f"Probed {len(self.EXFIL_PATHS)} paths on {target}",
                remediation = "Continue regular API security audits and access control reviews.",
            ))

        return findings
