"""
Supply Chain Attack Module
MITRE ATT&CK: T1195 — Supply Chain Compromise
              T1059 — Command and Scripting Interpreter

Simulates supply chain attack vectors:
  - Exposed package manifests (package.json, requirements.txt)
  - Outdated/vulnerable component detection
  - Third-party script injection vectors
  - Dependency confusion probes
"""

import asyncio
import aiohttp
import re
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class SupplyChainModule(BaseAttackModule):
    MODULE_NAME  = "supply_chain"
    DESCRIPTION  = "Simulates supply chain attack vectors via exposed manifests and third-party scripts (T1195)"
    MITRE_TACTIC = "Initial Access"
    MITRE_IDS    = ["T1195", "T1195.002", "T1059"]

    # Exposed dependency/manifest files
    MANIFEST_PATHS = [
        "/package.json",
        "/package-lock.json",
        "/requirements.txt",
        "/Pipfile",
        "/Gemfile",
        "/composer.json",
        "/pom.xml",
        "/build.gradle",
        "/.npmrc",
        "/yarn.lock",
        "/Pipfile.lock",
    ]

    # Paths that load third-party scripts
    SCRIPT_PATHS = [
        "/",
        "/index.html",
        "/moodle/",
        "/mail/",
    ]

    # Known vulnerable version patterns
    VULNERABLE_PATTERNS = [
        (r'"version"\s*:\s*"([^"]+)"',          "npm package version"),
        (r"(Django|Flask|Spring|Rails)==([^\n]+)","Framework version"),
        (r"(log4j|log4j2)[^=]*==?([^\n\s]+)",   "Log4j version — check for CVE-2021-44228"),
    ]

    # Suspicious third-party domains in script tags
    SUSPICIOUS_SCRIPT_PATTERNS = [
        r'<script[^>]+src=["\']https?://(?!cdnjs|unpkg|jsdelivr|ajax\.googleapis)([^"\']+)["\']',
    ]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"[supply_chain] Starting against {target}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # Stage 1: Probe for exposed manifest/dependency files
            self.logger.info("[supply_chain] Stage 1: Manifest file exposure")
            for path in self.MANIFEST_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")

                            findings.append(self.finding(
                                title       = f"Dependency Manifest Exposed: {path}",
                                description = (
                                    f"The file '{path}' is publicly accessible. "
                                    "This reveals all dependencies and their versions, "
                                    "allowing attackers to identify vulnerable components "
                                    "or mount a dependency confusion attack."
                                ),
                                severity    = Severity.HIGH,
                                mitre_id    = "T1195.002",
                                evidence    = f"GET {url} → HTTP 200, {len(body)} bytes",
                                remediation = (
                                    f"1. Block access to {path} via web server config.\n"
                                    "2. Move manifests outside web root.\n"
                                    "3. Add to .htaccess: <Files package.json> deny from all </Files>"
                                ),
                                raw_data    = {"path": path, "size": len(body)},
                            ))

                            # Check for vulnerable versions
                            for pattern, desc in self.VULNERABLE_PATTERNS:
                                matches = re.findall(pattern, body, re.IGNORECASE)
                                if matches:
                                    findings.append(self.finding(
                                        title       = f"Component Version Exposed: {desc}",
                                        description = (
                                            f"Version information found in {path}: {matches[:3]}. "
                                            "Attackers can cross-reference these against CVE databases."
                                        ),
                                        severity    = Severity.MEDIUM,
                                        mitre_id    = "T1195",
                                        evidence    = f"Pattern '{pattern}' matched: {matches[:3]}",
                                        remediation = (
                                            "1. Keep all dependencies updated.\n"
                                            "2. Use tools like 'npm audit' or 'safety check' regularly.\n"
                                            "3. Subscribe to security advisories for your dependencies."
                                        ),
                                    ))
                except Exception as e:
                    self.logger.debug(f"Manifest probe {url}: {e}")
                await asyncio.sleep(0.2)

            # Stage 2: Third-party script injection analysis
            self.logger.info("[supply_chain] Stage 2: Third-party script analysis")
            for path in self.SCRIPT_PATHS[:2]:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            for pattern in self.SUSPICIOUS_SCRIPT_PATTERNS:
                                matches = re.findall(pattern, body, re.IGNORECASE)
                                if matches:
                                    findings.append(self.finding(
                                        title       = "Third-Party Script Loaded from External Domain",
                                        description = (
                                            f"The page at '{path}' loads scripts from external domains: "
                                            f"{matches[:3]}. "
                                            "A compromised CDN or script host could inject malicious code "
                                            "into all users' browsers (supply chain attack)."
                                        ),
                                        severity    = Severity.MEDIUM,
                                        mitre_id    = "T1059",
                                        evidence    = f"External script domains: {matches[:3]}",
                                        remediation = (
                                            "1. Use Subresource Integrity (SRI) hashes for all external scripts.\n"
                                            "2. Self-host critical JavaScript dependencies.\n"
                                            "3. Implement a strict Content-Security-Policy."
                                        ),
                                    ))
                except Exception as e:
                    self.logger.debug(f"Script probe {url}: {e}")
                await asyncio.sleep(0.3)

        if not findings:
            findings.append(self.finding(
                title       = "No Supply Chain Vectors Found",
                description = "No exposed manifests or suspicious third-party scripts detected.",
                severity    = Severity.INFO,
                mitre_id    = "T1195",
                evidence    = f"Probed {len(self.MANIFEST_PATHS)} manifest paths",
                remediation = "Continue regular dependency audits and SRI checks.",
            ))

        return findings
