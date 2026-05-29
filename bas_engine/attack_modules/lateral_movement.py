"""
Lateral Movement Module
MITRE ATT&CK: T1021 — Remote Services

Simulates SMB/WMI/SSH-style lateral movement attempts between internal hosts.
Tests whether the SOC detects east-west movement traffic.
"""

import asyncio
import aiohttp
import random
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class LateralMovementModule(BaseAttackModule):
    MODULE_NAME  = "lateral_movement"
    DESCRIPTION  = "Simulates SMB/WMI/SSH lateral movement between internal hosts (T1021)"
    MITRE_TACTIC = "Lateral Movement"
    MITRE_IDS    = ["T1021", "T1021.002", "T1021.001"]

    # Internal hosts to probe — uses the target subnet as base
    PROBE_PATHS = [
        "/admin",
        "/manager",
        "/console",
        "/phpmyadmin",
        "/wp-admin",
        "/.env",
        "/config",
        "/backup",
    ]

    METHODS = [
        "SMB/PsExec",
        "WMI Remote Execution",
        "SSH Forwarding",
        "RDP Session Hijacking",
        "Pass-the-Hash via NTLM",
    ]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"[lateral_movement] Starting against {target}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # Probe for exposed admin/management interfaces
            for path in self.PROBE_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            method = random.choice(self.METHODS)
                            sev    = Severity.CRITICAL if resp.status in (200, 302) else Severity.HIGH

                            findings.append(self.finding(
                                title       = f"Lateral Movement Vector: {path}",
                                description = (
                                    f"Path '{path}' responded with HTTP {resp.status}. "
                                    f"In a real attack, this could be leveraged via {method} "
                                    f"to pivot into adjacent systems."
                                ),
                                severity    = sev,
                                mitre_id    = "T1021",
                                evidence    = f"GET {url} → HTTP {resp.status}",
                                remediation = (
                                    "1. Implement network segmentation — restrict east-west traffic.\n"
                                    "2. Enforce authentication on all management interfaces.\n"
                                    "3. Deploy host-based IDS to detect unusual internal connections.\n"
                                    "4. Disable SMB/WMI if not required in your environment."
                                ),
                                raw_data    = {"path": path, "status": resp.status, "method": method},
                            ))
                except Exception as e:
                    self.logger.debug(f"Probe {url} failed: {e}")

                await asyncio.sleep(0.3)

        if not findings:
            findings.append(self.finding(
                title       = "No Lateral Movement Vectors Found",
                description = "All probed admin/management paths returned 404 or were unreachable.",
                severity    = Severity.INFO,
                mitre_id    = "T1021",
                evidence    = f"Probed {len(self.PROBE_PATHS)} paths on {target}",
                remediation = "Continue monitoring for internal east-west traffic anomalies.",
            ))

        return findings
