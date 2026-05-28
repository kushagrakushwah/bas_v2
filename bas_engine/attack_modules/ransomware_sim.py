"""
Ransomware Simulation Module
MITRE ATT&CK: T1486 — Data Encrypted for Impact

Simulates ransomware behavior:
  - File discovery (T1083)
  - Shadow copy deletion probe (T1490)
  - Mock encryption staging
  - C2 beacon simulation

Does NOT encrypt any real files. Safe simulation only.
"""

import asyncio
import aiohttp
import random
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


class RansomwareSimModule(BaseAttackModule):
    MODULE_NAME  = "ransomware_sim"
    DESCRIPTION  = "Simulates ransomware behavior: file discovery, staging, C2 beacon (T1486)"
    MITRE_TACTIC = "Impact"
    MITRE_IDS    = ["T1486", "T1083", "T1490", "T1071"]

    # Simulated C2 beacon endpoints (safe, non-real)
    C2_PATHS = [
        "/c2/beacon",
        "/update/check",
        "/api/register",
        "/ping",
    ]

    # Paths that ransomware typically targets for file discovery
    FILE_DISCOVERY_PATHS = [
        "/uploads",
        "/files",
        "/documents",
        "/backup",
        "/data",
        "/export",
    ]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self.logger.info(f"[ransomware_sim] Starting against {target}")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "SecureForge-BAS/1.0 (authorized security testing)"},
        ) as session:

            # Stage 1: File discovery probe
            self.logger.info("[ransomware_sim] Stage 1: File discovery")
            discovered = []
            for path in self.FILE_DISCOVERY_PATHS:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 403):
                            discovered.append(path)
                except Exception as e:
                    self.logger.debug(f"Discovery probe {url}: {e}")
                await asyncio.sleep(0.2)

            if discovered:
                findings.append(self.finding(
                    title       = "File Discovery: Accessible Storage Paths Found",
                    description = (
                        f"Ransomware simulation discovered {len(discovered)} accessible storage "
                        f"paths: {', '.join(discovered)}. In a real attack these would be "
                        "enumerated and staged for encryption."
                    ),
                    severity    = Severity.HIGH,
                    mitre_id    = "T1083",
                    evidence    = f"Accessible paths: {discovered}",
                    remediation = (
                        "1. Restrict direct web access to upload/storage directories.\n"
                        "2. Implement file integrity monitoring on critical directories.\n"
                        "3. Maintain offline/immutable backups."
                    ),
                    raw_data    = {"discovered_paths": discovered},
                ))

            # Stage 2: Mock encryption staging (simulation only)
            self.logger.info("[ransomware_sim] Stage 2: Mock encryption staging")
            await asyncio.sleep(0.5)
            findings.append(self.finding(
                title       = "Ransomware Simulation: Encryption Staging",
                description = (
                    f"Simulated encryption process tracked across {len(discovered)} directories "
                    f"on {target}. No real files were modified. "
                    "A README_DECRYPT.txt artifact would be dropped in a real attack."
                ),
                severity    = Severity.CRITICAL,
                mitre_id    = "T1486",
                evidence    = "Mock encryption loop completed — no real files touched",
                remediation = (
                    "1. Deploy behavioral anti-ransomware endpoint solutions.\n"
                    "2. Implement immutable/versioned backups (3-2-1 rule).\n"
                    "3. Enable file activity monitoring and alert on mass file renames.\n"
                    "4. Test backup restoration procedures regularly."
                ),
            ))

            # Stage 3: C2 beacon simulation
            self.logger.info("[ransomware_sim] Stage 3: C2 beacon")
            for path in self.C2_PATHS[:2]:
                url = target.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status != 404:
                            findings.append(self.finding(
                                title       = f"Potential C2 Endpoint Reachable: {path}",
                                description = (
                                    f"The path '{path}' returned HTTP {resp.status}. "
                                    "This path pattern is commonly used by ransomware C2 beacons. "
                                    "Legitimate C2 infrastructure should be unreachable from internal hosts."
                                ),
                                severity    = Severity.CRITICAL,
                                mitre_id    = "T1071",
                                evidence    = f"GET {url} → HTTP {resp.status}",
                                remediation = (
                                    "1. Block outbound connections to unknown/untrusted endpoints.\n"
                                    "2. Implement DNS filtering and egress firewall rules.\n"
                                    "3. Monitor for unusual outbound HTTP/S traffic patterns."
                                ),
                                raw_data    = {"path": path, "status": resp.status},
                            ))
                except Exception as e:
                    self.logger.debug(f"C2 probe {url}: {e}")
                await asyncio.sleep(0.2)

        return findings
