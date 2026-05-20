"""
Network Reconnaissance / Port Scan Module
MITRE ATT&CK: T1046 — Network Service Discovery

Simulates network reconnaissance using async TCP probing.
Does NOT require nmap to be installed.
Tests common ports and reports open services.
"""

import asyncio
import aiohttp
from typing import List
from urllib.parse import urlparse

from attack_modules.base import BaseAttackModule
from models.simulation import Finding, Severity


class NmapScanModule(BaseAttackModule):
    MODULE_NAME  = "nmap_scan"
    DESCRIPTION  = "Simulates network recon via async TCP port probing (T1046)"
    MITRE_TACTIC = "Discovery"
    MITRE_IDS    = ["T1046", "T1590"]

    # Common ports to probe with their service names and risk levels
    PORTS = [
        (22,   "SSH",           Severity.LOW),
        (23,   "Telnet",        Severity.HIGH),
        (25,   "SMTP",          Severity.MEDIUM),
        (80,   "HTTP",          Severity.LOW),
        (443,  "HTTPS",         Severity.LOW),
        (445,  "SMB",           Severity.HIGH),
        (3306, "MySQL",         Severity.HIGH),
        (5432, "PostgreSQL",    Severity.HIGH),
        (6379, "Redis",         Severity.HIGH),
        (8080, "HTTP-Alt",      Severity.MEDIUM),
        (8443, "HTTPS-Alt",     Severity.LOW),
        (9200, "Elasticsearch", Severity.CRITICAL),
        (5601, "Kibana",        Severity.HIGH),
        (27017,"MongoDB",       Severity.HIGH),
    ]

    RISKY_SERVICES = {
        23:    "Telnet transmits credentials in plaintext.",
        445:   "SMB is commonly exploited (EternalBlue, ransomware propagation).",
        3306:  "MySQL exposed to network — database credentials at risk.",
        5432:  "PostgreSQL exposed — restrict to localhost.",
        6379:  "Redis with no auth by default — remote code execution risk.",
        9200:  "Elasticsearch HTTP API exposed — unauthenticated data access.",
        5601:  "Kibana dashboard exposed — potential data disclosure.",
        27017: "MongoDB exposed — commonly misconfigured with no auth.",
    }

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        target = self.target

        # Extract hostname from URL if needed
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host   = parsed.hostname
        else:
            host = target

        self.logger.info(f"[nmap_scan] Starting port scan against {host}")

        open_ports = []

        # Async TCP connect probe
        async def probe_port(port: int, service: str, severity: Severity):
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append((port, service, severity))
                self.logger.info(f"[nmap_scan] Open: {host}:{port} ({service})")
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"[nmap_scan] Port {port}: {e}")

        # Run all probes concurrently
        tasks = [probe_port(port, service, sev) for port, service, sev in self.PORTS]
        await asyncio.gather(*tasks)

        if not open_ports:
            findings.append(self.finding(
                title       = "No Open Ports Detected",
                description = f"No open ports found on {host} from the probed list.",
                severity    = Severity.INFO,
                mitre_id    = "T1046",
                evidence    = f"Probed {len(self.PORTS)} ports on {host}",
                remediation = "Continue monitoring for newly opened ports.",
            ))
            return findings

        # Finding per open port
        for port, service, severity in sorted(open_ports):
            risk_note = self.RISKY_SERVICES.get(port, "")
            findings.append(self.finding(
                title       = f"Open Port Detected: {port}/{service}",
                description = (
                    f"Port {port} ({service}) is open on {host}. "
                    f"{risk_note}"
                ),
                severity    = severity,
                mitre_id    = "T1046",
                evidence    = f"TCP connect to {host}:{port} succeeded",
                remediation = (
                    f"1. Verify {service} on port {port} is intentionally exposed.\n"
                    "2. Apply firewall rules to restrict access to trusted IPs only.\n"
                    "3. Disable any service not required for operations."
                ),
                raw_data    = {"host": host, "port": port, "service": service},
            ))

        # Summary finding
        critical_ports = [p for p, s, sev in open_ports if sev == Severity.CRITICAL]
        if critical_ports:
            findings.append(self.finding(
                title       = f"Critical Services Exposed: {critical_ports}",
                description = (
                    f"The following critical-risk ports are open: {critical_ports}. "
                    "These services are commonly targeted in real-world attacks and "
                    "should be immediately restricted."
                ),
                severity    = Severity.CRITICAL,
                mitre_id    = "T1590",
                evidence    = f"Critical open ports: {critical_ports} on {host}",
                remediation = (
                    "1. Immediately restrict access to these ports via firewall.\n"
                    "2. Move management interfaces to a dedicated VLAN.\n"
                    "3. Enable authentication and TLS on all exposed services."
                ),
            ))

        return findings
