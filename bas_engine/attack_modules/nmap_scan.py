"""
Network Reconnaissance / Port Scan Module
MITRE ATT&CK: T1046 — Network Service Discovery
             T1590 — Gather Victim Network Information

Full-featured async scanner supporting:
  - Single IP scan
  - CIDR subnet discovery + scan
  - Hostname resolution
  - Dynamic port profiles (quick / standard / full / custom)
  - OS/service fingerprinting via banner grabbing
  - UDP port hints
  - Concurrent scanning with configurable limits
"""

import asyncio
import ipaddress
import socket
import re
import time
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity


# ---------------------------------------------------------------------------
# Port database — (service_name, severity, common_banner_hints)
# ---------------------------------------------------------------------------
PORT_DB: Dict[int, Tuple[str, Severity, str]] = {
    # Remote access
    21:    ("FTP",            Severity.HIGH,     "220"),
    22:    ("SSH",            Severity.LOW,      "SSH-"),
    23:    ("Telnet",         Severity.HIGH,     ""),
    3389:  ("RDP",            Severity.HIGH,     ""),
    5900:  ("VNC",            Severity.HIGH,     "RFB"),
    # Web
    80:    ("HTTP",           Severity.LOW,      "HTTP"),
    443:   ("HTTPS",          Severity.LOW,      ""),
    8080:  ("HTTP-Alt",       Severity.MEDIUM,   "HTTP"),
    8443:  ("HTTPS-Alt",      Severity.LOW,      ""),
    8888:  ("HTTP-Dev",       Severity.MEDIUM,   ""),
    3000:  ("Node/Grafana",   Severity.MEDIUM,   ""),
    4200:  ("Angular-Dev",    Severity.MEDIUM,   ""),
    5000:  ("Flask/Dev",      Severity.MEDIUM,   ""),
    # Mail
    25:    ("SMTP",           Severity.MEDIUM,   "220"),
    110:   ("POP3",           Severity.MEDIUM,   "+OK"),
    143:   ("IMAP",           Severity.MEDIUM,   "* OK"),
    465:   ("SMTPS",          Severity.LOW,      ""),
    587:   ("SMTP-Sub",       Severity.LOW,      ""),
    993:   ("IMAPS",          Severity.LOW,      ""),
    # Databases
    1433:  ("MSSQL",          Severity.CRITICAL, ""),
    1521:  ("Oracle",         Severity.CRITICAL, ""),
    3306:  ("MySQL",          Severity.HIGH,     ""),
    5432:  ("PostgreSQL",     Severity.HIGH,     ""),
    6379:  ("Redis",          Severity.CRITICAL, "+PONG"),
    27017: ("MongoDB",        Severity.CRITICAL, ""),
    5984:  ("CouchDB",        Severity.HIGH,     "CouchDB"),
    7474:  ("Neo4j",          Severity.HIGH,     ""),
    9042:  ("Cassandra",      Severity.HIGH,     ""),
    # Search / messaging
    9200:  ("Elasticsearch",  Severity.CRITICAL, "cluster_name"),
    9300:  ("ES-Transport",   Severity.CRITICAL, ""),
    5601:  ("Kibana",         Severity.HIGH,     ""),
    9092:  ("Kafka",          Severity.HIGH,     ""),
    2181:  ("Zookeeper",      Severity.HIGH,     ""),
    # Infrastructure
    53:    ("DNS",            Severity.MEDIUM,   ""),
    161:   ("SNMP",           Severity.HIGH,     ""),
    389:   ("LDAP",           Severity.HIGH,     ""),
    636:   ("LDAPS",          Severity.MEDIUM,   ""),
    445:   ("SMB",            Severity.CRITICAL, ""),
    135:   ("MSRPC",          Severity.HIGH,     ""),
    139:   ("NetBIOS",        Severity.HIGH,     ""),
    # Container / cloud
    2375:  ("Docker-API",     Severity.CRITICAL, ""),
    2376:  ("Docker-TLS",     Severity.HIGH,     ""),
    6443:  ("K8s-API",        Severity.HIGH,     ""),
    10250: ("Kubelet",        Severity.CRITICAL, ""),
    2379:  ("etcd",           Severity.CRITICAL, ""),
    # CI/CD / monitoring
    8500:  ("Consul",         Severity.HIGH,     ""),
    8600:  ("Consul-DNS",     Severity.HIGH,     ""),
    4646:  ("Nomad",          Severity.HIGH,     ""),
    9090:  ("Prometheus",     Severity.MEDIUM,   ""),
    3100:  ("Loki",           Severity.MEDIUM,   ""),
    # Misc
    11211: ("Memcached",      Severity.CRITICAL, ""),
    6380:  ("Redis-Alt",      Severity.CRITICAL, ""),
    5672:  ("RabbitMQ",       Severity.HIGH,     "AMQP"),
    15672: ("RabbitMQ-Mgmt",  Severity.HIGH,     ""),
    4369:  ("Erlang-Port",    Severity.HIGH,     ""),
    7000:  ("Cassandra-Int",  Severity.HIGH,     ""),
    7001:  ("Cassandra-TLS",  Severity.HIGH,     ""),
    8161:  ("ActiveMQ",       Severity.HIGH,     ""),
    61616: ("ActiveMQ-AMQP",  Severity.HIGH,     ""),
}

# Port scan profiles
PROFILES = {
    "quick":    [21,22,23,80,443,445,3306,3389,5432,6379,8080,9200,27017],
    "standard": sorted(PORT_DB.keys()),
    "full":     sorted(PORT_DB.keys()) + list(range(1, 1025)),
    "web":      [80,443,8080,8443,8888,3000,4200,5000,8500,15672],
    "db":       [1433,1521,3306,5432,6379,7474,9042,27017,5984,11211],
    "devops":   [2375,2376,6443,10250,2379,9090,3100,8500,4646,9092,2181],
}

RISKY_NOTES: Dict[int, str] = {
    21:    "FTP often transmits credentials in plaintext.",
    23:    "Telnet transmits everything in plaintext — replace with SSH.",
    445:   "SMB is a top exploit target (EternalBlue, ransomware).",
    1433:  "MSSQL exposed to network — restrict to application servers only.",
    3306:  "MySQL exposed — risk of credential brute-force and data exfil.",
    5432:  "PostgreSQL should be bound to localhost only.",
    6379:  "Redis has no auth by default — trivial remote code execution.",
    9200:  "Elasticsearch REST API exposed — unauthenticated data access.",
    27017: "MongoDB commonly misconfigured with no authentication.",
    2375:  "Docker daemon API exposed without TLS — full host compromise.",
    10250: "Kubelet API exposed — can exec into any pod on the node.",
    2379:  "etcd exposed — full Kubernetes secret store readable.",
    11211: "Memcached UDP amplification DDoS vector, no auth.",
    3389:  "RDP exposed to network — brute-force and BlueKeep risk.",
    5900:  "VNC exposed — often has weak/no authentication.",
}


class NmapScanModule(BaseAttackModule):
    MODULE_NAME  = "nmap_scan"
    DESCRIPTION  = "Full async network scanner: subnet discovery, dynamic port profiles, banner grabbing (T1046)"
    MITRE_TACTIC = "Discovery"
    MITRE_IDS    = ["T1046", "T1590", "T1595"]

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _parse_target(self, target: str) -> Tuple[str, bool]:
        """Return (host_or_cidr, is_cidr)."""
        t = target.strip()
        if t.startswith(("http://", "https://")):
            t = urlparse(t).hostname or t
        try:
            ipaddress.ip_network(t, strict=False)
            return t, "/" in t
        except ValueError:
            return t, False

    def _resolve(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def _get_ports(self, profile: str, custom: Optional[str]) -> List[int]:
        if custom:
            ports = set()
            for part in custom.split(","):
                part = part.strip()
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    ports.update(range(int(lo), int(hi) + 1))
                else:
                    ports.add(int(part))
            return sorted(ports)
        base = set(PROFILES.get(profile, PROFILES["standard"]))
        # Always include full PORT_DB for standard+
        if profile in ("standard", "full"):
            base |= set(PORT_DB.keys())
        return sorted(base)

    async def _grab_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            # Send HTTP probe for web ports, otherwise just read
            if port in (80, 8080, 8888, 3000, 4200, 5000, 8443, 8500, 15672, 9090, 3100):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=timeout)
                banner = data.decode("utf-8", errors="replace").strip()[:120]
            except Exception:
                banner = ""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return banner
        except Exception:
            return ""

    async def _probe_port(
        self,
        host: str,
        port: int,
        timeout: float,
        semaphore: asyncio.Semaphore,
        results: list,
    ):
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                # Port is open — grab banner
                banner = await self._grab_banner(host, port, timeout)
                service, severity, _ = PORT_DB.get(port, (f"unknown-{port}", Severity.LOW, ""))
                results.append((port, service, severity, banner))
                self.logger.info(f"[nmap_scan] {host}:{port} OPEN ({service})")
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"[nmap_scan] {host}:{port} error: {e}")

    async def _scan_host(
        self,
        host: str,
        ports: List[int],
        timeout: float,
        concurrency: int,
    ) -> List[Tuple[int, str, Severity, str]]:
        """Scan a single host, return list of (port, service, severity, banner)."""
        semaphore = asyncio.Semaphore(concurrency)
        results: list = []
        tasks = [
            self._probe_port(host, port, timeout, semaphore, results)
            for port in ports
        ]
        await asyncio.gather(*tasks)
        return sorted(results, key=lambda x: x[0])

    async def _discover_subnet(
        self,
        cidr: str,
        timeout: float,
        concurrency: int,
    ) -> List[str]:
        """Ping-equivalent: TCP connect to port 80 or 22 to find live hosts."""
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(h) for h in network.hosts()]
        self.logger.info(f"[nmap_scan] Discovering live hosts in {cidr} ({len(hosts)} addresses)")

        semaphore = asyncio.Semaphore(min(concurrency * 2, 256))
        live: list = []

        async def ping(ip: str):
            async with semaphore:
                for probe_port in (80, 22, 443, 445, 8080):
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, probe_port), timeout=timeout
                        )
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        live.append(ip)
                        self.logger.info(f"[nmap_scan] Live host: {ip}")
                        return
                    except Exception:
                        pass

        await asyncio.gather(*[ping(ip) for ip in hosts])
        return live

    def _build_findings(
        self,
        host: str,
        resolved_ip: Optional[str],
        open_ports: List[Tuple[int, str, Severity, str]],
        scan_duration: float,
        ports_scanned: int,
    ) -> List[Finding]:
        findings: List[Finding] = []

        display = f"{host}" + (f" ({resolved_ip})" if resolved_ip and resolved_ip != host else "")

        if not open_ports:
            findings.append(self.finding(
                title       = f"No Open Ports — {display}",
                description = f"Scanned {ports_scanned} ports on {display} in {scan_duration:.1f}s. No open ports found.",
                severity    = Severity.INFO,
                mitre_id    = "T1046",
                evidence    = f"TCP connect probe on {ports_scanned} ports",
                remediation = "Host may be firewalled or offline. Verify connectivity.",
            ))
            return findings

        # Per-port findings
        critical_ports, high_ports = [], []
        for port, service, severity, banner in open_ports:
            risk_note = RISKY_NOTES.get(port, "")
            banner_note = f"\n\nBanner: `{banner}`" if banner else ""
            if severity == Severity.CRITICAL:
                critical_ports.append(port)
            elif severity == Severity.HIGH:
                high_ports.append(port)

            findings.append(self.finding(
                title       = f"Open Port {port}/{service} on {display}",
                description = (
                    f"Port **{port}** ({service}) is open on {display}. "
                    f"{risk_note}{banner_note}"
                ),
                severity    = severity,
                mitre_id    = "T1046",
                evidence    = f"TCP connect to {host}:{port} succeeded in <{scan_duration:.1f}s",
                remediation = (
                    f"1. Confirm {service} on port {port} is intentionally exposed.\n"
                    "2. Apply firewall rules — restrict to trusted source IPs only.\n"
                    "3. Enable authentication, encryption, and audit logging.\n"
                    "4. Disable or uninstall the service if not required."
                ),
                raw_data    = {
                    "host": host,
                    "ip": resolved_ip,
                    "port": port,
                    "service": service,
                    "banner": banner,
                },
            ))

        # Attack surface summary
        findings.append(self.finding(
            title       = f"Attack Surface Summary — {display}",
            description = (
                f"Scan completed in **{scan_duration:.1f}s** | "
                f"Ports scanned: **{ports_scanned}** | "
                f"Open ports: **{len(open_ports)}** | "
                f"Critical: **{len(critical_ports)}** | "
                f"High: **{len(high_ports)}**\n\n"
                f"Open: {[p for p, *_ in open_ports]}\n"
                + (f"\nCritical risk ports: {critical_ports}" if critical_ports else "")
            ),
            severity    = Severity.CRITICAL if critical_ports else (Severity.HIGH if high_ports else Severity.MEDIUM),
            mitre_id    = "T1590",
            evidence    = f"Full scan result for {display}",
            remediation = (
                "1. Immediately remediate all CRITICAL and HIGH severity ports.\n"
                "2. Implement network segmentation — databases/infra must not be internet-facing.\n"
                "3. Use a WAF for all web-facing services.\n"
                "4. Schedule recurring scans to detect new exposures."
            ),
            raw_data    = {
                "host": host,
                "ip": resolved_ip,
                "open_ports": [p for p, *_ in open_ports],
                "critical_ports": critical_ports,
                "scan_duration_sec": round(scan_duration, 2),
            },
        ))

        return findings

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []

        # Read options from self.options (dict passed in from simulation config)
        all_options = getattr(self, "options", {}) or {}

        options = all_options.get(
            "nmap_scan",
            all_options
        )
        profile      = options.get("profile", "standard").lower()
        custom_ports = options.get("ports", None)        # e.g. "22,80,443,8000-9000"
        timing = options.get("timing", "T4")

        TIMING_CONFIG = {
            "T2": {
                "timeout": 4.0,
                "concurrency": 50
            },
            "T3": {
                "timeout": 3.0,
                "concurrency": 100
            },
            "T4": {
                "timeout": 2.0,
                "concurrency": 200
            },
            "T5": {
                "timeout": 1.0,
                "concurrency": 400
            }
        }

        cfg = TIMING_CONFIG.get(
            timing,
            TIMING_CONFIG["T4"]
        )

        timeout = float(
            options.get(
                "timeout",
                cfg["timeout"]
            )
        )

        concurrency = int(
            options.get(
                "concurrency",
                cfg["concurrency"]
            )
        )
        subnet_scan  = options.get("subnet_scan", False)  # force subnet mode

        target, is_cidr = self._parse_target(self.target)

        ports = self._get_ports(profile, custom_ports)
        self.logger.info(
            f"[nmap_scan] Target={target} | Profile={profile} | "
            f"Ports={len(ports)} | Timeout={timeout}s | Concurrency={concurrency}"
        )

        # ------------------------------------------------------------------
        # SUBNET MODE
        # ------------------------------------------------------------------
        if is_cidr or subnet_scan:
            cidr = target if is_cidr else target + "/24"
            live_hosts = await self._discover_subnet(cidr, timeout, concurrency)

            if not live_hosts:
                findings.append(self.finding(
                    title       = f"No Live Hosts Found in {cidr}",
                    description = f"TCP discovery probe found no responsive hosts in {cidr}.",
                    severity    = Severity.INFO,
                    mitre_id    = "T1046",
                    evidence    = f"Probed all hosts in {cidr} on ports 22,80,443,445,8080",
                    remediation = "Subnet may be firewalled or offline.",
                ))
                return findings

            # Discovery summary
            findings.append(self.finding(
                title       = f"Subnet Discovery: {len(live_hosts)} Live Hosts in {cidr}",
                description = (
                    f"Found **{len(live_hosts)}** live hosts in `{cidr}`:\n\n"
                    + "\n".join(f"- `{ip}`" for ip in sorted(live_hosts))
                ),
                severity    = Severity.MEDIUM,
                mitre_id    = "T1590",
                evidence    = f"TCP discovery across {cidr}",
                remediation = "Review all discovered hosts — unexpected hosts may indicate rogue devices.",
                raw_data    = {"cidr": cidr, "live_hosts": live_hosts},
            ))

            # Scan each live host
            for ip in live_hosts:
                t0 = time.monotonic()
                open_ports = await self._scan_host(ip, ports, timeout, concurrency)
                duration = time.monotonic() - t0
                findings.extend(self._build_findings(ip, ip, open_ports, duration, len(ports)))

        # ------------------------------------------------------------------
        # SINGLE HOST MODE
        # ------------------------------------------------------------------
        else:
            resolved_ip = self._resolve(target) if not self._is_ip(target) else target
            if not resolved_ip:
                findings.append(self.finding(
                    title       = f"DNS Resolution Failed: {target}",
                    description = f"Could not resolve `{target}` to an IP address.",
                    severity    = Severity.MEDIUM,
                    mitre_id    = "T1046",
                    evidence    = f"socket.gethostbyname('{target}') failed",
                    remediation = "Verify the hostname is correct and DNS is reachable.",
                ))
                return findings

            self.logger.info(f"[nmap_scan] Resolved {target} -> {resolved_ip}")
            t0 = time.monotonic()
            open_ports = await self._scan_host(resolved_ip, ports, timeout, concurrency)
            duration = time.monotonic() - t0
            findings.extend(
                self._build_findings(target, resolved_ip, open_ports, duration, len(ports))
            )

        return findings

    @staticmethod
    def _is_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False