"""
Privilege Escalation Module
MITRE ATT&CK: T1068 — Exploitation for Privilege Escalation
              T1548 — Abuse Elevation Control Mechanism
              T1078 — Valid Accounts

Simulates local privilege escalation vectors typically run post-initial-access.
In simulation mode: runs checks that an attacker would run to FIND escalation paths.
In live mode: enumerates real system state (read-only, no exploitation).
"""

import asyncio
import subprocess
import os
import stat
import logging
import platform
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Finding, Severity

logger = logging.getLogger("secureforge.module.privesc")


class PrivEscModule(BaseAttackModule):
    MODULE_NAME  = "privilege_escalation"
    DESCRIPTION  = "Privilege escalation vector enumeration (T1068, T1548)"
    MITRE_TACTIC = "Privilege Escalation"
    MITRE_IDS    = ["T1068", "T1548", "T1548.001", "T1078"]

    async def execute(self) -> List[Finding]:
        findings: List[Finding] = []
        live = self.options.get("live_mode", False)

        if live and platform.system() == "Linux":
            findings.extend(await self._check_suid_binaries())
            findings.extend(await self._check_sudo_rules())
            findings.extend(await self._check_writable_paths())
            findings.extend(await self._check_cron_jobs())
            findings.extend(await self._check_world_writable_services())
            findings.extend(await self._check_docker_group())
            findings.extend(await self._check_kernel_version())
        else:
            # Simulation mode — representative findings based on common misconfiguration stats
            findings.extend(self._simulate_findings())

        return findings

    # ── Live Linux checks (read-only enumeration) ──────────────────────────────

    async def _check_suid_binaries(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "find / -perm -4000 -type f 2>/dev/null | head -50"
            )
            known_safe = {
                "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                "/bin/mount", "/bin/umount", "/usr/bin/newgrp",
                "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
            }
            unusual = [
                line.strip() for line in result.splitlines()
                if line.strip() and line.strip() not in known_safe
            ]

            gtfobins_candidates = [
                b for b in unusual
                if any(name in b for name in [
                    "find", "vim", "python", "ruby", "perl", "awk",
                    "nmap", "bash", "sh", "env", "tee", "cp", "mv",
                    "less", "more", "man", "git", "ftp", "ncat",
                ])
            ]

            if gtfobins_candidates:
                findings.append(self.finding(
                    title       = "SUID Binaries Exploitable via GTFOBins",
                    description = f"{len(gtfobins_candidates)} SUID binary(-ies) found that can be "
                                  "used for privilege escalation per GTFOBins: "
                                  + ", ".join(gtfobins_candidates[:5]),
                    severity    = Severity.HIGH,
                    mitre_id    = "T1548.001",
                    evidence    = f"SUID files: {gtfobins_candidates}",
                    remediation = (
                        "Remove SUID bit from non-essential binaries:\n"
                        "  chmod u-s <binary>\n"
                        "Audit: find / -perm -4000 -type f 2>/dev/null"
                    ),
                    raw_data    = {"suid_files": unusual, "gtfobins": gtfobins_candidates},
                ))
            elif unusual:
                findings.append(self.finding(
                    title       = "Unusual SUID Binaries Present",
                    description = f"{len(unusual)} non-standard SUID binaries found. Review required.",
                    severity    = Severity.MEDIUM,
                    mitre_id    = "T1548.001",
                    evidence    = str(unusual[:10]),
                    remediation = "Audit all SUID binaries and remove unnecessary SUID bits.",
                    raw_data    = {"unusual_suid": unusual},
                ))
        except Exception as e:
            self.logger.debug(f"SUID check failed: {e}")
        return findings

    async def _check_sudo_rules(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("sudo -l -n 2>/dev/null || true")
            if "NOPASSWD" in result:
                nopasswd_lines = [l for l in result.splitlines() if "NOPASSWD" in l]
                findings.append(self.finding(
                    title       = "Passwordless sudo Rules Configured",
                    description = f"NOPASSWD sudo entries found: any process running as this user "
                                  "can escalate to root without a password prompt.",
                    severity    = Severity.CRITICAL,
                    mitre_id    = "T1548.003",
                    evidence    = "\n".join(nopasswd_lines),
                    remediation = (
                        "Remove NOPASSWD from /etc/sudoers for non-essential commands.\n"
                        "Use 'sudo visudo' to safely edit. Apply principle of least privilege."
                    ),
                    raw_data    = {"sudo_rules": nopasswd_lines},
                ))
            elif "ALL" in result and "(ALL)" in result:
                findings.append(self.finding(
                    title       = "Unrestricted sudo Access",
                    description = "User has full sudo access (ALL) on this system.",
                    severity    = Severity.HIGH,
                    mitre_id    = "T1548.003",
                    evidence    = result[:500],
                    remediation = "Restrict sudo rules to specific required commands only.",
                ))
        except Exception as e:
            self.logger.debug(f"sudo check failed: {e}")
        return findings

    async def _check_writable_paths(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null"
            )
            if result.strip():
                writable = [l.strip() for l in result.splitlines() if l.strip()]
                findings.append(self.finding(
                    title       = "Writable Directories in PATH",
                    description = f"{len(writable)} PATH directory(-ies) are writable by the current user. "
                                  "An attacker could plant malicious binaries that get executed as a higher-privileged user.",
                    severity    = Severity.HIGH,
                    mitre_id    = "T1574.007",
                    evidence    = f"Writable PATH dirs: {writable}",
                    remediation = (
                        "1. Remove world-writable directories from PATH.\n"
                        "2. Ensure /tmp is not in PATH.\n"
                        "3. Set correct ownership/permissions on PATH directories."
                    ),
                    raw_data    = {"writable_dirs": writable},
                ))
        except Exception as e:
            self.logger.debug(f"PATH writable check failed: {e}")
        return findings

    async def _check_cron_jobs(self) -> List[Finding]:
        findings = []
        try:
            cron_dirs = [
                "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                "/etc/cron.weekly", "/var/spool/cron",
            ]
            world_writable = []
            for d in cron_dirs:
                if os.path.isdir(d):
                    for f in os.listdir(d):
                        fp  = os.path.join(d, f)
                        try:
                            st = os.stat(fp)
                            if st.st_mode & stat.S_IWOTH:
                                world_writable.append(fp)
                        except Exception:
                            pass

            if world_writable:
                findings.append(self.finding(
                    title       = "World-Writable Cron Job Files",
                    description = f"{len(world_writable)} cron file(s) are world-writable. "
                                  "An attacker can inject commands that execute as root on a schedule.",
                    severity    = Severity.CRITICAL,
                    mitre_id    = "T1053.003",
                    evidence    = str(world_writable),
                    remediation = (
                        "Set correct permissions on cron files:\n"
                        "  chmod 644 /etc/cron.d/*\n"
                        "  chown root:root /etc/cron.d/*"
                    ),
                    raw_data    = {"world_writable_cron": world_writable},
                ))
        except Exception as e:
            self.logger.debug(f"Cron check failed: {e}")
        return findings

    async def _check_docker_group(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("id")
            if "docker" in result:
                findings.append(self.finding(
                    title       = "Current User in Docker Group",
                    description = "Membership in the docker group is equivalent to root access. "
                                  "User can mount host filesystem via a container and read/write any file.",
                    severity    = Severity.CRITICAL,
                    mitre_id    = "T1611",
                    evidence    = f"id output: {result.strip()}",
                    remediation = (
                        "1. Remove non-admin users from the docker group.\n"
                        "2. Use rootless Docker or Podman for developer workflows.\n"
                        "3. Audit docker group membership regularly."
                    ),
                ))
        except Exception as e:
            self.logger.debug(f"Docker group check failed: {e}")
        return findings

    async def _check_world_writable_services(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd(
                "find /etc/systemd/system /lib/systemd/system -name '*.service' "
                "-writable 2>/dev/null | head -20"
            )
            if result.strip():
                files = [l.strip() for l in result.splitlines() if l.strip()]
                findings.append(self.finding(
                    title       = "Writable systemd Service Files",
                    description = f"{len(files)} systemd service file(s) are writable. "
                                  "An attacker can modify service definitions to execute arbitrary code as root on next restart.",
                    severity    = Severity.CRITICAL,
                    mitre_id    = "T1543.002",
                    evidence    = str(files[:5]),
                    remediation = (
                        "Set ownership and permissions:\n"
                        "  chown root:root /etc/systemd/system/*.service\n"
                        "  chmod 644 /etc/systemd/system/*.service"
                    ),
                    raw_data    = {"writable_services": files},
                ))
        except Exception as e:
            self.logger.debug(f"Service file check failed: {e}")
        return findings

    async def _check_kernel_version(self) -> List[Finding]:
        findings = []
        try:
            result = await self._run_cmd("uname -r")
            kernel = result.strip()
            # Rough heuristic: kernels < 5.15 have known privesc CVEs
            parts  = kernel.split(".")
            if len(parts) >= 2:
                major, minor = int(parts[0]), int(parts[1].split("-")[0])
                if major < 5 or (major == 5 and minor < 15):
                    findings.append(self.finding(
                        title       = f"Potentially Vulnerable Kernel: {kernel}",
                        description = f"Kernel version {kernel} predates 5.15 LTS and may be vulnerable to "
                                      "known local privilege escalation exploits (Dirty Pipe, OverlayFS, etc.).",
                        severity    = Severity.HIGH,
                        mitre_id    = "T1068",
                        evidence    = f"uname -r: {kernel}",
                        remediation = (
                            "Update kernel to latest LTS version:\n"
                            "  apt update && apt upgrade linux-image-generic   # Debian/Ubuntu\n"
                            "  yum update kernel                               # RHEL/CentOS"
                        ),
                        raw_data    = {"kernel": kernel},
                    ))
        except Exception as e:
            self.logger.debug(f"Kernel version check failed: {e}")
        return findings

    # ── Simulation mode ────────────────────────────────────────────────────────

    def _simulate_findings(self) -> List[Finding]:
        """
        Returns representative findings typical of a misconfigured Linux server.
        Used when live_mode=False or on non-Linux targets.
        """
        return [
            self.finding(
                title       = "[SIM] SUID Binary Exploitable — /usr/bin/find",
                description = "Simulation detected a commonly misconfigured SUID binary. "
                              "find with SUID set allows trivial privilege escalation.",
                severity    = Severity.HIGH,
                mitre_id    = "T1548.001",
                evidence    = "find / -perm -4000 -name find → /usr/bin/find",
                remediation = "Remove SUID bit: chmod u-s /usr/bin/find",
            ),
            self.finding(
                title       = "[SIM] Passwordless sudo — /usr/bin/python3",
                description = "Simulation: NOPASSWD sudo rule for python3 grants unrestricted code execution as root.",
                severity    = Severity.CRITICAL,
                mitre_id    = "T1548.003",
                evidence    = "sudo -l → (ALL) NOPASSWD: /usr/bin/python3",
                remediation = "Remove NOPASSWD rule from /etc/sudoers. Apply least-privilege sudo.",
            ),
            self.finding(
                title       = "[SIM] World-Writable Cron Script",
                description = "Simulation: /etc/cron.daily/backup.sh is world-writable. "
                              "Any user can inject commands executed as root on a schedule.",
                severity    = Severity.CRITICAL,
                mitre_id    = "T1053.003",
                evidence    = "ls -la /etc/cron.daily/backup.sh → -rwxrwxrwx",
                remediation = "chmod 755 /etc/cron.daily/backup.sh && chown root:root /etc/cron.daily/backup.sh",
            ),
            self.finding(
                title       = "[SIM] User in Docker Group",
                description = "Simulation: service account is in the docker group, enabling container escape to root.",
                severity    = Severity.CRITICAL,
                mitre_id    = "T1611",
                evidence    = "id → uid=1001 groups=1001,999(docker)",
                remediation = "gpasswd -d serviceaccount docker",
            ),
            self.finding(
                title       = "[SIM] Outdated Kernel — Potential Dirty Pipe",
                description = "Simulation: kernel 5.8.0 is potentially vulnerable to CVE-2022-0847 (Dirty Pipe).",
                severity    = Severity.HIGH,
                mitre_id    = "T1068",
                evidence    = "uname -r → 5.8.0-63-generic",
                remediation = "Upgrade kernel to >= 5.16.11 / 5.15.25 / 5.10.102.",
            ),
        ]

    async def _run_cmd(self, cmd: str) -> str:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return stdout.decode(errors="replace")