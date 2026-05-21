# ---------------------------------------------------
# AI REMEDIATION ENGINE
# ---------------------------------------------------

def generate_remediation(finding):

    severity = str(
        finding.get(
            "severity",
            "info"
        )
    ).lower()

    title = str(
        finding.get(
            "title",
            ""
        )
    ).lower()

    # ---------------------------------------------------
    # RULE-BASED AI LOGIC
    # ---------------------------------------------------

    if "brute" in title:

        return """
- Enforce MFA for all remote access.
- Apply account lockout thresholds.
- Monitor authentication anomalies.
- Restrict SSH exposure externally.
"""

    if "waf" in title:

        return """
- Strengthen WAF filtering rules.
- Enable anomaly scoring.
- Inspect encoded payloads.
- Add behavioral bot detection.
"""

    if "credential" in title:

        return """
- Rotate privileged credentials immediately.
- Enable LSASS protection.
- Audit credential access events.
- Enforce PAM solutions.
"""

    if "exfiltration" in title:

        return """
- Monitor outbound traffic anomalies.
- Enable DLP policies.
- Restrict sensitive egress paths.
- Alert on archive staging behavior.
"""

    if severity == "critical":

        return """
- Immediate SOC escalation required.
- Isolate affected systems.
- Perform incident response triage.
- Validate containment controls.
"""

    return """
- Review security telemetry.
- Validate detection coverage.
- Strengthen monitoring rules.
- Perform mitigation testing.
"""

# ---------------------------------------------------
# AI PRIORITY ENGINE
# ---------------------------------------------------

def calculate_priority(finding):

    severity = str(
        finding.get(
            "severity",
            "info"
        )
    ).lower()

    weights = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "info": "P5"
    }

    return weights.get(
        severity,
        "P5"
    )

# ---------------------------------------------------
# EXECUTIVE AI SUMMARY
# ---------------------------------------------------

def generate_ai_summary(findings):

    total = len(findings)

    critical = len([
        f for f in findings
        if str(
            f.get("severity")
        ).lower() == "critical"
    ])

    high = len([
        f for f in findings
        if str(
            f.get("severity")
        ).lower() == "high"
    ])

    return f"""
AI Security Assessment Summary

SecureForge identified {total} findings across the simulated attack surface.

Critical Findings:
{critical}

High Severity Findings:
{high}

AI Assessment:
- Multiple attack paths were successfully emulated.
- Detection coverage exists but several ATT&CK gaps remain.
- Priority should be given to credential access and lateral movement visibility.
- Security posture is moderately resilient but requires additional hardening.

Recommended Next Actions:
1. Improve ATT&CK coverage.
2. Enhance alert correlation.
3. Strengthen identity protection.
4. Increase telemetry visibility.
"""