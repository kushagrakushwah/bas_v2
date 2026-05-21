# ---------------------------------------------------
# EXECUTIVE SUMMARY GENERATOR
# ---------------------------------------------------

def build_executive_summary(
    simulations,
    findings,
    posture_score,
    detection_rate
):

    total_sims = len(simulations)

    total_findings = len(findings)

    critical_findings = len([
        f for f in findings
        if str(
            f.get("severity")
        ).lower() == "critical"
    ])

    summary = f"""
SecureForge BAS Executive Summary

Total Simulations Executed:
{total_sims}

Total Findings:
{total_findings}

Critical Findings:
{critical_findings}

SOC Posture Score:
{posture_score}/100

Detection Coverage:
{detection_rate}

Key Insights:
- Breach & Attack Simulations were successfully executed.
- ATT&CK coverage validation completed.
- Detection gap analysis performed.
- Risk posture calculated from simulation telemetry.
- Multiple attack tactics were emulated.

Recommendations:
- Improve detection visibility for uncovered ATT&CK tactics.
- Strengthen monitoring for lateral movement activity.
- Enhance alert correlation for privilege escalation attempts.
- Validate incident response playbooks regularly.
"""

    return summary