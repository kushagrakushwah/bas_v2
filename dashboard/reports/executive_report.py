from datetime import datetime

# ---------------------------------------------------
# GENERATE REPORT
# ---------------------------------------------------

def generate_executive_report(simulations):

    total = len(simulations)

    completed = len([
        s for s in simulations
        if s.get("status") == "completed"
    ])

    findings = 0

    for sim in simulations:

        for module in sim.get(
            "module_results",
            []
        ):

            findings += len(
                module.get(
                    "findings",
                    []
                )
            )

    report = f"""
SECUREFORGE EXECUTIVE REPORT
Generated: {datetime.now()}

----------------------------------------

Total Simulations:
{total}

Completed Simulations:
{completed}

Total Findings:
{findings}

----------------------------------------

Security Posture Summary:

SecureForge BAS telemetry indicates
active detection visibility and
continuous attack simulation coverage.

Recommendations:
- Continue continuous BAS validation
- Monitor critical findings
- Expand MITRE ATT&CK coverage
"""

    return report