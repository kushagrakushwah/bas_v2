import streamlit as st
import pandas as pd
from datetime import datetime

from streamlit_autorefresh import st_autorefresh

from services.api_client import api

from components.findings import (
    render_status_badge,
    render_severity_badge
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

st_autorefresh(
    interval=5000,
    key="launch_refresh"
)

# ---------------------------------------------------
# MODULE DEFINITIONS
# ---------------------------------------------------

MODULE_INFO = {
    "nmap_scan": {
        "mitre": "T1046",
        "tactic": "Discovery",
        "technique": "Network Service Scanning"
    },
    "owasp_web": {
        "mitre": "T1190",
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application"
    },
    "ssh_bruteforce": {
        "mitre": "T1110",
        "tactic": "Credential Access",
        "technique": "Brute Force"
    },
    "waf_evasion": {
        "mitre": "T1190",
        "tactic": "Defense Evasion",
        "technique": "WAF Bypass"
    },
    "credential_dumping": {
        "mitre": "T1003",
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping"
    },
    "lateral_movement": {
        "mitre": "T1021",
        "tactic": "Lateral Movement",
        "technique": "Remote Services"
    },
    "privilege_escalation": {
        "mitre": "T1548",
        "tactic": "Privilege Escalation",
        "technique": "Abuse Elevation Control"
    },
    "data_exfiltration": {
        "mitre": "T1041",
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over C2 Channel"
    },
    "ransomware_sim": {
        "mitre": "T1486",
        "tactic": "Impact",
        "technique": "Data Encrypted for Impact"
    },
    "supply_chain": {
        "mitre": "T1195",
        "tactic": "Initial Access",
        "technique": "Supply Chain Compromise"
    },
    "network_load_sim": {
        "mitre": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint DoS"
    },
    "apt_killchain": {
        "mitre": "TA0001-TA0040",
        "tactic": "Multi-Stage",
        "technique": "APT Kill Chain"
    }
}

AVAILABLE_MODULES = list(MODULE_INFO.keys())

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_launch_page():

    st.title("🚀 Launch Center")

    st.caption(
        "🟢 Live telemetry enabled • Auto-refresh every 5s"
    )

    st.markdown(
        """
Configure and launch Breach & Attack Simulations.
"""
    )

    # ---------------------------------------------------
    # LAUNCH FORM
    # ---------------------------------------------------

    with st.form("launch_form"):

        col1, col2 = st.columns(2)

        with col1:

            sim_name = st.text_input(
                "Simulation Name",
                value=f"Simulation-{datetime.now().strftime('%H%M%S')}"
            )

            target = st.text_input(
                "Target URL/IP",
                placeholder="https://target.local"
            )

        with col2:

            modules = st.multiselect(
                "Select Attack Modules",
                AVAILABLE_MODULES,
                default=["waf_evasion"]
            )

            parallel = st.checkbox(
                "Run Modules In Parallel",
                value=True
            )

        live_mode = st.checkbox(
            "⚠️ LIVE MODE (Exploit)",
            value=False
        )

        submitted = st.form_submit_button(
            "🚀 Launch Simulation",
            use_container_width=True
        )

    # ---------------------------------------------------
    # LAUNCH
    # ---------------------------------------------------

    if submitted:

        if not target.strip():

            st.error("Target cannot be empty.")

        elif not modules:

            st.error("Select at least one module.")

        else:

            with st.spinner(
                "Launching simulation..."
            ):

                result = api.launch_simulation(
                    name=sim_name,
                    target=target,
                    modules=modules,
                    parallel=parallel,
                    metadata={
                        "live_mode": live_mode
                    }
                )

            if result:

                st.success(
                    "Simulation launched successfully."
                )

                st.code(result.get("id"))

            else:

                st.error(
                    "Failed to launch simulation."
                )

    st.markdown("---")

    # ---------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------

    st.subheader("📊 Platform Summary")

    summary = api.summary()

    if summary:

        c1, c2, c3, c4, c5 = st.columns(5)

        c1.metric(
            "Total",
            summary.get("total", 0)
        )

        c2.metric(
            "Queued",
            summary.get("queued", 0)
        )

        c3.metric(
            "Running",
            summary.get("running", 0)
        )

        c4.metric(
            "Completed",
            summary.get("completed", 0)
        )

        c5.metric(
            "Failed",
            summary.get("failed", 0)
        )

    else:

        st.warning(
            "Unable to fetch summary."
        )

    st.markdown("---")

    # ---------------------------------------------------
    # MODULES TABLE
    # ---------------------------------------------------

    st.subheader("📦 Available Modules")

    modules_table = []

    for module, info in MODULE_INFO.items():

        modules_table.append({
            "Module": module,
            "MITRE ID": info["mitre"],
            "Tactic": info["tactic"],
            "Technique": info["technique"]
        })

    st.dataframe(
        pd.DataFrame(modules_table),
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # SIMULATION RESULTS
    # ---------------------------------------------------

    st.subheader("🧪 Simulation Results")

    simulations = api.list_simulations()

    if simulations:

        rows = []

        for sim in simulations:

            rows.append({
                "Name":
                    sim.get("name"),

                "Target":
                    sim.get("target"),

                "Status":
                    sim.get("status"),

                "Modules":
                    len(sim.get("modules", [])),

                "Findings":
                    sim.get("total_findings", 0),

                "Critical":
                    sim.get("critical_findings", 0),

                "Risk Score":
                    api.calculate_risk_score(sim)
            })

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True
        )

    else:

        st.info(
            "No simulations available."
        )

    st.markdown("---")

    # ---------------------------------------------------
    # DETAILED FINDINGS
    # ---------------------------------------------------

    st.subheader("🔍 Detailed Findings")

    if simulations:

        for sim in simulations:

            with st.expander(
                f"{sim.get('name')}"
            ):

                render_status_badge(
                    sim.get("status")
                )

                st.markdown("")

                st.write(
                    f"### 🎯 Target: "
                    f"{sim.get('target')}"
                )

                st.write(
                    f"### ⚠️ Risk Score: "
                    f"{api.calculate_risk_score(sim)}"
                )

                findings = api.extract_findings(sim)

                if findings:

                    for finding in findings:

                        st.markdown("---")

                        col1, col2 = st.columns([5, 1])

                        with col1:

                            st.markdown(
                                f"### {finding.get('title')}"
                            )

                        with col2:

                            render_severity_badge(
                                finding.get("severity")
                            )

                        st.write(
                            finding.get("description")
                        )

                        st.caption(
                            f"MITRE ID: "
                            f"{finding.get('mitre_id')}"
                        )

                else:

                    st.info(
                        "No findings recorded."
                    )

    else:

        st.info(
            "No findings available."
        )