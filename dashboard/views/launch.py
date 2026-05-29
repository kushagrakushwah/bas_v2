import re
import traceback
import streamlit as st
import pandas as pd
from datetime import datetime

from streamlit_autorefresh import st_autorefresh
from services.api_client import api
from components.findings import (
    render_status_badge,
    render_severity_badge
)

st_autorefresh(
    interval=5000,
    key="launch_refresh"
)

MODULE_INFO = {
    "nmap_scan": {"mitre": "T1046", "tactic": "Discovery", "technique": "Network Service Scanning"},
    "owasp_web": {"mitre": "T1190", "tactic": "Initial Access", "technique": "Exploit Public-Facing Application"},
    "ssh_bruteforce": {"mitre": "T1110", "tactic": "Credential Access", "technique": "Brute Force"},
    "waf_evasion": {"mitre": "T1190", "tactic": "Defense Evasion", "technique": "WAF Bypass"},
    "credential_dumping": {"mitre": "T1003", "tactic": "Credential Access", "technique": "OS Credential Dumping"},
    "lateral_movement": {"mitre": "T1021", "tactic": "Lateral Movement", "technique": "Remote Services"},
    "privilege_escalation": {"mitre": "T1548", "tactic": "Privilege Escalation", "technique": "Abuse Elevation Control"},
    "data_exfiltration": {"mitre": "T1041", "tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel"},
    "ransomware_sim": {"mitre": "T1486", "tactic": "Impact", "technique": "Data Encrypted for Impact"},
    "supply_chain": {"mitre": "T1195", "tactic": "Initial Access", "technique": "Supply Chain Compromise"},
    "network_load_sim": {"mitre": "T1499", "tactic": "Impact", "technique": "Endpoint DoS"},
    "apt_killchain": {"mitre": "TA0001-TA0040", "tactic": "Multi-Stage", "technique": "APT Kill Chain"}
}

AVAILABLE_MODULES = list(MODULE_INFO.keys())

ATTACK_RECOMMENDATIONS = {
    21: ["credential_dumping"],
    22: ["ssh_bruteforce"],
    23: ["credential_dumping"],
    25: ["owasp_web"],
    53: ["owasp_web"],
    80: ["owasp_web"],
    110: ["credential_dumping"],
    111: ["lateral_movement"],
    135: ["lateral_movement"],
    139: ["lateral_movement"],
    143: ["credential_dumping"],
    389: ["credential_dumping"],
    443: ["owasp_web"],
    445: ["lateral_movement"],
    587: ["credential_dumping"],
    993: ["credential_dumping"],
    995: ["credential_dumping"],
    1433: ["credential_dumping"],
    1521: ["credential_dumping"],
    3306: ["credential_dumping"],
    3389: ["credential_dumping"],
    5432: ["credential_dumping"],
    5900: ["lateral_movement"],
    6379: ["credential_dumping"],
    8080: ["owasp_web"],
    8443: ["owasp_web"]
}

RECOMMENDED_MODULE_CONFIG = {
    "ssh_bruteforce": {"parallel": False},
    "owasp_web": {"parallel": False},
    "credential_dumping": {"parallel": False},
    "lateral_movement": {"parallel": False}
}

def render_launch_page():

    st.title("🚀 Launch Center")
    st.caption("🟢 Live telemetry enabled • Auto-refresh every 5s")
    st.markdown("Configure and launch Breach & Attack Simulations.")

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
                default=[]
            )

            nmap_options = {}

            if "nmap_scan" in modules:
                st.markdown("---")
                st.subheader("🌐 Nmap Recon Configuration")

                coln1, coln2 = st.columns(2)

                with coln1:
                    scan_profile = st.selectbox(
                        "Scan Profile",
                        ["Quick Discovery", "Standard Discovery", "Adversary Mode", "Full Adversary"]
                    )
                    port_range = st.text_input("Port Range", value="1-1000")

                with coln2:
                    timing = st.selectbox("Timing", ["T2", "T3", "T4", "T5"], index=2)
                    concurrency = st.slider("Concurrency", min_value=10, max_value=500, value=100, step=10)

                assume_alive = st.checkbox("Assume Hosts Alive (-Pn)", value=False)
                subnet_scan = st.checkbox("Subnet Discovery Mode", value=False)
                service_detection = st.checkbox("Service Detection (-sV)", value=True)
                os_detection = st.checkbox("OS Detection (-O)", value=False)
                full_port_scan = st.checkbox("Scan All Ports (1-65535)", value=False)

                if full_port_scan:
                    port_range = "1-65535"

                profile_map = {
                    "Quick Discovery": "quick",
                    "Standard Discovery": "standard",
                    "Adversary Mode": "standard",
                    "Full Adversary": "full"
                }

                nmap_options = {
                    "profile": profile_map[scan_profile],
                    "ports": port_range,
                    "timing": timing,
                    "concurrency": concurrency,
                    "subnet_scan": subnet_scan,
                    "assume_alive": assume_alive,
                    "service_detection": service_detection,
                    "os_detection": os_detection
                }

            parallel = st.checkbox("Run Modules In Parallel", value=True)
            live_mode = st.checkbox("⚠️ LIVE MODE (Exploit)", value=False)
            
            submitted = st.form_submit_button("🚀 Launch Simulation")

    if submitted:
        if not target.strip():
            st.error("Target cannot be empty.")
        elif not modules:
            st.error("Select at least one module.")
        else:
            with st.spinner("Launching simulation..."):
                simulation_options = {}
                if "nmap_scan" in modules:
                    simulation_options["nmap_scan"] = nmap_options

                try:
                    result = api.launch_simulation(
                        name=sim_name,
                        target=target,
                        modules=modules,
                        parallel=parallel,
                        options=simulation_options,
                        metadata={"live_mode": live_mode}
                    )
                    if result:
                        st.success("Simulation launched successfully.")
                        st.code(result.get("id"))
                    else:
                        st.error("Failed to launch simulation.")
                except Exception as e:
                    st.error(f"API Error launching simulation: {e}")
                    st.code(traceback.format_exc())

    st.markdown("---")
    st.subheader("📊 Platform Summary")

    try:
        summary = api.summary()
        if summary:
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total", summary.get("total", 0))
            c2.metric("Queued", summary.get("queued", 0))
            c3.metric("Running", summary.get("running", 0))
            c4.metric("Completed", summary.get("completed", 0))
            c5.metric("Failed", summary.get("failed", 0))
        else:
            st.warning("Unable to fetch summary.")
    except Exception as e:
        st.error(f"Error fetching summary: {e}")

    st.markdown("---")
    st.subheader("📦 Available Modules")

    modules_table = []
    for module, info in MODULE_INFO.items():
        modules_table.append({
            "Module": module,
            "MITRE ID": info["mitre"],
            "Tactic": info["tactic"],
            "Technique": info["technique"]
        })

    st.dataframe(pd.DataFrame(modules_table))

    st.markdown("---")
    st.subheader("🧪 Simulation Results")

    # --- DEBUGGING INJECTED HERE (Set expanded=False for production) ---
    with st.expander("🛠️ DEBUG: Raw API List Simulations Output", expanded=False):
        try:
            simulations = api.list_simulations()
            st.write(simulations)
            if not isinstance(simulations, list):
                st.error("CRITICAL: api.list_simulations() is NOT returning a list! It is returning: " + str(type(simulations)))
        except Exception as e:
            st.error(f"API Error during list_simulations(): {e}")
            st.code(traceback.format_exc())
            simulations = []
    # -------------------------------------------------------------------

    if simulations and isinstance(simulations, list):
        rows = []
        for sim in simulations:
            if not isinstance(sim, dict):
                continue

            risk_score = 0
            if hasattr(api, 'calculate_risk_score'):
                risk_score = api.calculate_risk_score(sim)

            rows.append({
                "Name": sim.get("name"),
                "Target": sim.get("target"),
                "Status": sim.get("status"),
                "Modules": len(sim.get("modules", [])),
                "Findings": sim.get("total_findings", 0),
                "Critical": sim.get("critical_findings", 0),
                "Risk Score": risk_score
            })

        st.dataframe(pd.DataFrame(rows))
    else:
        st.info("No valid simulations available to display in table.")

    st.markdown("---")
    st.subheader("🔍 Detailed Findings")

    if simulations and isinstance(simulations, list):
        for sim in simulations:
            if not isinstance(sim, dict):
                continue

            with st.expander(f"{sim.get('name', 'Unknown')}"):
                render_status_badge(sim.get("status", "Unknown"))
                st.markdown("")
                st.write(f"### 🎯 Target: {sim.get('target', 'Unknown')}")

                try:
                    if hasattr(api, 'calculate_risk_score'):
                        st.write(f"### ⚠️ Risk Score: {api.calculate_risk_score(sim)}")
                except Exception as e:
                    st.warning(f"Could not calculate risk score: {e}")

                try:
                    findings = api.extract_findings(sim)
                except Exception as e:
                    st.error(f"CRASH in extract_findings() for sim {sim.get('name')}: {e}")
                    st.code(traceback.format_exc())
                    continue 

                if findings:
                    recommended_attacks = set()

                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue

                        description = str(finding.get("description", ""))
                        raw_data = finding.get("raw_data") or {}
                        port = raw_data.get("port")

                        # HYBRID RECOMMENDATION ENGINE
                        # First try: exact port match from raw_data
                        if port is not None:
                            try:
                                port_num = int(port)
                                if port_num in ATTACK_RECOMMENDATIONS:
                                    recommended_attacks.update(ATTACK_RECOMMENDATIONS[port_num])
                            except ValueError:
                                pass
                        
                        # Second try (Fallback): Regex search on the finding description
                        for rec_port, attacks in ATTACK_RECOMMENDATIONS.items():
                            pattern = rf"\b{rec_port}\b"
                            if re.search(pattern, description):
                                recommended_attacks.update(attacks)

                        st.markdown("---")
                        col1, col2 = st.columns([5, 1])

                        with col1:
                            st.markdown(f"### {finding.get('title', 'Untitled Finding')}")

                        with col2:
                            render_severity_badge(finding.get("severity", "info"))

                        st.write(finding.get("description", "No description provided."))
                        st.caption(f"MITRE ID: {finding.get('mitre_id', 'Unknown')}")

                    if recommended_attacks:
                        st.markdown("---")
                        st.subheader("🎯 Recommended Next Attacks")

                        cols = st.columns(min(len(recommended_attacks), 4))

                        for idx, attack in enumerate(sorted(recommended_attacks)):
                            with cols[idx % len(cols)]:
                                if st.button(f"🚀 Launch {attack}", key=f"rec_{sim.get('name')}_{attack}"):
                                    with st.spinner(f"Launching {attack}..."):
                                        config = RECOMMENDED_MODULE_CONFIG.get(attack, {})
                                        try:
                                            result = api.launch_simulation(
                                                name=f"{attack}-{datetime.now().strftime('%H%M%S')}",
                                                target=sim.get("target"),
                                                modules=[attack],
                                                parallel=config.get("parallel", False),
                                                options={},
                                                metadata={
                                                    "live_mode": False,
                                                    "triggered_by": "nmap_recommendation"
                                                }
                                            )

                                            if result:
                                                st.success(f"{attack} launched successfully")
                                                st.rerun()
                                            else:
                                                st.error(f"Failed to launch {attack}")
                                        except Exception as e:
                                            st.error(f"API Error launching {attack}: {e}")
                else:
                    st.info("No findings recorded.")
    else:
        st.info("No findings available.")