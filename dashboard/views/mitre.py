import streamlit as st
import pandas as pd

from services.api_client import api

from charts.mitre_graph import (
    build_mitre_heatmap
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_mitre_page():

    st.title("🎯 MITRE ATT&CK")

    st.caption(
        "ATT&CK coverage and tactic visualization"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LOAD SIMULATIONS
    # ---------------------------------------------------

    simulations = api.list_simulations()

    findings = []

    # ---------------------------------------------------
    # EXTRACT FINDINGS
    # ---------------------------------------------------

    if simulations:

        for sim in simulations:

            for module in sim.get(
                "module_results",
                []
            ):

                for finding in module.get(
                    "findings",
                    []
                ):

                    findings.append({
                        "title":
                            finding.get("title"),

                        "severity":
                            finding.get("severity"),

                        "mitre_id":
                            finding.get("mitre_id"),

                        "description":
                            finding.get("description"),

                        "module":
                            module.get("module"),

                        "tactic":
                            map_tactic(
                                module.get("module")
                            )
                    })

    # ---------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Total Findings",
        len(findings)
    )

    c2.metric(
        "Mapped Techniques",
        len(set([
            f["mitre_id"]
            for f in findings
            if f["mitre_id"]
        ]))
    )

    c3.metric(
        "ATT&CK Tactics",
        len(set([
            f["tactic"]
            for f in findings
        ]))
    )

    st.markdown("---")

    # ---------------------------------------------------
    # HEATMAP
    # ---------------------------------------------------

    st.subheader(
        "🔥 ATT&CK Coverage Heatmap"
    )

    fig = build_mitre_heatmap(
        findings
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # FINDINGS TABLE
    # ---------------------------------------------------

    st.subheader(
        "📋 ATT&CK Findings"
    )

    if findings:

        df = pd.DataFrame(findings)

        st.dataframe(
            df,
            use_container_width=True
        )

    else:

        st.info(
            "No MITRE findings available."
        )

# ---------------------------------------------------
# TACTIC MAPPING
# ---------------------------------------------------

def map_tactic(module):

    mapping = {

        "nmap_scan":
            "Discovery",

        "owasp_web":
            "Initial Access",

        "ssh_bruteforce":
            "Credential Access",

        "waf_evasion":
            "Defense Evasion",

        "credential_dumping":
            "Credential Access",

        "lateral_movement":
            "Lateral Movement",

        "privilege_escalation":
            "Privilege Escalation",

        "data_exfiltration":
            "Exfiltration",

        "ransomware_sim":
            "Impact",

        "supply_chain":
            "Initial Access",

        "network_load_sim":
            "Impact",

        "apt_killchain":
            "Execution"
    }

    return mapping.get(
        module,
        "Discovery"
    )