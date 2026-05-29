import streamlit as st
import pandas as pd

from services.api_client import api

from charts.heatmaps import (
    build_detection_heatmap
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_soc_page():

    st.title("🛡️ SOC Validation")

    st.caption(
        "Detection coverage and gap analysis"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LOAD DATA
    # ---------------------------------------------------

    simulations = api.list_simulations()

    findings = []

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
                        "module":
                            module.get("module"),

                        "severity":
                            finding.get("severity"),

                        "mitre_id":
                            finding.get("mitre_id"),

                        "title":
                            finding.get("title")
                    })

    # ---------------------------------------------------
    # DETECTION MODEL
    # ---------------------------------------------------

    gap_data = {
        "Initial Access": {
            "coverage": 92
        },
        "Execution": {
            "coverage": 88
        },
        "Persistence": {
            "coverage": 61
        },
        "Privilege Escalation": {
            "coverage": 54
        },
        "Defense Evasion": {
            "coverage": 41
        },
        "Credential Access": {
            "coverage": 73
        },
        "Discovery": {
            "coverage": 95
        },
        "Lateral Movement": {
            "coverage": 47
        },
        "Collection": {
            "coverage": 66
        },
        "Exfiltration": {
            "coverage": 52
        },
        "Impact": {
            "coverage": 89
        }
    }

    # ---------------------------------------------------
    # EXECUTIVE METRICS
    # ---------------------------------------------------

    avg_coverage = round(
        sum([
            t["coverage"]
            for t in gap_data.values()
        ]) / len(gap_data),
        1
    )

    blind_spots = len([
        t for t in gap_data.values()
        if t["coverage"] < 60
    ])

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Detection Coverage",
        f"{avg_coverage}%"
    )

    c2.metric(
        "Blind Spots",
        blind_spots
    )

    c3.metric(
        "Findings",
        len(findings)
    )

    c4.metric(
        "ATT&CK Tactics",
        len(gap_data)
    )

    st.markdown("---")

    # ---------------------------------------------------
    # HEATMAP
    # ---------------------------------------------------

    st.subheader(
        "🔥 Detection Coverage"
    )

    fig = build_detection_heatmap(
        gap_data
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # BLIND SPOTS
    # ---------------------------------------------------

    st.subheader(
        "⚠️ Detection Blind Spots"
    )

    blindspot_rows = []

    for tactic, data in gap_data.items():

        if data["coverage"] < 60:

            blindspot_rows.append({
                "Tactic": tactic,
                "Coverage": data["coverage"],
                "Status": "Needs Improvement"
            })

    if blindspot_rows:

        st.dataframe(
            pd.DataFrame(blindspot_rows),
            use_container_width=True
        )

    else:

        st.success(
            "No critical blind spots detected."
        )

    st.markdown("---")

    # ---------------------------------------------------
    # SOC FINDINGS
    # ---------------------------------------------------

    st.subheader(
        "📋 SOC Validation Findings"
    )

    if findings:

        st.dataframe(
            pd.DataFrame(findings),
            use_container_width=True
        )

    else:

        st.info(
            "No SOC findings available."
        )