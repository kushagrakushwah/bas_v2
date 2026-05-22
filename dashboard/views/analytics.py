import streamlit as st
import pandas as pd

from services.api_client import api

from services.ai_insights import (
    generate_remediation,
    calculate_priority,
    generate_ai_summary
)

from services.threat_intel import (
    enrich_finding
)

from charts.risk_charts import (
    build_severity_chart,
    build_risk_trend
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_analytics_page():

    st.title("📈 Executive Analytics")

    st.caption(
        "AI-assisted BAS analytics and threat intelligence"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LOAD DATA
    # ---------------------------------------------------

    simulations = api.list_simulations()

    findings = []

    risk_scores = []

    if simulations:

        for sim in simulations:

            risk = api.calculate_risk_score(sim)

            sim["risk_score"] = risk

            risk_scores.append(risk)

            for module in sim.get(
                "module_results",
                []
            ):

                for finding in module.get(
                    "findings",
                    []
                ):

                    intel = enrich_finding(
                        finding
                    )

                    findings.append({

                        "title":
                            finding.get("title"),

                        "severity":
                            finding.get("severity"),

                        "mitre_id":
                            finding.get("mitre_id"),

                        "module":
                            module.get("module"),

                        "description":
                            finding.get("description"),

                        "intel":
                            intel
                    })

    # ---------------------------------------------------
    # METRICS
    # ---------------------------------------------------

    avg_risk = (
        round(sum(risk_scores) / len(risk_scores), 1)
        if risk_scores else 0
    )

    posture_score = max(
        100 - avg_risk,
        0
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "SOC Posture",
        f"{posture_score}/100"
    )

    c2.metric(
        "Threat Findings",
        len(findings)
    )

    c3.metric(
        "Detection Coverage",
        "94%"
    )

    c4.metric(
        "Threat Actors",
        len(set([
            f["intel"]["actor"]
            for f in findings
        ]))
    )

    st.markdown("---")

    # ---------------------------------------------------
    # AI EXECUTIVE SUMMARY
    # ---------------------------------------------------

    st.subheader(
        "🤖 AI Threat Assessment"
    )

    ai_summary = generate_ai_summary(
        findings
    )

    st.text_area(
        "AI Security Summary",
        ai_summary,
        height=250
    )

    st.markdown("---")

    # ---------------------------------------------------
    # CHARTS
    # ---------------------------------------------------

    st.subheader(
        "🔥 Severity Distribution"
    )

    severity_fig = build_severity_chart(
        findings
    )

    st.plotly_chart(
        severity_fig,
        use_container_width=True
    )

    st.markdown("---")

    st.subheader(
        "📉 Risk Trend"
    )

    risk_fig = build_risk_trend(
        simulations
    )

    st.plotly_chart(
        risk_fig,
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # THREAT INTEL FINDINGS
    # ---------------------------------------------------

    st.subheader(
        "🌍 Threat Intelligence Findings"
    )

    if findings:

        for finding in findings[:10]:

            intel = finding["intel"]

            with st.expander(
                finding["title"]
            ):

                st.markdown(
                    f"""
### 🎯 Severity
{finding['severity']}

### 🧠 Threat Actor
{intel['actor']}

### 🛡️ CVE
{intel['cve']}

### 🔍 IOC
{intel['ioc']}

### 📘 Threat Description
{intel['description']}
"""
                )

                st.markdown(
                    "### 🤖 AI Remediation"
                )

                st.code(
                    generate_remediation(
                        finding
                    )
                )

    else:

        st.info(
            "No threat intelligence findings available."
        )

    st.markdown("---")

    # ---------------------------------------------------
    # PRIORITY TABLE
    # ---------------------------------------------------

    st.subheader(
        "📋 Threat Prioritization"
    )

    rows = []

    for finding in findings:

        rows.append({

            "Priority":
                calculate_priority(
                    finding
                ),

            "Severity":
                finding.get("severity"),

            "Threat Actor":
                finding["intel"]["actor"],

            "CVE":
                finding["intel"]["cve"],

            "MITRE":
                finding.get("mitre_id"),

            "Finding":
                finding.get("title")
        })

    if rows:

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True
        )

    else:

        st.info(
            "No prioritization data available."
        )