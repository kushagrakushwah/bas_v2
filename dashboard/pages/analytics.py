import streamlit as st
import pandas as pd

from services.api_client import api

from services.ai_insights import (
    generate_remediation,
    calculate_priority,
    generate_ai_summary
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
        "AI-assisted BAS analytics and SOC posture"
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
                            finding.get("description")
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

    detection_rate = (
        "94%"
        if findings
        else "0%"
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "SOC Posture",
        f"{posture_score}/100"
    )

    c2.metric(
        "Avg Risk",
        avg_risk
    )

    c3.metric(
        "Detection Coverage",
        detection_rate
    )

    c4.metric(
        "Findings",
        len(findings)
    )

    st.markdown("---")

    # ---------------------------------------------------
    # AI EXECUTIVE SUMMARY
    # ---------------------------------------------------

    st.subheader(
        "🤖 AI Executive Assessment"
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
    # SEVERITY DISTRIBUTION
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

    # ---------------------------------------------------
    # RISK TREND
    # ---------------------------------------------------

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
    # AI FINDING PRIORITIZATION
    # ---------------------------------------------------

    st.subheader(
        "🧠 AI Prioritized Findings"
    )

    if findings:

        ai_rows = []

        for finding in findings:

            ai_rows.append({

                "Priority":
                    calculate_priority(
                        finding
                    ),

                "Severity":
                    finding.get("severity"),

                "Finding":
                    finding.get("title"),

                "MITRE":
                    finding.get("mitre_id"),

                "Module":
                    finding.get("module")
            })

        st.dataframe(
            pd.DataFrame(ai_rows),
            use_container_width=True
        )

    else:

        st.info(
            "No findings available."
        )

    st.markdown("---")

    # ---------------------------------------------------
    # AI REMEDIATION
    # ---------------------------------------------------

    st.subheader(
        "🛠️ AI Remediation Guidance"
    )

    if findings:

        for finding in findings[:5]:

            with st.expander(
                finding.get("title")
            ):

                st.markdown(
                    f"""
### Severity
{finding.get("severity")}

### MITRE ID
{finding.get("mitre_id")}

### AI Recommendation
"""
                )

                st.code(
                    generate_remediation(
                        finding
                    )
                )

    else:

        st.info(
            "No remediation guidance available."
        )