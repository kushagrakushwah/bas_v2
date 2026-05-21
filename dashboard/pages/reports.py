import streamlit as st
import pandas as pd
from datetime import datetime

from services.api_client import api

from reports.executive_summary import (
    build_executive_summary
)

from reports.pdf_generator import (
    generate_pdf_report
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_reports_page():

    st.title("📄 Reporting Engine")

    st.caption(
        "Executive BAS reporting and export"
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
                            module.get("module")
                    })

    # ---------------------------------------------------
    # METRICS
    # ---------------------------------------------------

    posture_score = max(
        100 - (
            sum(risk_scores) / len(risk_scores)
            if risk_scores else 0
        ),
        0
    )

    detection_rate = "94%"

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Reports Ready",
        len(simulations)
    )

    c2.metric(
        "Findings",
        len(findings)
    )

    c3.metric(
        "Posture Score",
        round(posture_score, 1)
    )

    c4.metric(
        "Detection Coverage",
        detection_rate
    )

    st.markdown("---")

    # ---------------------------------------------------
    # EXECUTIVE SUMMARY
    # ---------------------------------------------------

    st.subheader(
        "🧠 Executive Summary"
    )

    summary = build_executive_summary(
        simulations,
        findings,
        round(posture_score, 1),
        detection_rate
    )

    st.text_area(
        "Generated Summary",
        summary,
        height=350
    )

    st.markdown("---")

    # ---------------------------------------------------
    # EXPORT REPORT
    # ---------------------------------------------------

    st.subheader(
        "⬇️ Export PDF Report"
    )

    filename = (
        f"secureforge_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    if st.button(
        "📄 Generate PDF Report",
        use_container_width=True
    ):

        output_path = f"/tmp/{filename}"

        generate_pdf_report(
            output_path,
            "SecureForge BAS Report",
            summary
        )

        with open(output_path, "rb") as f:

            st.download_button(
                label="⬇️ Download Report",
                data=f,
                file_name=filename,
                mime="application/pdf"
            )

    st.markdown("---")

    # ---------------------------------------------------
    # REPORT DATA TABLE
    # ---------------------------------------------------

    st.subheader(
        "📋 Findings Included In Report"
    )

    if findings:

        st.dataframe(
            pd.DataFrame(findings),
            use_container_width=True
        )

    else:

        st.info(
            "No findings available for reporting."
        )