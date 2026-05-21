import streamlit as st

# ---------------------------------------------------
# STATUS BADGES
# ---------------------------------------------------

def render_status_badge(status: str):

    status = str(status).lower()

    colors = {
        "completed": "#00c853",
        "running": "#ffab00",
        "queued": "#90a4ae",
        "failed": "#ff5252",
        "cancelled": "#616161"
    }

    color = colors.get(status, "#90a4ae")

    st.markdown(
        f"""
        <span style="
            background-color:{color};
            color:white;
            padding:4px 12px;
            border-radius:12px;
            font-size:12px;
            font-weight:bold;
        ">
        {status.upper()}
        </span>
        """,
        unsafe_allow_html=True
    )

# ---------------------------------------------------
# SEVERITY BADGES
# ---------------------------------------------------

def render_severity_badge(severity: str):

    severity = str(severity).lower()

    colors = {
        "critical": "#d50000",
        "high": "#ff1744",
        "medium": "#ff9100",
        "low": "#00c853",
        "info": "#2962ff"
    }

    color = colors.get(severity, "#90a4ae")

    st.markdown(
        f"""
        <span style="
            background-color:{color};
            color:white;
            padding:4px 12px;
            border-radius:12px;
            font-size:12px;
            font-weight:bold;
        ">
        {severity.upper()}
        </span>
        """,
        unsafe_allow_html=True
    )