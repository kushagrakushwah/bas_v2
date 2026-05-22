import streamlit as st

# ---------------------------------------------------
# ALERTS PAGE
# ---------------------------------------------------

def render_alerts_page():

    st.title("🔔 Alert Center")

    st.caption(
        "Realtime SOC notification pipeline"
    )

    st.markdown("---")

    st.subheader(
        "Slack Integration"
    )

    slack = st.text_input(
        "Slack Webhook URL",
        type="password"
    )

    st.markdown("---")

    st.subheader(
        "Email Alerts"
    )

    smtp_server = st.text_input(
        "SMTP Server"
    )

    smtp_port = st.number_input(
        "SMTP Port",
        value=587
    )

    smtp_user = st.text_input(
        "SMTP Username"
    )

    smtp_pass = st.text_input(
        "SMTP Password",
        type="password"
    )

    recipient = st.text_input(
        "Alert Recipient"
    )

    st.markdown("---")

    if st.button(
        "💾 Save Alert Configuration"
    ):

        st.success(
            "Alert configuration saved."
        )

    st.markdown("---")

    st.subheader(
        "Alert Policies"
    )

    st.checkbox(
        "Critical Findings",
        value=True
    )

    st.checkbox(
        "Simulation Failures",
        value=True
    )

    st.checkbox(
        "Realtime Attack Telemetry",
        value=False
    )

    st.checkbox(
        "Module Completion Events",
        value=False
    )

    st.markdown("---")

    st.info(
        "Slack and email environment variables can also be configured server-side."
    )