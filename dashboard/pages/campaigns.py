import streamlit as st
import pandas as pd

from services.api_client import api

from services.campaign_engine import (
    CAMPAIGNS,
    build_campaign_payload
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_campaigns_page():

    st.title("⚔️ Campaign Engine")

    st.caption(
        "Multi-stage BAS attack orchestration"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # CAMPAIGN SELECTOR
    # ---------------------------------------------------

    selected_campaign = st.selectbox(
        "Select Campaign",
        list(CAMPAIGNS.keys())
    )

    target = st.text_input(
        "Campaign Target",
        placeholder="https://target.local"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # CAMPAIGN MODULES
    # ---------------------------------------------------

    st.subheader(
        "🧩 Attack Chain"
    )

    modules = CAMPAIGNS[selected_campaign]

    chain_rows = []

    for idx, module in enumerate(modules):

        chain_rows.append({
            "Step": idx + 1,
            "Module": module
        })

    st.dataframe(
        pd.DataFrame(chain_rows),
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # EXECUTE CAMPAIGN
    # ---------------------------------------------------

    if st.button(
        "🚀 Execute Campaign",
        use_container_width=True
    ):

        if not target.strip():

            st.error(
                "Target required."
            )

        else:

            payload = build_campaign_payload(
                selected_campaign,
                target
            )

            result = api.launch_simulation(
                name=payload["name"],
                target=payload["target"],
                modules=payload["modules"],
                parallel=payload["parallel"],
                metadata=payload["metadata"]
            )

            if result:

                st.success(
                    "Campaign launched successfully."
                )

                st.code(
                    result.get("id")
                )

            else:

                st.error(
                    "Campaign execution failed."
                )

    st.markdown("---")

    # ---------------------------------------------------
    # CAMPAIGN DESCRIPTIONS
    # ---------------------------------------------------

    st.subheader(
        "📚 Campaign Profiles"
    )

    descriptions = {

        "APT Recon Chain":
            "Recon + web probing + credential access",

        "Lateral Movement Chain":
            "Credential abuse and movement simulation",

        "Ransomware Impact Chain":
            "Privilege escalation followed by impact simulation",

        "Data Exfiltration Chain":
            "Simulates theft of sensitive data",

        "Full Kill Chain":
            "Full multi-stage adversary emulation"
    }

    for name, desc in descriptions.items():

        with st.expander(name):

            st.write(desc)

            st.write(
                "Modules:"
            )

            for module in CAMPAIGNS[name]:

                st.markdown(
                    f"- `{module}`"
                )