import streamlit as st

from auth.auth_manager import (
    logout,
    current_role
)

# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------

def render_sidebar():

    st.sidebar.title(
        "🛡️ SecureForge"
    )

    st.sidebar.caption(
        "Enterprise BAS Platform"
    )

    st.sidebar.markdown("---")

    # ---------------------------------------------------
    # USER INFO
    # ---------------------------------------------------

    st.sidebar.subheader(
        "👤 Session"
    )

    st.sidebar.write(
        f"User: "
        f"{st.session_state.get('username')}"
    )

    st.sidebar.write(
        f"Role: "
        f"{current_role()}"
    )

    st.sidebar.markdown("---")

    # ---------------------------------------------------
    # NAVIGATION
    # ---------------------------------------------------

    page = st.sidebar.radio(

        "Navigation",

        [

            "Launch Center",
            "Realtime Operations",
            "MITRE ATT&CK",
            "SOC Validation",
            "Executive Analytics",
            "Campaign Engine",
            "Infrastructure",
            "Reports",
            "Alert Center"
        ]
    )

    st.sidebar.markdown("---")

    # ---------------------------------------------------
    # LOGOUT
    # ---------------------------------------------------

    if st.sidebar.button(
        "Logout",
        use_container_width=True
    ):

        logout()

        st.rerun()

    return page