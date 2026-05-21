import streamlit as st

from auth.auth_manager import (
    is_authenticated
)

from pages.login import (
    render_login_page
)

from components.sidebar import (
    render_sidebar
)

from pages.launch import (
    render_launch_page
)

from pages.realtime import (
    render_realtime_page
)

from pages.mitre import (
    render_mitre_page
)

from pages.soc_validation import (
    render_soc_page
)

from pages.analytics import (
    render_analytics_page
)

from pages.campaigns import (
    render_campaigns_page
)

from pages.infrastructure import (
    render_infrastructure_page
)

from pages.reports import (
    render_reports_page
)

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="SecureForge",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------
# SESSION DEFAULTS
# ---------------------------------------------------

if "authenticated" not in st.session_state:

    st.session_state.authenticated = False

# ---------------------------------------------------
# AUTH GATE
# ---------------------------------------------------

if not is_authenticated():

    render_login_page()

    st.stop()

# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------

page = render_sidebar()

# ---------------------------------------------------
# ROUTING
# ---------------------------------------------------

if page == "Launch Center":

    render_launch_page()

elif page == "Realtime Operations":

    render_realtime_page()

elif page == "MITRE ATT&CK":

    render_mitre_page()

elif page == "SOC Validation":

    render_soc_page()

elif page == "Executive Analytics":

    render_analytics_page()

elif page == "Campaign Engine":

    render_campaigns_page()

elif page == "Infrastructure":

    render_infrastructure_page()

elif page == "Reports":

    render_reports_page()