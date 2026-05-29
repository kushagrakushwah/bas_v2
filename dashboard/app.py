import streamlit as st

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(

    page_title="SecureForge",

    page_icon="🛡️",

    layout="wide"
)

# =====================================================
# AUTH
# =====================================================

from auth.auth_manager import (
    is_authenticated
)

from views.login import (
    render_login_page
)

# =====================================================
# SIDEBAR
# =====================================================

from components.sidebar import (
    render_sidebar
)

# =====================================================
# STANDARD VIEWS
# =====================================================

from views.launch import (
    render_launch_page
)

from views.realtime import (
    render_realtime_page
)

from views.mitre import (
    render_mitre_page
)

from views.soc_validation import (
    render_soc_page
)

from views.analytics import (
    render_analytics_page
)

from views.campaigns import (
    render_campaigns_page
)

from views.infrastructure import (
    render_infrastructure_page
)

from views.reports import (
    render_reports_page
)

from views.alerts import (
    render_alerts_page
)

# =====================================================
# RECON VIEW
# =====================================================

from views.recon.attack_surface import (
    render_attack_surface
)

# =====================================================
# SESSION STATE
# =====================================================

if "authenticated" not in st.session_state:

    st.session_state.authenticated = False

# =====================================================
# AUTH GATE
# =====================================================

if not is_authenticated():

    render_login_page()

    st.stop()

# =====================================================
# SIDEBAR NAVIGATION
# =====================================================

page = render_sidebar()

# =====================================================
# ROUTING
# =====================================================

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

elif page == "Alert Center":

    render_alerts_page()

