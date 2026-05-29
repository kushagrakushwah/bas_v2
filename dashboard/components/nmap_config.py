import streamlit as st

from components.recon.host_card import (
    render_host_card
)

from services.recon_api import (
    discover_subnet
)

# =========================================================
# ATTACK SURFACE PAGE
# =========================================================

def render_attack_surface():

    # =====================================================
    # HEADER
    # =====================================================

    st.title(
        "🌐 Attack Surface Intelligence"
    )

    st.markdown(

        """
Discover hosts, enumerate services,
fingerprint infrastructure,
and launch BAS attack simulations.
"""
    )

    # =====================================================
    # SCAN CONFIGURATION
    # =====================================================

    with st.container():

        st.subheader(
            "🔍 Discovery Configuration"
        )

        col1, col2 = st.columns(2)

        with col1:

            target = st.text_input(

                "Subnet / Target",

                placeholder="192.168.1.0/24"
            )

        with col2:

            port_range = st.text_input(

                "Port Range",

                value="1-1000"
            )

        col3, col4 = st.columns(2)

        with col3:

            scan_mode = st.selectbox(

                "Scan Profile",

                [

                    "Quick",
                    "Standard",
                    "Aggressive",
                    "Full"
                ]
            )

        with col4:

            timing_profile = st.selectbox(

                "Nmap Timing",

                [

                    "T2",
                    "T3",
                    "T4",
                    "T5"
                ],

                index=2
            )

    # =====================================================
    # DISCOVERY BUTTON
    # =====================================================

    if st.button(

        "🚀 Start Discovery",

        use_container_width=True
    ):

        if not target:

            st.error(
                "Please enter a target subnet or IP."
            )

            return

        # =================================================
        # LIVE DISCOVERY
        # =================================================

        with st.spinner(

            "Running subnet discovery..."
        ):

            try:

                data = discover_subnet(

                    target,
                    port_range
                )

                hosts = data.get(

                    "results",
                    []
                )

            except Exception as e:

                st.error(
                    f"Discovery failed: {e}"
                )

                return

        # =================================================
        # SUMMARY
        # =================================================

        st.success(
            f"Discovery completed. "
            f"{len(hosts)} host(s) identified."
        )

        st.divider()

        # =================================================
        # NO HOSTS
        # =================================================

        if not hosts:

            st.warning(
                "No live hosts discovered."
            )

            return

        # =================================================
        # DASHBOARD METRICS
        # =================================================

        total_ports = 0

        for host in hosts:

            total_ports += len(

                host.get(
                    "ports",
                    []
                )
            )

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(

                "Hosts Discovered",

                len(hosts)
            )

        with col2:

            st.metric(

                "Open Ports",

                total_ports
            )

        with col3:

            st.metric(

                "Attack Recommendations",

                total_ports
            )

        st.divider()

        # =================================================
        # HOST EXPLORER
        # =================================================

        st.subheader(
            "🖥️ Host Explorer"
        )

        for host in hosts:

            render_host_card(host)