import streamlit as st
import requests

from services.attack_launcher import (
    launch_attack
)

from components.recon.live_attack_console import (
    render_attack_console
)

# =====================================================
# API
# =====================================================

API_BASE = "http://localhost:8000/api/v1"

# =====================================================
# ATTACK RECOMMENDATIONS
# =====================================================

PORT_ATTACK_MAP = {

    22: [
        "ssh_bruteforce"
    ],

    21: [
        "ftp_bruteforce"
    ],

    80: [
        "waf_evasion",
        "owasp_web"
    ],

    443: [
        "waf_evasion",
        "owasp_web"
    ],

    445: [
        "smb_recon"
    ],

    3389: [
        "rdp_bruteforce"
    ],

    8080: [
        "owasp_web"
    ],

    8443: [
        "waf_evasion"
    ]
}

# =====================================================
# PORT ACTIONS
# =====================================================

def render_port_actions(

    host,
    port_data,
):

    port = port_data["port"]

    service = port_data.get(
        "service",
        "unknown"
    )

    attacks = PORT_ATTACK_MAP.get(
        port,
        []
    )

    with st.container():

        col1, col2, col3 = st.columns(
            [1, 2, 3]
        )

        # =========================================
        # PORT
        # =========================================

        with col1:

            st.code(
                f"{port}/tcp"
            )

        # =========================================
        # SERVICE
        # =========================================

        with col2:

            st.write(
                f"**{service.upper()}**"
            )

        # =========================================
        # ACTIONS
        # =========================================

        with col3:

            if not attacks:

                st.info(
                    "No mapped attacks"
                )

                return

            selected = st.selectbox(

                f"Actions for {host}-{port}",

                attacks,

                key=f"{host}_{port}"
            )

            # =====================================
            # LAUNCH
            # =====================================

            if st.button(

                f"🚀 Launch {selected}",

                key=f"launch_{host}_{port}"
            ):

                with st.spinner(

                    "Launching BAS simulation..."
                ):

                    try:

                        result = launch_attack(

                            host,

                            selected
                        )

                        render_attack_console(
                            result
                        )

                        st.success(
                            f"{selected} launched"
                        )

                    except Exception as e:

                        st.error(
                            f"Launch failed: {e}"
                        )