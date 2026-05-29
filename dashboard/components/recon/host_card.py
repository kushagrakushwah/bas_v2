import streamlit as st

from components.recon.port_actions import (
    render_port_actions
)


def render_host_card(host):

    with st.container():

        col1, col2 = st.columns([4, 1])

        # =========================================
        # HOST INFO
        # =========================================

        with col1:

            st.subheader(

                host.get(
                    "host",
                    "unknown"
                )
            )

            st.caption(

                host.get(
                    "hostname",
                    "Unknown Host"
                )
            )

            st.write(

                f"OS: "
                f"{host.get('os', 'Unknown')}"
            )

        # =========================================
        # STATE
        # =========================================

        with col2:

            st.metric(

                "State",

                host.get(
                    "state",
                    "unknown"
                ).upper()
            )

        st.divider()

        # =========================================
        # PORTS
        # =========================================

        ports = host.get(
            "ports",
            []
        )

        if not ports:

            st.warning(
                "No open ports."
            )

            return

        st.write(
            "### Open Ports & Attack Actions"
        )

        for port_data in ports:

            render_port_actions(

                host["host"],
                port_data
            )