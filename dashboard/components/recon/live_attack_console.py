import streamlit as st

from components.recon.live_simulation_panel import (
    render_live_simulation
)

from components.recon.realtime_telemetry import (
    render_realtime_telemetry
)


def render_attack_console(

    simulation
):

    simulation_id = simulation.get(
        "id",
        "unknown"
    )

    with st.container():

        st.subheader(
            "⚔️ Attack Launched"
        )

        st.success(
            "Simulation started successfully."
        )

        render_live_simulation(
            simulation
        )

        st.divider()

        # =========================================
        # REALTIME TELEMETRY
        # =========================================

        render_realtime_telemetry(
            simulation_id
        )

        st.divider()

        st.write(
            "### Raw Simulation Data"
        )

        st.json(simulation)