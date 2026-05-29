import streamlit as st

from components.recon.simulation_status import (
    render_status
)


def render_live_simulation(

    simulation
):

    with st.container():

        st.subheader(
            "⚔️ Live Simulation"
        )

        st.code(
            simulation.get(
                "id",
                "unknown"
            )
        )

        render_status(simulation)

        st.write(
            "### Modules"
        )

        modules = simulation.get(
            "modules",
            []
        )

        for module in modules:

            st.write(
                f"• {module}"
            )

        st.write(
            "### Target"
        )

        st.code(
            simulation.get(
                "target",
                "unknown"
            )
        )