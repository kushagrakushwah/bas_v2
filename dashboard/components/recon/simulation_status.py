import streamlit as st


def render_status(

    simulation
):

    status = simulation.get(
        "status",
        "unknown"
    )

    if status == "completed":

        st.success(
            "Simulation Completed"
        )

    elif status == "running":

        st.warning(
            "Simulation Running"
        )

    elif status == "failed":

        st.error(
            "Simulation Failed"
        )

    else:

        st.info(
            status.upper()
        )