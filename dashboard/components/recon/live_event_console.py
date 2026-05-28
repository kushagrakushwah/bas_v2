import streamlit as st


def render_event(

    event
):

    event_type = event.get(
        "event_type",
        "INFO"
    )

    message = event.get(
        "message",
        ""
    )

    timestamp = event.get(
        "timestamp",
        ""
    )

    with st.container():

        st.caption(timestamp)

        if event_type == "ERROR":

            st.error(message)

        elif event_type == "WARNING":

            st.warning(message)

        elif event_type == "SUCCESS":

            st.success(message)

        else:

            st.info(message)