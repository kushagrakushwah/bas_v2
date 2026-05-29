import websocket
import threading
import json

import streamlit as st

# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------

if "ws_events" not in st.session_state:

    st.session_state.ws_events = []

# ---------------------------------------------------
# MESSAGE HANDLER
# ---------------------------------------------------

def on_message(ws, message):

    try:

        data = json.loads(message)

        st.session_state.ws_events.insert(
            0,
            data
        )

        st.session_state.ws_events = (
            st.session_state.ws_events[:50]
        )

    except Exception:
        pass

# ---------------------------------------------------
# START STREAM
# ---------------------------------------------------

def start_event_stream():

    if st.session_state.get(
        "ws_started"
    ):
        return

    st.session_state.ws_started = True

    ws = websocket.WebSocketApp(

        "ws://localhost:8000/ws/events",

        on_message=on_message
    )

    thread = threading.Thread(

        target=ws.run_forever,

        daemon=True
    )

    thread.start()

# ---------------------------------------------------
# FETCH EVENTS
# ---------------------------------------------------

def fetch_live_events():

    return st.session_state.get(
        "ws_events",
        []
    )