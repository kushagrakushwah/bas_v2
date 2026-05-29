import json
import websocket
import streamlit as st
import threading
import queue


event_queue = queue.Queue()


# =========================================================
# WEBSOCKET CALLBACK
# =========================================================

def on_message(

    ws,

    message,
):

    try:

        data = json.loads(message)

        event_queue.put(data)

    except Exception:

        pass


# =========================================================
# START WS CLIENT
# =========================================================

def start_websocket(

    simulation_id,
):

    ws_url = (

        "ws://localhost:8000"
        f"/ws/{simulation_id}"
    )

    ws = websocket.WebSocketApp(

        ws_url,

        on_message=on_message
    )

    thread = threading.Thread(

        target=ws.run_forever,

        daemon=True
    )

    thread.start()


# =========================================================
# LIVE TELEMETRY PANEL
# =========================================================

def render_realtime_telemetry(

    simulation_id,
):

    st.subheader(
        "⚡ Live Telemetry"
    )

    start_websocket(
        simulation_id
    )

    telemetry_box = st.empty()

    logs = []

    while True:

        try:

            event = event_queue.get(
                timeout=1
            )

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

            line = (
                f"[{event_type}] "
                f"{timestamp} "
                f"{message}"
            )

            logs.append(line)

            telemetry_box.code(

                "\n".join(logs[-25:]),

                language="text"
            )

        except Exception:

            break