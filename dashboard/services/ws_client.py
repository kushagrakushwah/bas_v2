"""
WebSocket Client
"""

import websocket
import json
import threading


class SimulationWebSocket:

    def __init__(

        self,
        simulation_id,
        callback,
    ):

        self.simulation_id = (
            simulation_id
        )

        self.callback = callback

        self.ws = None

    def start(self):

        url = (

            "ws://localhost:8000"
            f"/ws/{self.simulation_id}"
        )

        self.ws = websocket.WebSocketApp(

            url,

            on_message=self.on_message
        )

        thread = threading.Thread(

            target=self.ws.run_forever,

            daemon=True
        )

        thread.start()

    def on_message(

        self,
        ws,
        message,
    ):

        try:

            data = json.loads(message)

            self.callback(data)

        except Exception:

            pass