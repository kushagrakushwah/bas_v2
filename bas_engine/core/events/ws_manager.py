"""
WebSocket Connection Manager
"""

from collections import defaultdict

from fastapi import WebSocket


class WSManager:

    def __init__(self):

        self.connections = (
            defaultdict(list)
        )

    async def connect(

        self,

        simulation_id,

        websocket: WebSocket,
    ):

        await websocket.accept()

        self.connections[
            simulation_id
        ].append(websocket)

    def disconnect(

        self,

        simulation_id,

        websocket,
    ):

        if simulation_id in self.connections:

            self.connections[
                simulation_id
            ].remove(websocket)

    async def broadcast(

        self,

        simulation_id,

        data,
    ):

        for ws in self.connections.get(

            simulation_id,

            []
        ):

            await ws.send_json(data)


manager = WSManager()