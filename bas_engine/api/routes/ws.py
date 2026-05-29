from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# ---------------------------------------------------
# ACTIVE CONNECTIONS
# ---------------------------------------------------

active_connections = []

# ---------------------------------------------------
# WEBSOCKET ENDPOINT
# ---------------------------------------------------

@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):

    await websocket.accept()

    active_connections.append(
        websocket
    )

    try:

        while True:

            # Keep alive
            await websocket.receive_text()

    except WebSocketDisconnect:

        if websocket in active_connections:

            active_connections.remove(
                websocket
            )

# ---------------------------------------------------
# BROADCAST EVENT
# ---------------------------------------------------

async def broadcast_event(event):

    disconnected = []

    for connection in active_connections:

        try:

            await connection.send_json(event)

        except Exception:

            disconnected.append(
                connection
            )

    for conn in disconnected:

        if conn in active_connections:

            active_connections.remove(conn)