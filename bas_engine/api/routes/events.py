from fastapi import APIRouter, Request

router = APIRouter()

# ---------------------------------------------------
# LIVE EVENT HISTORY
# ---------------------------------------------------

@router.get("/")
async def get_events(
    request: Request,
    limit: int = 50
):

    event_bus = request.app.state.event_bus

    return event_bus.get_history(limit=limit)