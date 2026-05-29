from fastapi import APIRouter

from bas_engine.services.replay_service import (
    ReplayService
)

router = APIRouter()

replay_service = ReplayService()


# ------------------------------------------------
# TIMELINE BY SIMULATION
# ------------------------------------------------

@router.get("/{sim_id}")

async def replay_simulation(
    sim_id: str
):

    return await replay_service.get_simulation_timeline(
        sim_id
    )


# ------------------------------------------------
# RECENT EVENTS
# ------------------------------------------------

@router.get("/recent/events")

async def recent_events():

    return await replay_service.get_recent_events()