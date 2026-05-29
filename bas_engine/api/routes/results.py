from fastapi import APIRouter, Request, HTTPException
from bas_engine.models.simulation import SimulationResult

router = APIRouter()

@router.get("/{sim_id}", response_model=SimulationResult)
async def get_result(request: Request, sim_id: str):
    """Fetch findings for a specific simulation run."""
    result = request.app.state.orchestrator.get(sim_id)
    if not result:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return result