from fastapi import APIRouter

from bas_engine.services.recon_service import (
    ReconService
)

router = APIRouter()

service = ReconService()


@router.get("/discover")
async def discover(

    target: str,

    ports: str = "1-1000",
):

    results = await service.discover_subnet(

        target,
        ports
    )

    return {

        "target": target,

        "results": results
    }