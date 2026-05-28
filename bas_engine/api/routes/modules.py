from fastapi import APIRouter
from bas_engine.attack_modules.registry import MODULE_REGISTRY

router = APIRouter()

@router.get("/")
async def list_modules():
    """Returns all available attack modules and their MITRE mappings."""
    return [
        {
            "id": key,
            "description": module.DESCRIPTION,
            "tactic": module.MITRE_TACTIC,
            "mitre_ids": module.MITRE_IDS
        }
        for key, module in MODULE_REGISTRY.items()
    ]