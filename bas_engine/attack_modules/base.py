"""
BaseAttackModule — abstract base class every attack module must extend.
"""

import uuid
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Any

from models.simulation import AttackModuleResult, Finding, Severity


class BaseAttackModule(ABC):
    """
    All attack modules inherit from this class.

    Subclass contract:
      1. Set `MODULE_NAME`  — unique identifier (snake_case)
      2. Set `DESCRIPTION`  — one-liner for the API
      3. Set `MITRE_TACTIC` — e.g. "Initial Access"
      4. Implement `execute()` — async coroutine, returns List[Finding]

    The `run()` wrapper handles timing, error catching, and result assembly.
    """

    MODULE_NAME:   str = "base_module"
    DESCRIPTION:   str = "Base attack module"
    MITRE_TACTIC:  str = "Unknown"
    MITRE_IDS:     List[str] = []

    def __init__(self, target: str, options: dict, sim_id: str):
        self.target  = target
        self.options = options
        self.sim_id  = sim_id
        self.logger  = logging.getLogger(f"secureforge.module.{self.MODULE_NAME}")

    @abstractmethod
    async def execute(self) -> List[Finding]:
        """Perform the actual simulation logic. Return list of Findings."""
        ...

    async def run(self) -> AttackModuleResult:
        """Wrapper — calls execute(), handles timing + exceptions."""
        started = datetime.utcnow()
        self.logger.info(f"[{self.MODULE_NAME}] Starting against {self.target}")
        try:
            findings = await self.execute()
            finished = datetime.utcnow()
            return AttackModuleResult(
                module      = self.MODULE_NAME,
                status      = "success",
                findings    = findings,
                started_at  = started,
                finished_at = finished,
                duration_s  = (finished - started).total_seconds(),
                stats       = {"findings_count": len(findings)},
            )
        except Exception as exc:
            finished = datetime.utcnow()
            self.logger.error(f"[{self.MODULE_NAME}] Error: {exc}", exc_info=True)
            return AttackModuleResult(
                module      = self.MODULE_NAME,
                status      = "error",
                findings    = [],
                error       = str(exc),
                started_at  = started,
                finished_at = finished,
                duration_s  = (finished - started).total_seconds(),
            )

    # ── Helper builders ────────────────────────────────────────────────────────

    def finding(
        self,
        title:       str,
        description: str,
        severity:    Severity,
        mitre_id:    str  = None,
        evidence:    str  = None,
        remediation: str  = None,
        raw_data:    dict = None,
    ) -> Finding:
        return Finding(
            id          = str(uuid.uuid4()),
            title       = title,
            description = description,
            severity    = severity,
            mitre_id    = mitre_id or (self.MITRE_IDS[0] if self.MITRE_IDS else None),
            evidence    = evidence,
            remediation = remediation,
            raw_data    = raw_data,
        )