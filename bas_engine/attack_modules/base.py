"""
BaseAttackModule — abstract base class every attack module must extend.
"""

import uuid
import logging

from abc import ABC, abstractmethod

from datetime import datetime

from typing import List

from bas_engine.models.simulation import (

    AttackModuleResult,
    Finding,
    Severity
)

from bas_engine.core.events.event_stream import (
    EventStream
)

from bas_engine.core.events.ws_manager import (
    manager
)


class BaseAttackModule(ABC):
    """
    All attack modules inherit from this class.

    Subclass contract:
      1. Set MODULE_NAME
      2. Set DESCRIPTION
      3. Set MITRE_TACTIC
      4. Implement execute()

    run() handles:
    - timing
    - telemetry
    - websocket events
    - exception handling
    """

    MODULE_NAME: str = "base_module"

    DESCRIPTION: str = "Base attack module"

    MITRE_TACTIC: str = "Unknown"

    MITRE_IDS: List[str] = []


    # =====================================================
    # INIT
    # =====================================================

    def __init__(

        self,
        target: str,
        options: dict,
        sim_id: str,
    ):

        self.target = target

        self.options = options

        self.sim_id = sim_id

        self.logger = logging.getLogger(

            f"secureforge.module.{self.MODULE_NAME}"
        )


    # =====================================================
    # ABSTRACT EXECUTION
    # =====================================================

    @abstractmethod
    async def execute(self) -> List[Finding]:

        """
        Actual attack logic.
        Must return findings.
        """

        ...


    # =====================================================
    # TELEMETRY EMITTER
    # =====================================================

    async def emit_event(

        self,

        event_type: str,

        message: str,

        metadata: dict = None,
    ):

        try:

            await manager.broadcast(

                self.sim_id,

                EventStream.build_event(

                    simulation_id=self.sim_id,

                    event_type=event_type,

                    message=message,

                    metadata=metadata or {},
                )
            )

        except Exception as e:

            self.logger.warning(

                f"Event emit failed: {e}"
            )


    # =====================================================
    # MAIN EXECUTION WRAPPER
    # =====================================================

    async def run(self) -> AttackModuleResult:

        started = datetime.utcnow()

        self.logger.info(

            f"[{self.MODULE_NAME}] "
            f"Starting against {self.target}"
        )

        # =================================================
        # START EVENT
        # =================================================

        await self.emit_event(

            "INFO",

            f"{self.MODULE_NAME} started",

            {

                "target": self.target,

                "module": self.MODULE_NAME,
            }
        )

        try:

            # =============================================
            # EXECUTE MODULE
            # =============================================

            findings = await self.execute()

            finished = datetime.utcnow()

            # =============================================
            # SUCCESS EVENT
            # =============================================

            await self.emit_event(

                "SUCCESS",

                f"{self.MODULE_NAME} completed",

                {

                    "findings":
                        len(findings),

                    "module":
                        self.MODULE_NAME,

                    "duration":
                        (
                            finished - started
                        ).total_seconds()
                }
            )

            # =============================================
            # FINDING EVENTS
            # =============================================

            for finding in findings:

                await self.emit_event(

                    "FINDING",

                    finding.title,

                    {

                        "severity":
                            str(
                                finding.severity
                            ),

                        "mitre_id":
                            finding.mitre_id,

                        "module":
                            self.MODULE_NAME,
                    }
                )

            # =============================================
            # RESULT
            # =============================================

            return AttackModuleResult(

                module=self.MODULE_NAME,

                status="success",

                findings=findings,

                started_at=started,

                finished_at=finished,

                duration_s=(
                    finished - started
                ).total_seconds(),

                stats={

                    "findings_count":
                        len(findings)
                },
            )

        # =================================================
        # EXCEPTION HANDLING
        # =================================================

        except Exception as exc:

            finished = datetime.utcnow()

            self.logger.error(

                f"[{self.MODULE_NAME}] "
                f"Error: {exc}",

                exc_info=True
            )

            # =============================================
            # ERROR EVENT
            # =============================================

            await self.emit_event(

                "ERROR",

                str(exc),

                {

                    "module":
                        self.MODULE_NAME
                }
            )

            return AttackModuleResult(

                module=self.MODULE_NAME,

                status="error",

                findings=[],

                error=str(exc),

                started_at=started,

                finished_at=finished,

                duration_s=(
                    finished - started
                ).total_seconds(),
            )


    # =====================================================
    # HELPER FINDING BUILDER
    # =====================================================

    def finding(

        self,

        title: str,

        description: str,

        severity: Severity,

        mitre_id: str = None,

        evidence: str = None,

        remediation: str = None,

        raw_data: dict = None,
    ) -> Finding:

        return Finding(

            id=str(uuid.uuid4()),

            title=title,

            description=description,

            severity=severity,

            mitre_id=(
                mitre_id
                or (
                    self.MITRE_IDS[0]
                    if self.MITRE_IDS
                    else None
                )
            ),

            evidence=evidence,

            remediation=remediation,

            raw_data=raw_data,
        )