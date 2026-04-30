"""
Data models — Pydantic v2 schemas for the BAS Engine API.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class SimulationStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


# ── Finding ────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    id:          str
    title:       str
    description: str
    severity:    Severity
    mitre_id:    Optional[str]  = None   # e.g. T1110, T1059
    evidence:    Optional[str]  = None
    remediation: Optional[str]  = None
    raw_data:    Optional[dict] = None
    timestamp:   datetime       = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


# ── Attack Module Result ────────────────────────────────────────────────────────

class AttackModuleResult(BaseModel):
    module:      str
    status:      str                    # "success" | "error" | "partial"
    findings:    List[Finding]          = []
    error:       Optional[str]          = None
    stats:       Dict[str, Any]         = {}
    started_at:  Optional[datetime]     = None
    finished_at: Optional[datetime]     = None
    duration_s:  Optional[float]        = None

    class Config:
        use_enum_values = True


# ── Simulation Request ─────────────────────────────────────────────────────────

class SimulationRequest(BaseModel):
    name:     str                    = Field(..., description="Human-readable simulation name")
    target:   str                    = Field(..., description="Target host/IP/URL")
    modules:  List[str]              = Field(..., description="List of attack module names")
    parallel: bool                   = Field(False, description="Run modules in parallel")
    options:  Dict[str, Any]         = Field(default_factory=dict, description="Per-module options")
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("modules")
    @classmethod
    def modules_not_empty(cls, v):
        if not v:
            raise ValueError("At least one attack module must be specified")
        return v

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()


# ── Simulation Result ──────────────────────────────────────────────────────────

class SimulationResult(BaseModel):
    id:             str
    name:           str
    target:         str
    modules:        List[str]
    status:         str
    module_results: List[AttackModuleResult]   = []
    error:          Optional[str]              = None
    metadata:       Dict[str, Any]             = {}
    created_at:     datetime
    updated_at:     datetime
    started_at:     Optional[datetime]         = None
    finished_at:    Optional[datetime]         = None

    @property
    def duration_s(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.module_results)

    @property
    def critical_findings(self) -> int:
        return sum(
            1 for r in self.module_results
            for f in r.findings
            if f.severity in (Severity.CRITICAL, "critical")
        )

    class Config:
        use_enum_values = True


# ── Summary ────────────────────────────────────────────────────────────────────

class SimulationSummary(BaseModel):
    total:     int
    queued:    int
    running:   int
    completed: int
    failed:    int