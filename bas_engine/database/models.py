from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Float
)

from sqlalchemy.orm import relationship

from bas_engine.database.connection import Base

from datetime import datetime
import uuid


class SimulationDB(Base):

    __tablename__ = "simulations"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    name = Column(String)

    target = Column(String)

    status = Column(String)

    metadata_json = Column(JSON)
    
    detection_summary = Column(JSON)

    soc_score = Column(Float)

    coverage_data = Column(JSON)

    blindspot_data = Column(JSON)

    sigma_rules = Column(JSON)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    started_at = Column(DateTime)

    finished_at = Column(DateTime)
    

    module_results = relationship(
        "ModuleResultDB",
        back_populates="simulation",
        cascade="all, delete-orphan"
    )


class ModuleResultDB(Base):

    __tablename__ = "module_results"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    simulation_id = Column(
        String,
        ForeignKey("simulations.id")
    )

    module = Column(String)

    status = Column(String)

    error = Column(Text)

    stats = Column(JSON)

    started_at = Column(DateTime)

    finished_at = Column(DateTime)

    duration_s = Column(Float)

    simulation = relationship(
        "SimulationDB",
        back_populates="module_results"
    )

    findings = relationship(
        "FindingDB",
        back_populates="module_result",
        cascade="all, delete-orphan"
    )


class FindingDB(Base):

    __tablename__ = "findings"

    id = Column(
        String,
        primary_key=True
    )

    module_result_id = Column(
        String,
        ForeignKey("module_results.id")
    )

    title = Column(String)

    description = Column(Text)

    severity = Column(String)

    mitre_id = Column(String)

    evidence = Column(Text)

    remediation = Column(Text)

    raw_data = Column(JSON)

    timestamp = Column(DateTime)

    module_result = relationship(
        "ModuleResultDB",
        back_populates="findings"
    )


class EventDB(Base):

    __tablename__ = "events"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    event_type = Column(String)

    payload = Column(JSON)

    timestamp = Column(DateTime)