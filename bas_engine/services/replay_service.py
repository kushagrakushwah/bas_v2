from sqlalchemy import select

from bas_engine.database.connection import (
    AsyncSessionLocal
)

from bas_engine.database.models import (
    EventDB
)


class ReplayService:

    # ------------------------------------------------
    # GET SIMULATION TIMELINE
    # ------------------------------------------------

    async def get_simulation_timeline(
        self,
        sim_id: str
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(

                select(EventDB)

                .where(
                    EventDB.payload["id"].as_string() == sim_id
                )

                .order_by(
                    EventDB.timestamp.asc()
                )
            )

            events = result.scalars().all()

            return [

                {
                    "event_type":
                        e.event_type,

                    "payload":
                        e.payload,

                    "timestamp":
                        e.timestamp.isoformat()
                }

                for e in events
            ]

    # ------------------------------------------------
    # GET ALL EVENTS
    # ------------------------------------------------

    async def get_recent_events(
        self,
        limit: int = 100
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(

                select(EventDB)

                .order_by(
                    EventDB.timestamp.desc()
                )

                .limit(limit)
            )

            events = result.scalars().all()

            return [

                {
                    "event_type":
                        e.event_type,

                    "payload":
                        e.payload,

                    "timestamp":
                        e.timestamp.isoformat()
                }

                for e in events
            ]