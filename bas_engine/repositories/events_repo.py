from sqlalchemy import select

from bas_engine.database.connection import (
    AsyncSessionLocal
)

from bas_engine.database.models import (
    EventDB
)

from datetime import datetime


class EventsRepository:

    # ------------------------------------------------
    # SAVE EVENT
    # ------------------------------------------------

    async def save_event(
        self,
        event_type: str,
        payload: dict,
        timestamp: str
    ):

        async with AsyncSessionLocal() as session:

# --------------------------------------------
# SAFE JSON SERIALIZATION
# --------------------------------------------

            def sanitize(obj):

                if isinstance(obj, datetime):

                    return obj.isoformat()

                elif isinstance(obj, dict):

                    return {
                        k: sanitize(v)
                        for k, v in obj.items()
                    }

                elif isinstance(obj, list):

                    return [
                        sanitize(v)
                        for v in obj
                    ]

                return obj


            safe_payload = sanitize(payload)

            db_event = EventDB(

                event_type=event_type,

                payload=safe_payload,

                timestamp=datetime.fromisoformat(
                    timestamp
                )
            )

            session.add(db_event)

            await session.commit()

    # ------------------------------------------------
    # GET EVENTS
    # ------------------------------------------------

    async def list_events(
        self,
        limit: int = 500
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(

                select(EventDB)

                .order_by(
                    EventDB.timestamp.desc()
                )

                .limit(limit)
            )

            return result.scalars().all()