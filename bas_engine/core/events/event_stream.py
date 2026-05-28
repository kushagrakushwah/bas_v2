"""
Realtime Event Stream Engine
"""

from datetime import datetime


class EventStream:

    @staticmethod
    def build_event(

        simulation_id,

        event_type,

        message,

        metadata=None,
    ):

        return {

            "simulation_id":
                simulation_id,

            "timestamp":
                datetime.utcnow().isoformat(),

            "event_type":
                event_type,

            "message":
                message,

            "metadata":
                metadata or {},
        }