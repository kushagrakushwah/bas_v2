"""
EventBus — lightweight async pub/sub for internal component communication.
Events are also forwarded to ELK via the elk_client when available.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime
from typing import Callable, Dict, List, Any
from bas_engine.repositories.events_repo import (
    EventsRepository
)
logger = logging.getLogger("secureforge.eventbus")


class EventBus:
    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = defaultdict(list)
        self._history:   List[dict] = []
        self._max_history = 1000
        self.repo = EventsRepository()

    def subscribe(self, event_type: str, handler: Callable):
        self._listeners[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: Callable):
        self._listeners[event_type].remove(handler)

    async def publish(self, event_type: str, payload: dict = None):
        event = {
            "type":      event_type,
            "payload":   payload or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.repo.save_event(
            event_type,
            payload or {},
            event["timestamp"]
        )

        # Store history (ring buffer)
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        logger.debug(f"Event: {event_type} | {payload}")

        # Notify all subscribers
        handlers = self._listeners.get(event_type, []) + self._listeners.get("*", [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Event handler error ({event_type}): {e}")

    def get_history(self, limit: int = 100, event_type: str = None) -> List[dict]:
        history = self._history
        if event_type:
            history = [e for e in history if e["type"] == event_type]
        return history[-limit:]