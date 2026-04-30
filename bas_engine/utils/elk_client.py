import logging
import aiohttp
import os
from datetime import datetime

logger = logging.getLogger("secureforge.elk")

class ELKClient:
    """Async client to push simulation events to Logstash."""
    def __init__(self):
        # Defaults to the Kubernetes service name 'logstash' on port 5044
        self.logstash_url = os.getenv("LOGSTASH_URL", "http://logstash.secureforge.svc.cluster.local:5044")
        self.session = None

    async def connect(self):
        self.session = aiohttp.ClientSession()
        logger.info(f"ELK Client initialized. Target: {self.logstash_url}")

    async def close(self):
        if self.session:
            await self.session.close()

    async def push_event(self, index: str, payload: dict):
        if not self.session:
            return
        
        event = {
            "@timestamp": datetime.utcnow().isoformat(),
            "_index_target": index,
            **payload
        }
        
        try:
            # Pushing to Logstash via HTTP input
            async with self.session.post(self.logstash_url, json=event, timeout=5) as resp:
                if resp.status not in (200, 201, 202):
                    logger.error(f"Failed to push to Logstash: {resp.status}")
        except Exception as e:
            logger.debug(f"ELK push failed (is Logstash running?): {e}")