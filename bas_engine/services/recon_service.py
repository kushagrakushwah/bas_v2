"""
Recon Service

Handles:
- subnet discovery
- nmap orchestration
- host intelligence
"""

import asyncio
import nmap

from typing import Dict, List

from bas_engine.core.recon.service_classifier import (
    ServiceClassifier
)

classifier = ServiceClassifier()


class ReconService:

    async def discover_subnet(

        self,
        target: str,
        ports: str = "1-1000",
    ) -> List[Dict]:

        scanner = nmap.PortScanner()

        loop = asyncio.get_event_loop()

        await loop.run_in_executor(

            None,

            lambda: scanner.scan(

                hosts=target,

                ports=ports,

                arguments="-sT -sV -Pn -T4"
            )
        )

        results = []

        for host in scanner.all_hosts():

            host_data = {

                "host": host,

                "hostname": (
                    scanner[host]
                    .hostname()
                ),

                "state": (
                    scanner[host]
                    .state()
                ),

                "os": "Unknown",

                "ports": []
            }

            if "tcp" in scanner[host]:

                for port in (

                    scanner[host]["tcp"]
                ):

                    service = (

                        scanner[host]["tcp"][port]
                    )

                    classified = (
                        classifier.classify(
                            port,
                            service.get(
                                "product",
                                ""
                            )
                        )
                    )

                    host_data["ports"].append(
                        classified
                    )

            results.append(host_data)

        return results