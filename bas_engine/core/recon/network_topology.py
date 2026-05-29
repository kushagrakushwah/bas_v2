"""
Network Topology Engine

Future:
- attack path visualization
- subnet relationships
- lateral movement graphing
"""

from typing import List, Dict


class NetworkTopology:

    def build_topology(

        self,
        hosts: List[Dict],
    ) -> Dict:

        nodes = []

        edges = []

        for host in hosts:

            nodes.append({

                "id": host.get("host"),

                "label": host.get("host"),

                "ports": host.get(
                    "open_ports",
                    []
                )
            })

        return {

            "nodes": nodes,

            "edges": edges,
        }