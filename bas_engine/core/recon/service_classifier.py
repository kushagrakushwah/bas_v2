"""
Service Classifier

Converts:
- ports
- service banners

into:
- classified services
- risk scores
- attack recommendations
"""

from typing import Dict

from .attack_recommender import (
    AttackRecommender
)


COMMON_SERVICES = {

    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
}


HIGH_RISK_PORTS = {

    21,
    23,
    445,
    3389,
    6379,
}


class ServiceClassifier:

    def __init__(self):

        self.recommender = (
            AttackRecommender()
        )

    def classify(

        self,
        port: int,
        banner: str = "",
    ) -> Dict:

        service = COMMON_SERVICES.get(
            port,
            "unknown"
        )

        risk = (
            "high"
            if port in HIGH_RISK_PORTS
            else "medium"
        )

        return {

            "port": port,

            "service": service,

            "banner": banner,

            "risk": risk,

            "recommended_attacks": (
                self.recommender
                .recommend_by_port(port)
            )
        }