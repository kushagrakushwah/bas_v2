"""
Attack Recommendation Engine

Maps:
- ports
- services
- banners

to:
- BAS attack modules
- recon actions
- validation workflows
"""

from typing import Dict, List


PORT_ATTACK_MAP = {

    21: [
        "ftp_anonymous",
        "credential_spray",
    ],

    22: [
        "ssh_bruteforce",
        "ssh_enumeration",
    ],

    23: [
        "telnet_bruteforce",
    ],

    25: [
        "smtp_enum",
    ],

    53: [
        "dns_enum",
    ],

    80: [
        "waf_evasion",
        "owasp_web",
        "apt_killchain",
    ],

    110: [
        "pop3_enum",
    ],

    139: [
        "smb_enum",
    ],

    143: [
        "imap_enum",
    ],

    389: [
        "ldap_enum",
    ],

    443: [
        "waf_evasion",
        "apt_killchain",
        "owasp_web",
    ],

    445: [
        "smb_enum",
        "lateral_movement",
    ],

    3306: [
        "mysql_bruteforce",
    ],

    3389: [
        "rdp_bruteforce",
    ],

    5432: [
        "postgres_enum",
    ],

    6379: [
        "redis_misconfig",
    ],

    8080: [
        "web_fuzzing",
        "waf_evasion",
    ],
}


class AttackRecommender:

    def recommend_by_port(

        self,
        port: int,
    ) -> List[str]:

        return PORT_ATTACK_MAP.get(
            port,
            []
        )

    def recommend_for_host(

        self,
        open_ports: List[int],
    ) -> Dict[int, List[str]]:

        recommendations = {}

        for port in open_ports:

            recommendations[port] = (
                self.recommend_by_port(port)
            )

        return recommendations