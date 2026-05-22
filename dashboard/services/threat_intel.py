# ---------------------------------------------------
# THREAT INTELLIGENCE DATABASE
# ---------------------------------------------------

THREAT_DB = {

    "credential": {

        "cve": "CVE-2023-23397",

        "actor":
            "APT29",

        "ioc":
            "Suspicious LSASS access",

        "risk":
            "Critical",

        "description":
            "Credential dumping activity associated with advanced adversaries."
    },

    "waf": {

        "cve": "CVE-2021-44228",

        "actor":
            "FIN7",

        "ioc":
            "Encoded payload delivery",

        "risk":
            "High",

        "description":
            "WAF evasion attempts targeting exposed web applications."
    },

    "lateral": {

        "cve": "CVE-2020-1472",

        "actor":
            "BlackCat",

        "ioc":
            "SMB lateral authentication",

        "risk":
            "Critical",

        "description":
            "Lateral movement activity observed in ransomware operations."
    },

    "exfiltration": {

        "cve": "CVE-2019-19781",

        "actor":
            "LockBit",

        "ioc":
            "Large outbound encrypted transfer",

        "risk":
            "Critical",

        "description":
            "Potential data exfiltration and staging activity."
    }
}

# ---------------------------------------------------
# ENRICH FINDING
# ---------------------------------------------------

def enrich_finding(finding):

    title = str(
        finding.get(
            "title",
            ""
        )
    ).lower()

    for keyword, intel in THREAT_DB.items():

        if keyword in title:

            return intel

    return {

        "cve": "N/A",

        "actor": "Unknown",

        "ioc": "No IOC mapping",

        "risk": "Medium",

        "description":
            "Generic suspicious activity."
    }