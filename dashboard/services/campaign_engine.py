from datetime import datetime

# ---------------------------------------------------
# PREDEFINED CAMPAIGNS
# ---------------------------------------------------

CAMPAIGNS = {

    "APT Recon Chain": [
        "nmap_scan",
        "owasp_web",
        "credential_dumping"
    ],

    "Lateral Movement Chain": [
        "credential_dumping",
        "lateral_movement",
        "privilege_escalation"
    ],

    "Ransomware Impact Chain": [
        "credential_dumping",
        "lateral_movement",
        "ransomware_sim"
    ],

    "Data Exfiltration Chain": [
        "owasp_web",
        "credential_dumping",
        "data_exfiltration"
    ],

    "Full Kill Chain": [
        "nmap_scan",
        "owasp_web",
        "credential_dumping",
        "privilege_escalation",
        "lateral_movement",
        "data_exfiltration",
        "ransomware_sim"
    ]
}

# ---------------------------------------------------
# BUILD CAMPAIGN PAYLOAD
# ---------------------------------------------------

def build_campaign_payload(
    campaign_name,
    target
):

    modules = CAMPAIGNS.get(
        campaign_name,
        []
    )

    return {
        "name":
            f"{campaign_name}-{datetime.now().strftime('%H%M%S')}",

        "target":
            target,

        "modules":
            modules,

        "parallel":
            False,

        "metadata": {
            "campaign": True,
            "campaign_name": campaign_name
        }
    }