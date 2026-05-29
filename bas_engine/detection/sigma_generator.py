# ---------------------------------------------------
# SIGMA RULE TEMPLATES
# ---------------------------------------------------

SIGMA_TEMPLATES = {

    # ------------------------------------------------
    # SSH BRUTE FORCE
    # ------------------------------------------------

    "T1110": {

        "title":
            "SSH Brute Force Detection",

        "logsource": {
            "product": "linux"
        },

        "detection": {

            "selection": {
                "process": "sshd"
            },

            "condition":
                "selection"
        },

        "level":
            "high"
    },
    # ------------------------------------------------
# VALID ACCOUNTS
# ------------------------------------------------

    "T1078": {

        "title":
            "Valid Accounts Usage Detection",

        "logsource": {
            "product": "authentication"
        },

        "detection": {

            "selection": {
                "event_type":
                    "login_success"
            },

            "condition":
                "selection"
        },

        "level":
            "medium"
    },

    # ------------------------------------------------
    # PUBLIC APP EXPLOIT
    # ------------------------------------------------

    "T1190": {

        "title":
            "Public Facing Application Exploit",

        "logsource": {
            "product": "webserver"
        },

        "detection": {

            "selection": {
                "http_status": 500
            },

            "condition":
                "selection"
        },

        "level":
            "medium"
    },
    # ------------------------------------------------
# ACTIVE SCANNING
# ------------------------------------------------

    "T1595": {

        "title":
            "Reconnaissance Scanning Activity",

        "logsource": {
            "product": "network"
        },

        "detection": {

            "selection": {
                "event_type":
                    "network_scan"
            },

            "condition":
                "selection"
        },

        "level":
            "low"
    },

    # ------------------------------------------------
    # RANSOMWARE
    # ------------------------------------------------

    "T1486": {

        "title":
            "Potential Ransomware Activity",

        "logsource": {
            "product": "windows"
        },

        "detection": {

            "selection": {
                "file_extension":
                    ".encrypted"
            },

            "condition":
                "selection"
        },

        "level":
            "critical"
    },
    # ------------------------------------------------
# SERVER SOFTWARE COMPONENT
# ------------------------------------------------

    "T1505": {

        "title":
            "Potential Persistence Component Activity",

        "logsource": {
            "product": "webserver"
        },

        "detection": {

            "selection": {
                "event_type":
                    "plugin_upload"
            },

            "condition":
                "selection"
        },

        "level":
            "high"
    },
    # ------------------------------------------------
    # PRIVILEGE ESCALATION
    # ------------------------------------------------

    "T1548": {

        "title":
            "Privilege Escalation Attempt",

        "logsource": {
            "product": "linux"
        },

        "detection": {

            "selection": {
                "event_type":
                    "sudo_abuse"
            },

            "condition":
                "selection"
        },

        "level":
            "high"
    }
    
}
# ---------------------------------------------------
# SIGMA GENERATOR
# ---------------------------------------------------

class SigmaGenerator:

    # ------------------------------------------------
    # GENERATE RULE
    # ------------------------------------------------

    def generate_rule(
        self,
        finding: dict
    ):

        mitre_id = finding.get(
            "mitre_id"
        )

        template = SIGMA_TEMPLATES.get(
            mitre_id
        )

        if not template:

            return {

                "status":
                    "unsupported",

                "message":
                    f"No Sigma template for {mitre_id}"
            }

        return {

            "status":
                "success",

            "sigma_rule":
                template
        }

    # ------------------------------------------------
    # GENERATE MULTIPLE
    # ------------------------------------------------

    def generate_rules(
        self,
        findings: list
    ):

        rules = []

        for finding in findings:

            generated = (
                self.generate_rule(
                    finding
                )
            )

            rules.append(
                generated
            )

        return rules