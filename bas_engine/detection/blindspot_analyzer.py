from bas_engine.detection.coverage_engine import (
    CoverageEngine
)


class BlindSpotAnalyzer:

    # ------------------------------------------------
    # FULL MITRE TACTIC SET
    # ------------------------------------------------

    ALL_TACTICS = [

        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Exfiltration",
        "Impact"
    ]

    def __init__(self):

        self.coverage_engine = (
            CoverageEngine()
        )

    # ------------------------------------------------
    # ANALYZE BLIND SPOTS
    # ------------------------------------------------

    def analyze(
        self,
        findings: list
    ):

        coverage_data = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        detected = set(
            coverage_data[
                "coverage"
            ].keys()
        )

        blind_spots = []

        for tactic in self.ALL_TACTICS:

            if tactic not in detected:

                blind_spots.append(
                    tactic
                )

        # --------------------------------------------
        # RISK LEVEL
        # --------------------------------------------

        count = len(blind_spots)

        if count >= 7:

            risk = "High"

        elif count >= 4:

            risk = "Moderate"

        else:

            risk = "Low"

        # --------------------------------------------
        # COVERAGE %
        # --------------------------------------------

        coverage_percent = round(

            (
                len(detected)
                / len(self.ALL_TACTICS)
            ) * 100,

            2
        )

        return {

            "coverage_percent":
                coverage_percent,

            "detected_tactics":
                list(detected),

            "blind_spots":
                blind_spots,

            "blind_spot_count":
                count,

            "risk_level":
                risk
        }