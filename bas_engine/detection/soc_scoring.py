from bas_engine.detection.coverage_engine import (
    CoverageEngine
)


class SOCScoringEngine:

    def __init__(self):

        self.coverage_engine = CoverageEngine()

    # ------------------------------------------------
    # CALCULATE SOC SCORE
    # ------------------------------------------------

    def calculate_score(
        self,
        findings: list
    ):

        coverage_data = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        coverage = coverage_data[
            "coverage"
        ]

        total_findings = coverage_data[
            "total_findings"
        ]

        tactics_detected = coverage_data[
            "tactics_detected"
        ]

        # --------------------------------------------
        # SEVERITY ANALYSIS
        # --------------------------------------------

        critical = 0
        high = 0
        medium = 0
        low = 0

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    ""
                )
            ).lower()

            if severity == "critical":
                critical += 1

            elif severity == "high":
                high += 1

            elif severity == "medium":
                medium += 1

            elif severity == "low":
                low += 1

        # --------------------------------------------
        # BASE SCORE
        # --------------------------------------------

        score = 100

        # Critical findings hurt heavily
        score -= critical * 15

        # High severity findings
        score -= high * 8

        # Medium severity findings
        score -= medium * 3

        # Unknown coverage penalty
        if tactics_detected < 4:
            score -= 10

        # Coverage reward
        score += min(
            tactics_detected * 2,
            10
        )

        # Clamp
        score = max(
            min(score, 100),
            0
        )

        # --------------------------------------------
        # RATING
        # --------------------------------------------

        if score >= 90:
            rating = "Excellent"

        elif score >= 75:
            rating = "Good"

        elif score >= 50:
            rating = "Moderate"

        else:
            rating = "Poor"

        # --------------------------------------------
        # BLIND SPOTS
        # --------------------------------------------

        blind_spots = max(
            12 - tactics_detected,
            0
        )

        return {

            "soc_score":
                round(score, 2),

            "rating":
                rating,

            "coverage_strength":
                f"{tactics_detected} tactics",

            "critical_findings":
                critical,

            "high_findings":
                high,

            "medium_findings":
                medium,

            "low_findings":
                low,

            "blind_spots":
                blind_spots,

            "coverage":
                coverage
        }