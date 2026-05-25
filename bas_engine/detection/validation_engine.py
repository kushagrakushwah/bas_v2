from detection.coverage_engine import (
    CoverageEngine
)

from detection.soc_scoring import (
    SOCScoringEngine
)

from detection.blindspot_analyzer import (
    BlindSpotAnalyzer
)

from detection.sigma_generator import (
    SigmaGenerator
)


class DetectionValidationEngine:

    def __init__(self):

        self.coverage_engine = (
            CoverageEngine()
        )

        self.soc_engine = (
            SOCScoringEngine()
        )

        self.blindspot_engine = (
            BlindSpotAnalyzer()
        )

        self.sigma_engine = (
            SigmaGenerator()
        )

    # ------------------------------------------------
    # FULL VALIDATION
    # ------------------------------------------------

    def validate(
        self,
        findings: list
    ):

        coverage = (
            self.coverage_engine
            .calculate_coverage(findings)
        )

        soc_score = (
            self.soc_engine
            .calculate_score(findings)
        )

        blindspots = (
            self.blindspot_engine
            .analyze(findings)
        )

        sigma_rules = (
            self.sigma_engine
            .generate_rules(findings)
        )

        return {

            "coverage":
                coverage,

            "soc_score":
                soc_score,

            "blindspots":
                blindspots,

            "sigma_rules":
                sigma_rules
        }