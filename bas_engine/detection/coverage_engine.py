from collections import defaultdict

from bas_engine.detection.mitre_mapper import (
    get_tactic
)


class CoverageEngine:

    # ------------------------------------------------
    # CALCULATE COVERAGE
    # ------------------------------------------------

    def calculate_coverage(
        self,
        findings: list
    ):

        tactic_counts = defaultdict(int)

        total = 0

        for finding in findings:

            mitre_id = finding.get(
                "mitre_id"
            )

            tactic = get_tactic(
                mitre_id
            )

            tactic_counts[tactic] += 1

            total += 1

        # --------------------------------------------
        # BUILD COVERAGE %
        # --------------------------------------------

        coverage = {}

        for tactic, count in tactic_counts.items():

            coverage[tactic] = round(
                (count / total) * 100,
                2
            )

        return {

            "total_findings":
                total,

            "tactics_detected":
                len(tactic_counts),

            "coverage":
                coverage
        }