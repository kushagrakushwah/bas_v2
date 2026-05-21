import requests
import streamlit as st
from typing import Dict, List, Optional

# ---------------------------------------------------
# CONFIG
# ---------------------------------------------------

API_BASE = "http://localhost:8000/api/v1"

TIMEOUT = 10

# ---------------------------------------------------
# API CLIENT
# ---------------------------------------------------

class APIClient:

    def __init__(self):
        self.base = API_BASE

    # ---------------------------------------------------
    # REQUEST WRAPPER
    # ---------------------------------------------------

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ):

        url = f"{self.base}{endpoint}"

        try:

            response = requests.request(
                method,
                url,
                timeout=TIMEOUT,
                **kwargs
            )

            response.raise_for_status()

            if response.text:
                return response.json()

            return None

        except requests.exceptions.RequestException as e:

            st.error(f"API Error: {e}")

            return None

    # ---------------------------------------------------
    # HEALTH
    # ---------------------------------------------------

    @st.cache_data(ttl=15)
    def health(_self):

        return _self._request(
            "GET",
            "/health"
        )

    # ---------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------

    @st.cache_data(ttl=15)
    def summary(_self):

        return _self._request(
            "GET",
            "/simulations/summary"
        )

    # ---------------------------------------------------
    # LIST SIMULATIONS
    # ---------------------------------------------------

    @st.cache_data(ttl=10)
    def list_simulations(_self):

        return _self._request(
            "GET",
            "/simulations"
        )

    # ---------------------------------------------------
    # SINGLE RESULT
    # ---------------------------------------------------

    @st.cache_data(ttl=10)
    def get_simulation(
        _self,
        sim_id: str
    ):

        return _self._request(
            "GET",
            f"/results/{sim_id}"
        )

    # ---------------------------------------------------
    # LAUNCH SIMULATION
    # ---------------------------------------------------

    def launch_simulation(
        self,
        name: str,
        target: str,
        modules: List[str],
        parallel: bool = True,
        options: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ):

        payload = {
            "name": name,
            "target": target,
            "modules": modules,
            "parallel": parallel,
            "options": options or {},
            "metadata": metadata or {}
        }

        result = self._request(
            "POST",
            "/simulations",
            json=payload
        )

        # Clear caches after launch
        st.cache_data.clear()

        return result

    # ---------------------------------------------------
    # RISK SCORING
    # ---------------------------------------------------

    def calculate_risk_score(
        self,
        simulation
    ):

        if not simulation:
            return 0

        weights = {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 5,
            "info": 1
        }

        score = 0

        for module in simulation.get(
            "module_results",
            []
        ):

            for finding in module.get(
                "findings",
                []
            ):

                severity = str(
                    finding.get(
                        "severity",
                        "info"
                    )
                ).lower()

                score += weights.get(
                    severity,
                    0
                )

        return min(score, 100)

    # ---------------------------------------------------
    # FINDINGS EXTRACTION
    # ---------------------------------------------------

    def extract_findings(
        self,
        simulation
    ):

        findings = []

        if not simulation:
            return findings

        for module in simulation.get(
            "module_results",
            []
        ):

            for finding in module.get(
                "findings",
                []
            ):

                findings.append({
                    "module":
                        module.get("module"),

                    "title":
                        finding.get("title"),

                    "severity":
                        finding.get("severity"),

                    "mitre_id":
                        finding.get("mitre_id"),

                    "description":
                        finding.get("description"),

                    "timestamp":
                        finding.get("timestamp")
                })

        return findings


# ---------------------------------------------------
# SINGLETON
# ---------------------------------------------------

api = APIClient()