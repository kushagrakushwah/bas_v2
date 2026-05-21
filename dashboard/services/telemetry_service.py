import requests
import streamlit as st

API_BASE = "http://localhost:8000/api/v1"

TIMEOUT = 5

# ---------------------------------------------------
# FETCH TELEMETRY EVENTS
# ---------------------------------------------------

@st.cache_data(ttl=3)
def fetch_events():

    try:

        response = requests.get(
            f"{API_BASE}/health",
            timeout=TIMEOUT
        )

        response.raise_for_status()

        # TEMPORARY FALLBACK EVENTS
        # Until backend telemetry endpoint is added

        return [
            {
                "timestamp": "LIVE",
                "event": "simulation.started",
                "severity": "medium",
                "module": "waf_evasion",
                "target": "https://target.local"
            },
            {
                "timestamp": "LIVE",
                "event": "module.completed",
                "severity": "info",
                "module": "nmap_scan",
                "target": "192.168.1.10"
            },
            {
                "timestamp": "LIVE",
                "event": "vulnerability.found",
                "severity": "high",
                "module": "owasp_web",
                "target": "corp.internal"
            }
        ]

    except Exception as e:

        st.error(f"Telemetry Error: {e}")

        return []