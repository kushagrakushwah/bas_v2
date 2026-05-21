import requests
import streamlit as st

API_BASE = "http://localhost:8000/api/v1"

# ---------------------------------------------------
# FETCH LIVE EVENTS
# ---------------------------------------------------

@st.cache_data(ttl=2)
def fetch_live_events():

    try:

        response = requests.get(
            f"{API_BASE}/events",
            timeout=5
        )

        response.raise_for_status()

        return response.json()

    except Exception as e:

        st.error(
            f"Event Stream Error: {e}"
        )

        return []