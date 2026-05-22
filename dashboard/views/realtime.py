import streamlit as st
import pandas as pd

from streamlit_autorefresh import (
    st_autorefresh
)

from services.api_client import api

from services.event_stream import (
    fetch_live_events,
    start_event_stream
)

from services.progress_tracker import (
    calculate_progress,
    determine_stage
)

from charts.progress_charts import (
    build_campaign_timeline
)

from components.findings import (
    render_severity_badge
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

st_autorefresh(
    interval=2000,
    key="progress_refresh"
)

# ---------------------------------------------------
# EVENT SEVERITY
# ---------------------------------------------------

def map_severity(event_type):

    event_type = str(event_type).lower()

    if "failed" in event_type:
        return "critical"

    if "vulnerability" in event_type:
        return "high"

    if "started" in event_type:
        return "medium"

    return "info"

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_realtime_page():

    st.title("📡 Live Attack Operations")
    start_event_stream()

    st.caption(
        "Realtime attack execution and campaign telemetry"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LOAD DATA
    # ---------------------------------------------------

    events = fetch_live_events()

    simulations = api.list_simulations()

    # ---------------------------------------------------
    # CALCULATE PROGRESS
    # ---------------------------------------------------

    for sim in simulations:

        progress = calculate_progress(sim)

        sim["progress"] = progress

        sim["stage"] = determine_stage(
            progress
        )

    # ---------------------------------------------------
    # GLOBAL METRICS
    # ---------------------------------------------------

    active_sims = len([
        s for s in simulations
        if s.get("status") == "running"
    ])

    completed = len([
        s for s in simulations
        if s.get("status") == "completed"
    ])

    findings = len([
        e for e in events
        if e.get("type") == "vulnerability.found"
    ])

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Active Simulations",
        active_sims
    )

    c2.metric(
        "Completed",
        completed
    )

    c3.metric(
        "Findings",
        findings
    )

    c4.metric(
        "Event Stream",
        "LIVE"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LIVE CAMPAIGN TRACKING
    # ---------------------------------------------------

    st.subheader(
        "⚔️ Live Campaign Tracking"
    )

    if simulations:

        for sim in simulations:

            progress = sim.get(
                "progress",
                0
            )

            stage = sim.get(
                "stage"
            )

            with st.container():

                st.markdown(
                    f"### {sim.get('name')}"
                )

                col1, col2, col3 = st.columns(
                    [3, 2, 2]
                )

                with col1:

                    st.write(
                        f"🎯 Target: "
                        f"{sim.get('target')}"
                    )

                with col2:

                    st.write(
                        f"📍 Stage: "
                        f"{stage}"
                    )

                with col3:

                    st.write(
                        f"📊 Progress: "
                        f"{progress}%"
                    )

                st.progress(
                    progress / 100
                )

                st.markdown("---")

    else:

        st.info(
            "No active campaigns."
        )

    # ---------------------------------------------------
    # CAMPAIGN TIMELINE
    # ---------------------------------------------------

    st.subheader(
        "📈 Campaign Timeline"
    )

    timeline_fig = build_campaign_timeline(
        simulations
    )

    st.plotly_chart(
        timeline_fig,
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LIVE EVENT STREAM
    # ---------------------------------------------------

    st.subheader(
        "⚡ Live EventBus Telemetry"
    )

    if events:

        for event in reversed(events):

            severity = map_severity(
                event.get("type")
            )

            payload = event.get(
                "payload",
                {}
            )

            with st.container():

                col1, col2, col3 = st.columns(
                    [2, 5, 1]
                )

                with col1:

                    st.caption(
                        event.get(
                            "timestamp",
                            "LIVE"
                        )
                    )

                with col2:

                    st.markdown(
                        f"### {event.get('type')}"
                    )

                    st.json(payload)

                with col3:

                    render_severity_badge(
                        severity
                    )

                st.markdown("---")

    else:

        st.warning(
            "No EventBus telemetry available."
        )

    # ---------------------------------------------------
    # ANALYTICS TABLE
    # ---------------------------------------------------

    st.subheader(
        "📊 Attack Operations Table"
    )

    rows = []

    for sim in simulations:

        rows.append({

            "Simulation":
                sim.get("name"),

            "Target":
                sim.get("target"),

            "Stage":
                sim.get("stage"),

            "Progress":
                sim.get("progress"),

            "Status":
                sim.get("status")
        })

    if rows:

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True
        )

    else:

        st.info(
            "No operations data available."
        )