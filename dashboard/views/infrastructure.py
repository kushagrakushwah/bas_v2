import streamlit as st
import pandas as pd

from streamlit_autorefresh import (
    st_autorefresh
)

from services.infrastructure_service import (
    get_infrastructure_status
)

from charts.timelines import (
    build_resource_chart
)

from components.findings import (
    render_status_badge
)

# ---------------------------------------------------
# AUTO REFRESH
# ---------------------------------------------------

st_autorefresh(
    interval=5000,
    key="infra_refresh"
)

# ---------------------------------------------------
# PAGE
# ---------------------------------------------------

def render_infrastructure_page():

    st.title("☸️ Infrastructure Monitoring")

    st.caption(
        "Cluster telemetry and service health"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # LOAD STATUS
    # ---------------------------------------------------

    data = get_infrastructure_status()

    services = data["services"]

    cluster = data["cluster"]

    # ---------------------------------------------------
    # CLUSTER METRICS
    # ---------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Nodes",
        cluster["nodes"]
    )

    c2.metric(
        "Pods",
        cluster["pods"]
    )

    c3.metric(
        "Healthy Pods",
        cluster["healthy_pods"]
    )

    c4.metric(
        "CPU Usage",
        f"{cluster['cpu_usage']}%"
    )

    st.markdown("---")

    # ---------------------------------------------------
    # RESOURCE UTILIZATION
    # ---------------------------------------------------

    st.subheader(
        "📈 Cluster Resources"
    )

    fig = build_resource_chart(
        cluster
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.markdown("---")

    # ---------------------------------------------------
    # SERVICE STATUS
    # ---------------------------------------------------

    st.subheader(
        "🖥️ Service Health"
    )

    for service in services:

        with st.container():

            col1, col2, col3, col4 = st.columns(
                [3, 2, 2, 2]
            )

            with col1:

                st.markdown(
                    f"### {service['name']}"
                )

            with col2:

                render_status_badge(
                    service["status"]
                )

            with col3:

                st.metric(
                    "CPU",
                    f"{service['cpu']}%"
                )

            with col4:

                st.metric(
                    "Memory",
                    f"{service['memory']}%"
                )

            st.markdown("---")

    # ---------------------------------------------------
    # SERVICES TABLE
    # ---------------------------------------------------

    st.subheader(
        "📋 Infrastructure Inventory"
    )

    st.dataframe(
        pd.DataFrame(services),
        use_container_width=True
    )