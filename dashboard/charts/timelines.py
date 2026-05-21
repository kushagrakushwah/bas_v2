import plotly.graph_objects as go

# ---------------------------------------------------
# RESOURCE TIMELINE
# ---------------------------------------------------

def build_resource_chart(cluster):

    labels = [
        "CPU Usage",
        "Memory Usage"
    ]

    values = [
        cluster["cpu_usage"],
        cluster["memory_usage"]
    ]

    fig = go.Figure()

    fig.add_trace(
        go.Bar(
            x=labels,
            y=values
        )
    )

    fig.update_layout(
        title="Cluster Resource Utilization",
        height=350,
        yaxis_title="Usage %"
    )

    return fig