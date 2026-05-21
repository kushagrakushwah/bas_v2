import plotly.graph_objects as go

# ---------------------------------------------------
# CAMPAIGN TIMELINE
# ---------------------------------------------------

def build_campaign_timeline(simulations):

    names = []
    progress_values = []

    for sim in simulations:

        names.append(
            sim.get("name")
        )

        progress_values.append(
            sim.get("progress", 0)
        )

    fig = go.Figure()

    fig.add_trace(
        go.Bar(
            x=names,
            y=progress_values
        )
    )

    fig.update_layout(
        title="Campaign Progress Timeline",
        height=350,
        yaxis_title="Completion %",
        xaxis_title="Simulation"
    )

    return fig