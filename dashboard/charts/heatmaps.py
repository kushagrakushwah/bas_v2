import plotly.graph_objects as go

# ---------------------------------------------------
# DETECTION GAP HEATMAP
# ---------------------------------------------------

def build_detection_heatmap(gap_data):

    tactics = list(gap_data.keys())

    scores = [
        gap_data[t]["coverage"]
        for t in tactics
    ]

    fig = go.Figure(
        data=go.Heatmap(
            z=[scores],
            x=tactics,
            y=["Coverage"],
            colorscale="RdYlGn",
            zmin=0,
            zmax=100,
            showscale=True
        )
    )

    fig.update_layout(
        title="Detection Coverage Heatmap",
        height=300,
        margin=dict(
            l=20,
            r=20,
            t=50,
            b=20
        )
    )

    return fig