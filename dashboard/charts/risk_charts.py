import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# ---------------------------------------------------
# SEVERITY DISTRIBUTION
# ---------------------------------------------------

def build_severity_chart(findings):

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                "info"
            )
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    fig = px.pie(
        names=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        title="Severity Distribution"
    )

    fig.update_layout(
        height=400
    )

    return fig

# ---------------------------------------------------
# RISK TREND
# ---------------------------------------------------

def build_risk_trend(simulations):

    names = []
    scores = []

    for sim in simulations:

        names.append(
            sim.get("name")
        )

        scores.append(
            sim.get("risk_score", 0)
        )

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=names,
            y=scores,
            mode="lines+markers",
            name="Risk Score"
        )
    )

    fig.update_layout(
        title="Simulation Risk Trend",
        height=400,
        xaxis_title="Simulation",
        yaxis_title="Risk Score"
    )

    return fig