import plotly.graph_objects as go

# ---------------------------------------------------
# MITRE TACTIC ORDER
# ---------------------------------------------------

TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact"
]

# ---------------------------------------------------
# BUILD MITRE HEATMAP
# ---------------------------------------------------

def build_mitre_heatmap(findings):

    tactic_counts = {
        tactic: 0
        for tactic in TACTICS
    }

    for finding in findings:

        tactic = finding.get(
            "tactic",
            "Discovery"
        )

        if tactic in tactic_counts:
            tactic_counts[tactic] += 1

    x = list(tactic_counts.keys())
    y = ["Coverage"]
    z = [[tactic_counts[t] for t in x]]

    fig = go.Figure(
        data=go.Heatmap(
            z=z,
            x=x,
            y=y,
            colorscale="Reds",
            showscale=True
        )
    )

    fig.update_layout(
        title="MITRE ATT&CK Coverage Heatmap",
        height=300,
        margin=dict(
            l=20,
            r=20,
            t=50,
            b=20
        )
    )

    return fig