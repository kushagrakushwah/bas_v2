import random
from datetime import datetime

# ---------------------------------------------------
# MOCK LIVE EVENT STREAM
# ---------------------------------------------------

EVENTS = [
    "simulation.started",
    "module.started",
    "module.completed",
    "vulnerability.found",
    "simulation.completed"
]

MODULES = [
    "nmap_scan",
    "owasp_web",
    "waf_evasion",
    "credential_dumping",
    "lateral_movement"
]

TARGETS = [
    "https://target.local",
    "corp.internal",
    "192.168.1.10"
]

SEVERITIES = [
    "info",
    "medium",
    "high",
    "critical"
]

# ---------------------------------------------------
# LIVE EVENTS
# ---------------------------------------------------

def stream_live_events():

    return {
        "timestamp":
            datetime.now().strftime("%H:%M:%S"),

        "event":
            random.choice(EVENTS),

        "module":
            random.choice(MODULES),

        "target":
            random.choice(TARGETS),

        "severity":
            random.choice(SEVERITIES),

        "progress":
            random.randint(5, 100)
    }