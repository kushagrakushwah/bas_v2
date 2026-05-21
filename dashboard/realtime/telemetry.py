import random
from datetime import datetime

# ---------------------------------------------------
# MOCK REALTIME TELEMETRY
# ---------------------------------------------------

EVENT_TYPES = [
    "simulation.started",
    "module.completed",
    "vulnerability.found",
    "simulation.failed",
    "simulation.completed"
]

SEVERITIES = [
    "info",
    "low",
    "medium",
    "high",
    "critical"
]

MODULES = [
    "waf_evasion",
    "nmap_scan",
    "owasp_web",
    "ssh_bruteforce",
    "credential_dumping"
]

TARGETS = [
    "https://target.local",
    "192.168.1.10",
    "corp.internal",
    "api.secureforge.local"
]

# ---------------------------------------------------
# GENERATE EVENTS
# ---------------------------------------------------

def generate_mock_events(count=15):

    events = []

    for _ in range(count):

        event_type = random.choice(EVENT_TYPES)

        events.append({
            "timestamp":
                datetime.now().strftime("%H:%M:%S"),

            "event":
                event_type,

            "severity":
                random.choice(SEVERITIES),

            "module":
                random.choice(MODULES),

            "target":
                random.choice(TARGETS)
        })

    return events