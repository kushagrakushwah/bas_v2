# ---------------------------------------------------
# ATTACK PROGRESS TRACKER
# ---------------------------------------------------

MODULE_STAGES = {

    "nmap_scan":
        10,

    "owasp_web":
        25,

    "waf_evasion":
        40,

    "credential_dumping":
        55,

    "privilege_escalation":
        70,

    "lateral_movement":
        85,

    "data_exfiltration":
        95,

    "ransomware_sim":
        100
}

# ---------------------------------------------------
# CALCULATE SIMULATION PROGRESS
# ---------------------------------------------------

def calculate_progress(simulation):

    modules = simulation.get(
        "module_results",
        []
    )

    if not modules:
        return 0

    max_progress = 0

    for module in modules:

        module_name = module.get(
            "module"
        )

        progress = MODULE_STAGES.get(
            module_name,
            5
        )

        if progress > max_progress:
            max_progress = progress

    return min(max_progress, 100)

# ---------------------------------------------------
# DETERMINE CURRENT STAGE
# ---------------------------------------------------

def determine_stage(progress):

    if progress < 20:
        return "Reconnaissance"

    if progress < 40:
        return "Initial Access"

    if progress < 60:
        return "Credential Access"

    if progress < 80:
        return "Privilege Escalation"

    if progress < 100:
        return "Lateral Movement"

    return "Impact Complete"