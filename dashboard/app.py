import streamlit as st
import requests
import pandas as pd
import os
import time
import urllib3
from datetime import datetime, timedelta, timezone
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
API_BASE_URL  = os.getenv("API_URL", "http://localhost:8000/api/v1")
ES_URL        = "https://192.168.10.62:9200"
ES_USER       = "Pixels@summersoc"
ES_PASS       = "Pixels@summersoc26"
VPN_IP        = "10.8.0.30"

# MITRE ATT&CK mapping per module
MITRE_MAP = {
    "waf_evasion":         {"id": "T1190",  "tactic": "Initial Access",        "name": "Exploit Public-Facing App"},
    "apt_killchain":       {"id": "T1595",  "tactic": "Reconnaissance",        "name": "Active Scanning"},
    "ssh_bruteforce":      {"id": "T1110",  "tactic": "Credential Access",     "name": "Brute Force"},
    "owasp_web":           {"id": "T1059",  "tactic": "Execution",             "name": "Command & Scripting"},
    "privilege_escalation":{"id": "T1548",  "tactic": "Privilege Escalation",  "name": "Abuse Elevation Control"},
    "lateral_movement":    {"id": "T1021",  "tactic": "Lateral Movement",      "name": "Remote Services"},
    "ransomware_sim":      {"id": "T1486",  "tactic": "Impact",                "name": "Data Encrypted for Impact"},
    "credential_dumping":  {"id": "T1003",  "tactic": "Credential Access",     "name": "OS Credential Dumping"},
    "data_exfiltration":   {"id": "T1041",  "tactic": "Exfiltration",          "name": "Exfil Over C2 Channel"},
    "supply_chain":        {"id": "T1195",  "tactic": "Initial Access",        "name": "Supply Chain Compromise"},
    "network_load_sim":    {"id": "T1498",  "tactic": "Impact",                "name": "Network DoS"},
    "nmap_scan":           {"id": "T1046",  "tactic": "Discovery",             "name": "Network Service Discovery"},
}

TACTIC_ORDER = [
    "Reconnaissance", "Initial Access", "Execution", "Credential Access",
    "Discovery", "Lateral Movement", "Privilege Escalation",
    "Exfiltration", "Impact"
]

# ─────────────────────────────────────────────
# ELASTICSEARCH HELPERS
# ─────────────────────────────────────────────

def es_query(index_pattern, query, size=100):
    try:
        url = f"{ES_URL}/{index_pattern}/_search"
        resp = requests.post(
            url, json={"query": query, "size": size},
            auth=(ES_USER, ES_PASS), verify=False, timeout=8
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

def get_soc_events_last_n_minutes(minutes=30):
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "bool": {
            "must": [{"match": {"source.ip": VPN_IP}}],
            "filter": [{"range": {"@timestamp": {"gte": threshold}}}]
        }
    }
    result = es_query("fosstlsoc-logs-modsec_audit_log-*", query, size=200)
    if not result:
        return []
    return result.get("hits", {}).get("hits", [])

def get_blocked_count(minutes=30):
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "bool": {
            "must": [
                {"match": {"source.ip": VPN_IP}},
                {"match": {"event.action": "blocked"}}
            ],
            "filter": [{"range": {"@timestamp": {"gte": threshold}}}]
        }
    }
    result = es_query("fosstlsoc-logs-modsec_audit_log-*", query)
    if not result:
        return 0, []
    hits = result.get("hits", {}).get("hits", [])
    rules = {}
    for h in hits:
        for r in h.get("fields", {}).get("rule.id", []):
            rules[r] = rules.get(r, 0) + 1
    return len(hits), rules

def get_brute_force_events(minutes=30):
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "bool": {
            "must": [{"match": {"source.ip": VPN_IP}}],
            "filter": [{"range": {"@timestamp": {"gte": threshold}}}]
        }
    }
    result = es_query("fosstlsoc-logs-roundcube_login-*", query, size=50)
    if not result:
        return []
    return result.get("hits", {}).get("hits", [])

def get_all_events_count(minutes=30):
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "bool": {
            "must": [{"match": {"source.ip": VPN_IP}}],
            "filter": [{"range": {"@timestamp": {"gte": threshold}}}]
        }
    }
    result = es_query("fosstlsoc-logs-*", query)
    if not result:
        return 0
    return result.get("hits", {}).get("total", {}).get("value", 0)

def get_module_detection(module_name, minutes=30):
    """Check if a specific module's attacks were detected by SOC."""
    module_queries = {
        "waf_evasion":    {"match": {"event.category": "web"}},
        "apt_killchain":  {"match": {"source.ip": VPN_IP}},
        "ssh_bruteforce": {"match": {"event.module": "roundcube_login"}},
        "owasp_web":      {"match": {"event.category": "web"}},
    }
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    base_query = module_queries.get(module_name, {"match": {"source.ip": VPN_IP}})
    query = {
        "bool": {
            "must": [{"match": {"source.ip": VPN_IP}}, base_query],
            "filter": [{"range": {"@timestamp": {"gte": threshold}}}]
        }
    }
    result = es_query("fosstlsoc-logs-*", query)
    if not result:
        return False, 0
    count = result.get("hits", {}).get("total", {}).get("value", 0)
    return count > 0, count

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SecureForge BAS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .detected-yes {
        background: #1a3a2a;
        border-left: 4px solid #00ff88;
        padding: 8px 12px;
        border-radius: 4px;
        margin: 4px 0;
    }
    .detected-no {
        background: #3a1a1a;
        border-left: 4px solid #ff4444;
        padding: 8px 12px;
        border-radius: 4px;
        margin: 4px 0;
    }
    .stage-card {
        border: 1px solid #444;
        border-radius: 8px;
        padding: 10px;
        margin: 5px 0;
    }
    .soc-score-big {
        font-size: 72px;
        font-weight: bold;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/color/96/security-shield-green.png", width=60)
    st.title("SecureForge BAS")
    st.caption("Breach & Attack Simulation Platform")
    st.divider()

    # Backend status
    st.subheader("🖥️ System Status")
    try:
        health = requests.get(f"{API_BASE_URL}/", timeout=3).json()
        st.success(f"BAS Engine: {health.get('status','?').upper()}")
    except:
        st.error("BAS Engine: OFFLINE")

    # ES status
    try:
        es_resp = requests.get(f"{ES_URL}/_cluster/health",
                               auth=(ES_USER, ES_PASS), verify=False, timeout=3).json()
        es_status = es_resp.get("status", "unknown")
        color = "🟢" if es_status == "green" else "🟡" if es_status == "yellow" else "🔴"
        st.success(f"{color} Elasticsearch: {es_status.upper()}")
    except:
        st.warning("Elasticsearch: Unreachable from pod")

    st.divider()
    st.subheader("📊 Simulation Stats")
    try:
        summary = requests.get(f"{API_BASE_URL}/simulations/summary", timeout=3).json()
        st.metric("Total Simulations", summary.get("total", 0))
        st.metric("Completed", summary.get("completed", 0))
        st.metric("Running", summary.get("running", 0))
    except:
        st.write("Awaiting data...")

    st.divider()
    st.caption(f"🕐 {datetime.now().strftime('%H:%M:%S')} — Auto-refresh off")
    if st.button("🔄 Refresh Dashboard"):
        st.rerun()

# ─────────────────────────────────────────────
# MAIN TABS
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 Launch Attack",
    "🔍 SOC Validation",
    "📈 SOC Health Score",
    "📊 Simulation Results"
])

# ══════════════════════════════════════════════
# TAB 1 — LAUNCH ATTACK
# ══════════════════════════════════════════════
with tab1:
    st.header("🚀 Configure & Launch Simulation")

    try:
        modules_data = requests.get(f"{API_BASE_URL}/modules/", timeout=3).json()
        available_modules = [m["id"] for m in modules_data]
    except:
        available_modules = [
            "ssh_bruteforce","owasp_web","privilege_escalation","waf_evasion",
            "lateral_movement","ransomware_sim","credential_dumping",
            "data_exfiltration","supply_chain","network_load_sim","nmap_scan","apt_killchain"
        ]

    with st.form("launch_form"):
        col1, col2 = st.columns(2)
        with col1:
            sim_name    = st.text_input("Simulation Name", "Nightly Baseline Scan")
            target_host = st.text_input("Target URL/IP", "https://tlsoc.nile.iitb.ac.in/moodle/")
        with col2:
            selected_modules = st.multiselect(
                "Select Attack Modules", available_modules, default=["waf_evasion"]
            )
            is_parallel = st.checkbox("Run Modules in Parallel", value=True)
            live_mode   = st.checkbox("⚠️ LIVE MODE (Exploit)", value=False)

        submitted = st.form_submit_button("🚀 Launch Simulation", use_container_width=True)

        if submitted:
            if not selected_modules:
                st.warning("Please select at least one module.")
            else:
                payload = {
                    "name": sim_name, "target": target_host,
                    "modules": selected_modules,
                    "parallel": is_parallel,
                    "options": {"live_mode": live_mode}
                }
                with st.spinner("Dispatching to Orchestrator..."):
                    res = requests.post(f"{API_BASE_URL}/simulations/", json=payload)
                    if res.status_code == 200:
                        st.success(f"✅ Simulation '{sim_name}' launched successfully!")
                        st.info("Switch to the **SOC Validation** tab after ~30s to see detection results.")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Failed: {res.text}")

    # Module info table
    st.divider()
    st.subheader("📋 Available Modules")
    module_info = []
    for m in available_modules:
        mitre = MITRE_MAP.get(m, {})
        module_info.append({
            "Module": m,
            "MITRE ID": mitre.get("id", "N/A"),
            "Tactic": mitre.get("tactic", "N/A"),
            "Technique": mitre.get("name", "N/A"),
        })
    st.dataframe(pd.DataFrame(module_info), use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════
# TAB 2 — SOC VALIDATION (THE NEW BIG FEATURE)
# ══════════════════════════════════════════════
with tab2:
    st.header("🔍 SOC Auto-Validation — Live Detection Status")
    st.caption("Queries Elasticsearch directly. No Kibana needed.")

    time_window = st.slider("Look-back window (minutes)", 5, 120, 30)

    col1, col2, col3, col4 = st.columns(4)

    # Fetch all metrics
    blocked_count, rules_fired = get_blocked_count(time_window)
    brute_events               = get_brute_force_events(time_window)
    all_events                 = get_all_events_count(time_window)
    soc_events                 = get_soc_events_last_n_minutes(time_window)

    with col1:
        st.metric("🛡️ WAF Blocks", blocked_count,
                  help="Requests blocked by ModSecurity in time window")
    with col2:
        st.metric("🔑 Brute Force Attempts", len(brute_events),
                  help="Failed login attempts in Roundcube logs")
    with col3:
        st.metric("📋 Total SOC Events", all_events,
                  help="All events across all log indices")
    with col4:
        st.metric("📌 ModSec Alerts", len(soc_events),
                  help="ModSecurity audit log entries")

    st.divider()

    # ── Per-Module Detection Status ──
    st.subheader("🎯 Per-Module SOC Detection")
    st.caption("Did the SOC pipeline detect each module's attacks?")

    try:
        simulations = requests.get(f"{API_BASE_URL}/simulations/", timeout=3).json()
        if isinstance(simulations, dict):
            simulations = simulations.get("simulations", simulations.get("items", []))
    except:
        simulations = []

    # Get unique modules run
    modules_run = set()
    for sim in simulations:
        for mr in sim.get("module_results", []):
            modules_run.add(mr.get("module", ""))

    if modules_run:
        for module in sorted(modules_run):
            detected, count = get_module_detection(module, time_window)
            mitre           = MITRE_MAP.get(module, {})
            col_a, col_b, col_c, col_d = st.columns([3, 2, 2, 2])
            with col_a:
                st.write(f"**{module}**")
                st.caption(f"{mitre.get('tactic','?')} — {mitre.get('id','?')}")
            with col_b:
                if detected:
                    st.markdown(
                        f'<div class="detected-yes">✅ SOC DETECTED</div>',
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f'<div class="detected-no">❌ NOT DETECTED</div>',
                        unsafe_allow_html=True
                    )
            with col_c:
                st.metric("Events", count)
            with col_d:
                st.write(f"MITRE: `{mitre.get('id','N/A')}`")
    else:
        st.info("No simulations run yet. Launch one from the Attack tab first.")

    st.divider()

    # ── CRS Rules Fired ──
    if rules_fired:
        st.subheader("📜 CRS Rules Triggered")
        rules_df = pd.DataFrame([
            {"Rule ID": k, "Hits": v, "Description": {
                "941100": "XSS via libinjection",
                "941110": "XSS Script Tag Vector",
                "941160": "NoScript XSS Checker",
                "942100": "SQL Injection via libinjection",
                "942200": "SQL UNION Attack",
                "930100": "Path Traversal Attack",
                "931100": "Remote File Inclusion",
                "932130": "Log4Shell JNDI Probe",
                "920450": "Shellshock Header",
                "949110": "Inbound Anomaly Score Exceeded",
            }.get(k, "CRS Rule")}
            for k, v in sorted(rules_fired.items(), key=lambda x: -x[1])
        ])
        st.dataframe(rules_df, use_container_width=True, hide_index=True)

    # ── Recent SOC Events ──
    st.divider()
    st.subheader("📡 Recent SOC Events (Live Feed)")
    if soc_events:
        events_data = []
        for hit in soc_events[:20]:
            fields = hit.get("fields", {})
            events_data.append({
                "Timestamp":  fields.get("@timestamp", ["?"])[0][:19].replace("T", " "),
                "Source IP":  fields.get("source.ip", ["?"])[0],
                "URL":        fields.get("url.path", ["?"])[0][:50],
                "Action":     fields.get("event.action", ["?"])[0],
                "HTTP":       fields.get("http.response.status_code", ["?"])[0],
                "Rules":      ", ".join(fields.get("rule.id", [])[:3]),
            })
        df_events = pd.DataFrame(events_data)

        def color_action(val):
            if val == "blocked":
                return "color: #ff6b6b"
            return "color: #69db7c"

        st.dataframe(
            df_events.style.map(color_action, subset=["Action"]),
            use_container_width=True, hide_index=True
        )
    else:
        st.info(f"No SOC events found in last {time_window} minutes. Run a simulation first.")

    # ── Brute Force Log ──
    if brute_events:
        st.divider()
        st.subheader("🔑 Brute Force Attempts (Roundcube Login Log)")
        bf_data = []
        for hit in brute_events[:15]:
            fields = hit.get("fields", {})
            bf_data.append({
                "Timestamp": fields.get("@timestamp", ["?"])[0][:19].replace("T", " "),
                "Username":  fields.get("user.name", ["?"])[0],
                "Source IP": fields.get("source.ip", ["?"])[0],
                "Outcome":   fields.get("event.outcome", ["?"])[0],
            })
        st.dataframe(pd.DataFrame(bf_data), use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════
# TAB 3 — SOC HEALTH SCORE + MITRE HEATMAP
# ══════════════════════════════════════════════
with tab3:
    st.header("📈 SOC Health Score & MITRE ATT&CK Coverage")

    # ── Calculate Score ──
    total_modules   = len(MITRE_MAP)
    detected_modules = 0
    module_statuses  = {}

    for module in MITRE_MAP:
        det, cnt = get_module_detection(module, 60)  # 60 min window for score
        module_statuses[module] = {"detected": det, "count": cnt}
        if det:
            detected_modules += 1

    # Weight: waf_evasion and apt_killchain count more
    weighted_score = 0
    weights = {
        "waf_evasion": 20, "apt_killchain": 20,
        "ssh_bruteforce": 10, "owasp_web": 10,
        "privilege_escalation": 10, "lateral_movement": 5,
        "ransomware_sim": 5, "credential_dumping": 5,
        "data_exfiltration": 5, "supply_chain": 5,
        "network_load_sim": 3, "nmap_scan": 2,
    }
    total_weight = sum(weights.values())
    for module, status in module_statuses.items():
        if status["detected"]:
            weighted_score += weights.get(module, 5)

    health_score = int((weighted_score / total_weight) * 100)

    # Score color
    if health_score >= 75:
        score_color = "#00ff88"
        score_label = "GOOD"
    elif health_score >= 50:
        score_color = "#ffd700"
        score_label = "MODERATE"
    else:
        score_color = "#ff4444"
        score_label = "POOR"

    # ── Score Display ──
    col_score, col_stats = st.columns([1, 2])

    with col_score:
        st.markdown(f"""
        <div style="background:#1e1e2e; border:2px solid {score_color};
                    border-radius:15px; padding:30px; text-align:center;">
            <div style="font-size:80px; font-weight:bold; color:{score_color};">
                {health_score}
            </div>
            <div style="font-size:24px; color:{score_color};">/ 100</div>
            <div style="font-size:18px; color:#aaa; margin-top:10px;">
                SOC Health Score
            </div>
            <div style="font-size:28px; font-weight:bold; color:{score_color};
                        margin-top:5px;">
                {score_label}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_stats:
        st.subheader("Coverage Breakdown")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Modules Detected", f"{detected_modules}/{total_modules}")
        with c2:
            detection_rate = int((detected_modules / total_modules) * 100) if total_modules else 0
            st.metric("Detection Rate", f"{detection_rate}%")
        with c3:
            blind_spots = total_modules - detected_modules
            st.metric("Blind Spots", blind_spots)

        st.divider()

        # Progress bars per tactic
        st.write("**Detection by MITRE Tactic:**")
        tactic_detected = {}
        tactic_total    = {}
        for module, mitre in MITRE_MAP.items():
            tactic = mitre["tactic"]
            tactic_total[tactic]    = tactic_total.get(tactic, 0) + 1
            if module_statuses.get(module, {}).get("detected"):
                tactic_detected[tactic] = tactic_detected.get(tactic, 0) + 1

        for tactic in TACTIC_ORDER:
            if tactic in tactic_total:
                det   = tactic_detected.get(tactic, 0)
                total = tactic_total[tactic]
                pct   = det / total
                st.write(f"`{tactic}` — {det}/{total}")
                st.progress(pct)

    st.divider()

    # ── MITRE ATT&CK Heatmap ──
    st.subheader("🗺️ MITRE ATT&CK Coverage Heatmap")
    st.caption("Green = Detected by SOC | Red = Not detected / Not tested")

    # Build heatmap grid
    cols_per_row = 4
    items        = list(MITRE_MAP.items())

    for i in range(0, len(items), cols_per_row):
        row_items = items[i:i + cols_per_row]
        cols      = st.columns(cols_per_row)
        for j, (module, mitre) in enumerate(row_items):
            status  = module_statuses.get(module, {})
            detected = status.get("detected", False)
            count    = status.get("count", 0)
            bg_color = "#1a3a2a" if detected else "#2a1a1a"
            border   = "#00ff88" if detected else "#ff4444"
            icon     = "✅" if detected else "❌"

            with cols[j]:
                st.markdown(f"""
                <div style="background:{bg_color}; border:2px solid {border};
                            border-radius:8px; padding:12px; margin:4px;
                            min-height:100px;">
                    <div style="font-size:18px;">{icon}</div>
                    <div style="font-size:11px; color:#aaa;">{mitre['id']}</div>
                    <div style="font-size:13px; font-weight:bold;">{module}</div>
                    <div style="font-size:10px; color:#888;">{mitre['tactic']}</div>
                    <div style="font-size:11px; color:#ccc;">Events: {count}</div>
                </div>
                """, unsafe_allow_html=True)

    # ── Coverage Summary Table ──
    st.divider()
    st.subheader("📋 Full Coverage Table")
    coverage_data = []
    for module, mitre in MITRE_MAP.items():
        status = module_statuses.get(module, {})
        coverage_data.append({
            "Module":    module,
            "MITRE ID":  mitre["id"],
            "Tactic":    mitre["tactic"],
            "Technique": mitre["name"],
            "Detected":  "✅ YES" if status.get("detected") else "❌ NO",
            "Events":    status.get("count", 0),
        })

    df_coverage = pd.DataFrame(coverage_data)

    def color_detected(val):
        if "YES" in str(val):
            return "color: #00ff88; font-weight: bold"
        return "color: #ff4444; font-weight: bold"

    st.dataframe(
        df_coverage.style.map(color_detected, subset=["Detected"]),
        use_container_width=True, hide_index=True
    )


# ══════════════════════════════════════════════
# TAB 4 — SIMULATION RESULTS
# ══════════════════════════════════════════════
with tab4:
    st.header("📊 Simulation History & Results")
    try:
        simulations = requests.get(f"{API_BASE_URL}/simulations/", timeout=3).json()
        if isinstance(simulations, dict):
            simulations = simulations.get("simulations",
                         simulations.get("items", list(simulations.values())[0]
                         if simulations else []))

        if simulations and isinstance(simulations, list):
            # Summary table — most recent first
            df_data = []
            for sim in simulations[:50]:
                df_data.append({
                    "ID":           sim.get("id","")[:8],
                    "Name":         sim.get("name",""),
                    "Target":       sim.get("target","")[:40],
                    "Modules":      ", ".join(sim.get("modules", [])),
                    "Status":       sim.get("status","").upper(),
                    "Findings":     sim.get("total_findings", 0),
                    "Duration (s)": round(sim.get("duration_s") or 0, 1),
                    "Started":      (sim.get("started_at","") or "")[:16].replace("T"," "),
                })
            df = pd.DataFrame(df_data)

            def color_status(val):
                if val == "COMPLETED": return "color: #00ff88"
                if val == "RUNNING":   return "color: #ffd700"
                return "color: #ff4444"

            st.dataframe(
                df.style.map(color_status, subset=["Status"]),
                use_container_width=True, hide_index=True
            )

            # Detail view
            st.divider()
            st.subheader("🔬 Detailed Findings")
            sim_ids = [s["id"] for s in simulations[:20]]
            if sim_ids:
                selected_id = st.selectbox("Select Simulation", sim_ids,
                    format_func=lambda x: f"{x[:8]} — {next((s['name'] for s in simulations if s['id']==x), '')}")

                if selected_id:
                    details = requests.get(
                        f"{API_BASE_URL}/results/{selected_id}", timeout=3
                    ).json()

                    for mr in details.get("module_results", []):
                        module_name = mr.get("module","")
                        findings    = mr.get("findings", [])
                        status      = mr.get("status","")
                        duration    = round(mr.get("duration_s") or 0, 1)

                        # SOC detection for this module
                        det, evt_count = get_module_detection(module_name, 60)
                        det_badge = "✅ SOC DETECTED" if det else "❌ NOT DETECTED"
                        det_color = "#00ff88" if det else "#ff4444"

                        with st.expander(
                            f"📦 {module_name} — {len(findings) if isinstance(findings, list) else '?'} findings | {duration}s",
                            expanded=True
                        ):
                            col_m1, col_m2, col_m3 = st.columns(3)
                            with col_m1:
                                st.markdown(f"**Status:** `{status.upper()}`")
                            with col_m2:
                                st.markdown(
                                    f'<span style="color:{det_color}; font-weight:bold;">'
                                    f'{det_badge}</span> ({evt_count} events)',
                                    unsafe_allow_html=True
                                )
                            with col_m3:
                                mitre = MITRE_MAP.get(module_name, {})
                                st.markdown(f"**MITRE:** `{mitre.get('id','N/A')}` — {mitre.get('tactic','?')}")

                            if isinstance(findings, list) and findings:
                                for f in findings:
                                    if not isinstance(f, dict):
                                        continue
                                    sev      = f.get("severity","info").upper()
                                    sev_color = {
                                        "CRITICAL":"#ff4444","HIGH":"#ff8c00",
                                        "MEDIUM":"#ffd700","LOW":"#69db7c","INFO":"#74c0fc"
                                    }.get(sev, "#aaa")
                                    st.markdown(
                                        f'<div style="border-left:3px solid {sev_color}; '
                                        f'padding:8px; margin:4px 0; background:#1a1a2e;">'
                                        f'<span style="color:{sev_color}; font-weight:bold;">[{sev}]</span> '
                                        f'<strong>{f.get("title","")}</strong> '
                                        f'<span style="color:#888;">MITRE: {f.get("mitre_id","N/A")}</span><br>'
                                        f'<span style="color:#ccc; font-size:12px;">{f.get("description","")}</span>'
                                        f'</div>',
                                        unsafe_allow_html=True
                                    )
        else:
            st.info("No simulations found. Launch one from the Attack tab!")
    except Exception as e:
        st.warning(f"Could not load results: {e}")
