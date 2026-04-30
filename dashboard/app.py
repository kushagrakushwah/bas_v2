import streamlit as st
import requests
import pandas as pd
import os
import time

# Point to the BAS Engine in Kubernetes (or localhost if running directly)
API_BASE_URL = os.getenv("API_URL", "http://bas-engine.secureforge.svc.cluster.local:8000/api/v1")

st.set_page_config(page_title="SecureForge BAS", page_icon="🛡️", layout="wide")

st.title("🛡️ SecureForge Attack Orchestrator")
st.markdown("Monitor and trigger Breach & Attack Simulations across your containerized infrastructure.")

# --- Sidebar: System Health & Stats ---
with st.sidebar:
    st.header("System Status")
    try:
        health = requests.get(f"{API_BASE_URL}/").json()
        st.success(f"Backend Status: {health.get('status', 'Unknown').upper()}")
    except Exception:
        st.error("Backend Disconnected")
    
    st.divider()
    st.header("Simulation Summary")
    try:
        summary = requests.get(f"{API_BASE_URL}/simulations/summary").json()
        st.metric("Total Simulations", summary.get("total", 0))
        st.metric("Completed", summary.get("completed", 0))
        st.metric("Running", summary.get("running", 0))
    except Exception:
        st.write("Awaiting data...")

# --- Main Dashboard ---
tab1, tab2 = st.tabs(["🚀 Launch Attack", "📊 Simulation Results"])

with tab1:
    st.subheader("Configure New Simulation")
    
    # Fetch available modules dynamically
    try:
        modules_data = requests.get(f"{API_BASE_URL}/modules/").json()
        available_modules = [m["id"] for m in modules_data]
    except Exception:
        available_modules = ["owasp_web", "ssh_bruteforce", "privilege_escalation"]

    with st.form("launch_form"):
        col1, col2 = st.columns(2)
        with col1:
            sim_name = st.text_input("Simulation Name", "Nightly Baseline Scan")
            target_host = st.text_input("Target URL/IP", "http://example.com")
        with col2:
            selected_modules = st.multiselect("Select Attack Modules", available_modules, default=available_modules[:1])
            is_parallel = st.checkbox("Run Modules in Parallel", value=True)
            live_mode = st.checkbox("⚠️ LIVE MODE (Exploit)", value=False, help="Uncheck for safe predictive simulation")

        submitted = st.form_submit_button("Launch Simulation")
        
        if submitted:
            if not selected_modules:
                st.warning("Please select at least one module.")
            else:
                payload = {
                    "name": sim_name,
                    "target": target_host,
                    "modules": selected_modules,
                    "parallel": is_parallel,
                    "options": {"live_mode": live_mode}
                }
                with st.spinner("Dispatching to Orchestrator..."):
                    res = requests.post(f"{API_BASE_URL}/simulations/", json=payload)
                    if res.status_code == 200:
                        st.success(f"Simulation '{sim_name}' launched successfully!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Failed to launch: {res.text}")

with tab2:
    st.subheader("Historical & Active Simulations")
    try:
        simulations = requests.get(f"{API_BASE_URL}/simulations/").json()
        if simulations:
            # Flatten data for a nice table
            df_data = []
            for sim in simulations:
                df_data.append({
                    "ID": sim["id"][:8],
                    "Name": sim["name"],
                    "Target": sim["target"],
                    "Status": sim["status"].upper(),
                    "Findings": sim.get("total_findings", 0),
                    "Duration (s)": round(sim.get("duration_s", 0) or 0, 2)
                })
            df = pd.DataFrame(df_data)
            
            # Color code status
            def color_status(val):
                color = 'green' if val == 'COMPLETED' else 'orange' if val == 'RUNNING' else 'red'
                return f'color: {color}'
            
            st.dataframe(df.style.map(color_status, subset=['Status']), use_container_width=True)
            
            # Detailed view expander
            st.markdown("### View Details")
            selected_sim_id = st.selectbox("Select Simulation ID to view findings", [s["id"] for s in simulations])
            if selected_sim_id:
                details = requests.get(f"{API_BASE_URL}/results/{selected_sim_id}").json()
                for mod_result in details.get("module_results", []):
                    with st.expander(f"Module: {mod_result['module']} ({len(mod_result['findings'])} findings)"):
                        for f in mod_result["findings"]:
                            st.markdown(f"**[{f['severity'].upper()}] {f['title']}** (MITRE: {f.get('mitre_id', 'N/A')})")
                            st.caption(f.get("description", ""))
        else:
            st.info("No simulations found. Launch one from the other tab!")
    except Exception:
        st.warning("Could not connect to API to fetch results.")