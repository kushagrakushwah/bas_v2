import random
import streamlit as st

# ---------------------------------------------------
# MOCK INFRASTRUCTURE STATUS
# ---------------------------------------------------

@st.cache_data(ttl=5)
def get_infrastructure_status():

    return {

        "services": [

            {
                "name": "BAS Engine",
                "status": "running",
                "cpu": random.randint(10, 60),
                "memory": random.randint(20, 70)
            },

            {
                "name": "Dashboard",
                "status": "running",
                "cpu": random.randint(5, 30),
                "memory": random.randint(10, 40)
            },

            {
                "name": "Elasticsearch",
                "status": "running",
                "cpu": random.randint(20, 80),
                "memory": random.randint(40, 90)
            },

            {
                "name": "Kibana",
                "status": "running",
                "cpu": random.randint(10, 40),
                "memory": random.randint(20, 60)
            },

            {
                "name": "Logstash",
                "status": "running",
                "cpu": random.randint(10, 50),
                "memory": random.randint(20, 70)
            }
        ],

        "cluster": {

            "nodes": 3,
            "pods": random.randint(12, 22),
            "healthy_pods": random.randint(10, 20),
            "cpu_usage": random.randint(20, 75),
            "memory_usage": random.randint(30, 85)
        }
    }