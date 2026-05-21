import streamlit as st

# ---------------------------------------------------
# DEMO USERS
# ---------------------------------------------------

USERS = {

    "admin": {
        "password": "admin123",
        "role": "Administrator"
    },

    "operator": {
        "password": "operator123",
        "role": "SOC Operator"
    },

    "analyst": {
        "password": "analyst123",
        "role": "Security Analyst"
    }
}

# ---------------------------------------------------
# LOGIN
# ---------------------------------------------------

def login(username, password):

    user = USERS.get(username)

    if not user:
        return False

    if user["password"] != password:
        return False

    st.session_state.authenticated = True
    st.session_state.username = username
    st.session_state.role = user["role"]

    return True

# ---------------------------------------------------
# LOGOUT
# ---------------------------------------------------

def logout():

    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None

# ---------------------------------------------------
# CHECK AUTH
# ---------------------------------------------------

def is_authenticated():

    return st.session_state.get(
        "authenticated",
        False
    )

# ---------------------------------------------------
# CURRENT ROLE
# ---------------------------------------------------

def current_role():

    return st.session_state.get(
        "role",
        "Unknown"
    )