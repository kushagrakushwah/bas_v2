import streamlit as st

from auth.auth_manager import (
    login
)

# ---------------------------------------------------
# LOGIN PAGE
# ---------------------------------------------------

def render_login_page():

    st.title("🔐 SecureForge Login")

    st.caption(
        "Enterprise BAS Authentication"
    )

    st.markdown("---")

    username = st.text_input(
        "Username"
    )

    password = st.text_input(
        "Password",
        type="password"
    )

    if st.button(
        "Login",
        use_container_width=True
    ):

        success = login(
            username,
            password
        )

        if success:

            st.success(
                "Authentication successful."
            )

            st.rerun()

        else:

            st.error(
                "Invalid credentials."
            )

    st.markdown("---")

    st.subheader(
        "Demo Credentials"
    )

    st.code(
        """
admin / admin123
operator / operator123
analyst / analyst123
"""
    )