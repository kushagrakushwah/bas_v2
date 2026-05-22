import os
import json
import smtplib
import requests

from email.mime.text import MIMEText

# ---------------------------------------------------
# SLACK ALERT
# ---------------------------------------------------

def send_slack_alert(message):

    webhook = os.getenv(
        "SLACK_WEBHOOK_URL"
    )

    if not webhook:
        return False

    payload = {

        "text": message
    }

    try:

        requests.post(
            webhook,
            json=payload,
            timeout=5
        )

        return True

    except Exception:

        return False

# ---------------------------------------------------
# EMAIL ALERT
# ---------------------------------------------------

def send_email_alert(subject, body):

    smtp_server = os.getenv(
        "SMTP_SERVER"
    )

    smtp_port = int(
        os.getenv(
            "SMTP_PORT",
            587
        )
    )

    smtp_user = os.getenv(
        "SMTP_USER"
    )

    smtp_pass = os.getenv(
        "SMTP_PASS"
    )

    recipient = os.getenv(
        "ALERT_EMAIL"
    )

    if not all([
        smtp_server,
        smtp_user,
        smtp_pass,
        recipient
    ]):

        return False

    try:

        msg = MIMEText(body)

        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = recipient

        server = smtplib.SMTP(
            smtp_server,
            smtp_port
        )

        server.starttls()

        server.login(
            smtp_user,
            smtp_pass
        )

        server.sendmail(
            smtp_user,
            [recipient],
            msg.as_string()
        )

        server.quit()

        return True

    except Exception:

        return False

# ---------------------------------------------------
# MAIN ALERT PIPELINE
# ---------------------------------------------------

def process_alert(event):

    event_type = event.get(
        "type",
        ""
    )

    payload = event.get(
        "payload",
        {}
    )

    # Only alert on high-value events
    interesting = [

        "vulnerability.found",
        "simulation.failed",
        "module.completed"
    ]

    if event_type not in interesting:
        return

    message = f"""
🚨 SecureForge Alert

Event:
{event_type}

Payload:
{json.dumps(payload, indent=2)}
"""

    # Slack
    send_slack_alert(
        message
    )

    # Email
    send_email_alert(
        f"SecureForge Alert: {event_type}",
        message
    )