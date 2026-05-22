import schedule
import threading
import time

# ---------------------------------------------------
# REPORT JOBS
# ---------------------------------------------------

jobs = []

# ---------------------------------------------------
# START SCHEDULER
# ---------------------------------------------------

def start_scheduler():

    thread = threading.Thread(
        target=run_scheduler,
        daemon=True
    )

    thread.start()

# ---------------------------------------------------
# LOOP
# ---------------------------------------------------

def run_scheduler():

    while True:

        schedule.run_pending()

        time.sleep(1)

# ---------------------------------------------------
# REGISTER DAILY REPORT
# ---------------------------------------------------

def register_daily_report(callback):

    job = schedule.every().day.at(
        "09:00"
    ).do(callback)

    jobs.append(job)

# ---------------------------------------------------
# REGISTER HOURLY REPORT
# ---------------------------------------------------

def register_hourly_report(callback):

    job = schedule.every().hour.do(
        callback
    )

    jobs.append(job)