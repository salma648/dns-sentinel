import sqlite3
import config
import smtplib
import time

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

last_email_sent = {}
EMAIL_COOLDOWN_SECONDS = 300


def can_send_email(alert_type, domain):
    key = f"{alert_type}:{domain}"
    current_time = time.time()

    last_time = last_email_sent.get(key, 0)

    if current_time - last_time >= EMAIL_COOLDOWN_SECONDS:
        last_email_sent[key] = current_time
        return True

    return False

def save_notification(
    alert_type,
    severity,
    source_ip,
    domain,
    channel,
    status,
    message
):
    conn = sqlite3.connect(config.DB_PATH)

    conn.execute("""
        INSERT INTO notifications (
            alert_type,
            severity,
            source_ip,
            domain,
            channel,
            status,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_type,
        severity,
        source_ip,
        domain,
        channel,
        status,
        message
    ))

    conn.commit()
    conn.close()

def send_email_notification(
    alert_type,
    severity,
    source_ip,
    domain
):
    if not config.EMAIL_ENABLED:
        return

    try:
        message = MIMEMultipart()

        message["From"] = config.EMAIL_SENDER
        message["To"] = config.EMAIL_RECEIVER
        message["Subject"] = (
            f"[DNS Sentinel] {alert_type} detected"
        )

        body = f"""
DNS Sentinel Alert

Attack Type : {alert_type}
Severity    : {severity}
Source IP   : {source_ip}
Domain      : {domain}

Immediate investigation is recommended.
"""

        message.attach(
            MIMEText(body, "plain")
        )

        server = smtplib.SMTP(
            config.SMTP_SERVER,
            config.SMTP_PORT
        )

        server.starttls()

        server.login(
            config.EMAIL_SENDER,
            config.EMAIL_PASSWORD
        )

        server.sendmail(
            config.EMAIL_SENDER,
            config.EMAIL_RECEIVER,
            message.as_string()
        )

        server.quit()

        print("Email notification sent.")

    except Exception as e:
        print("Email notification failed:", e)

def get_alert_receiver():
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT value
        FROM app_settings
        WHERE key = 'alert_email'
    """)

    row = cursor.fetchone()
    conn.close()

    if row and row[0]:
        return row[0]

    return config.EMAIL_RECEIVER