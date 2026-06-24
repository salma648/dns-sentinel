import sqlite3
from config import DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def save_event(
    source_ip,
    domain,
    rcode,
    entropy,
    source_type="SIMULATOR",
    detection_time_ms=0
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO dns_events (
            source_ip,
            domain,
            rcode,
            entropy,
            source_type,
            detection_time_ms
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        domain,
        rcode,
        entropy,
        source_type,
        detection_time_ms
    ))

    conn.commit()
    conn.close()


def save_alert(
    source_ip,
    domain,
    rcode,
    entropy,
    alert_type,
    severity,
    detection_time_ms=0
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            source_ip,
            domain,
            rcode,
            entropy,
            alert_type,
            severity,
            detection_time_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        domain,
        rcode,
        entropy,
        alert_type,
        severity,
        detection_time_ms
    ))

    conn.commit()
    conn.close()