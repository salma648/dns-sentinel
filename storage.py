import sqlite3
from config import DB_PATH


def save_event(source_ip, domain, rcode, entropy):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO dns_events (source_ip, domain, rcode, entropy)
        VALUES (?, ?, ?, ?)
    """, (source_ip, domain, rcode, entropy))

    conn.commit()
    conn.close()


def save_alert(source_ip, domain, rcode, entropy, alert_type, severity):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (source_ip, domain, rcode, entropy, alert_type, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (source_ip, domain, rcode, entropy, alert_type, severity))

    conn.commit()
    conn.close()
