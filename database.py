import sqlite3
from config import DB_PATH


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()

    for column in columns:
        if column[1] == column_name:
            return True

    return False


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            domain TEXT,
            rcode TEXT,
            entropy REAL,
            source_type TEXT DEFAULT 'SIMULATOR',
            detection_time_ms REAL DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            domain TEXT,
            rcode TEXT,
            entropy REAL,
            alert_type TEXT,
            severity TEXT,
            detection_time_ms REAL DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    if not column_exists(cursor, "dns_events", "source_type"):
        cursor.execute("""
            ALTER TABLE dns_events
            ADD COLUMN source_type TEXT DEFAULT 'SIMULATOR'
        """)

    if not column_exists(cursor, "dns_events", "detection_time_ms"):
        cursor.execute("""
            ALTER TABLE dns_events
            ADD COLUMN detection_time_ms REAL DEFAULT 0
        """)

    if not column_exists(cursor, "alerts", "detection_time_ms"):
        cursor.execute("""
            ALTER TABLE alerts
            ADD COLUMN detection_time_ms REAL DEFAULT 0
        """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            source_ip TEXT,
            domain TEXT,
            channel TEXT,
            status TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO app_settings (key, value)
        VALUES ('admin_username', 'admin')
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO app_settings (key, value)
        VALUES ('admin_password', 'admin123')
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO app_settings (key, value)
        VALUES ('alert_email', '')
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()