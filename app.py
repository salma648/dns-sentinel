from flask import Flask, render_template
import sqlite3

from config import DB_PATH

app = Flask(__name__)


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM dns_events"
    )
    total_events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )
    total_alerts = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity='critical'
    """)
    critical_alerts = cursor.fetchone()[0]

    conn.close()

    return {
        "events": total_events,
        "alerts": total_alerts,
        "critical": critical_alerts
    }


@app.route("/")
def home():

    stats = get_stats()

    return render_template(
        "dashboard.html",
        stats=stats
    )


if __name__ == "__main__":
    app.run(debug=True)