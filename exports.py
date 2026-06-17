import sqlite3
import csv
import json

from config import DB_PATH


def export_csv(cursor):
    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
    """)

    rows = cursor.fetchall()

    with open(
        "exports/alerts.csv",
        "w",
        newline=""
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "id",
            "timestamp",
            "source_ip",
            "domain",
            "alert_type",
            "severity"
        ])

        writer.writerows(rows)

    print("[OK] CSV exported")


def export_json(cursor):
    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
    """)

    rows = cursor.fetchall()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "domain": row[3],
            "alert_type": row[4],
            "severity": row[5]
        })

    with open(
        "exports/alerts.json",
        "w"
    ) as jsonfile:

        json.dump(
            alerts,
            jsonfile,
            indent=4
        )

    print("[OK] JSON exported")


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    export_csv(cursor)
    export_json(cursor)

    conn.close()


if __name__ == "__main__":
    main()