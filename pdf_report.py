import os
import sqlite3
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from config import DB_PATH


PDF_PATH = "exports/soc_report.pdf"


def fetch_count(cursor, query):
    cursor.execute(query)
    return cursor.fetchone()[0]


def generate_pdf_report():
    os.makedirs("exports", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    total_events = fetch_count(cursor, "SELECT COUNT(*) FROM dns_events")
    total_alerts = fetch_count(cursor, "SELECT COUNT(*) FROM alerts")
    critical_alerts = fetch_count(
        cursor,
        "SELECT COUNT(*) FROM alerts WHERE severity = 'critical'"
    )

    c = canvas.Canvas(PDF_PATH, pagesize=A4)
    width, height = A4

    y = height - 50

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "DNS Sentinel - SOC Report")

    y -= 30
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Executive Summary")

    y -= 25
    c.setFont("Helvetica", 11)
    c.drawString(70, y, f"Total DNS Events: {total_events}")

    y -= 20
    c.drawString(70, y, f"Total Alerts: {total_alerts}")

    y -= 20
    c.drawString(70, y, f"Critical Alerts: {critical_alerts}")

    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Alerts by Type")

    y -= 25
    c.setFont("Helvetica", 10)

    cursor.execute("""
        SELECT alert_type, COUNT(*)
        FROM alerts
        GROUP BY alert_type
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """)

    for alert_type, count in cursor.fetchall():
        c.drawString(70, y, f"{alert_type}: {count}")
        y -= 18

    y -= 25
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Top Suspicious IPs")

    y -= 25
    c.setFont("Helvetica", 10)

    cursor.execute("""
        SELECT source_ip, COUNT(*)
        FROM alerts
        GROUP BY source_ip
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """)

    for source_ip, count in cursor.fetchall():
        c.drawString(70, y, f"{source_ip}: {count} alerts")
        y -= 18

    y -= 25
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Recent Critical Alerts")

    y -= 25
    c.setFont("Helvetica", 9)

    cursor.execute("""
        SELECT timestamp, source_ip, alert_type, domain
        FROM alerts
        WHERE severity = 'critical'
        ORDER BY timestamp DESC
        LIMIT 8
    """)

    for timestamp, source_ip, alert_type, domain in cursor.fetchall():
        if y < 60:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)

        line = f"{timestamp} | {source_ip} | {alert_type} | {domain}"
        c.drawString(50, y, line[:110])
        y -= 16

    conn.close()

    c.save()

    return PDF_PATH