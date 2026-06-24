from flask import Flask, render_template, redirect, url_for, request, send_file
import sqlite3
import threading
import time
import os
import config
import threading

from config import DB_PATH
from engine import generate_traffic, process_dns_event
from exports import main as run_exports
from blocker import unblock_ip 
from pdf_report import generate_pdf_report
from detector import get_root_domain 
from powerdns_import import import_powerdns_log
from powerdns_stats import get_powerdns_stats
from powerdns_live_monitor import start_powerdns_monitor

app = Flask(__name__)

simulation_running = False
simulation_thread = None
simulation_lock = threading.Lock()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def get_stats():
    conn = get_db_connection()
    import os

    total_events = conn.execute(
        "SELECT COUNT(*) FROM dns_events"
    ).fetchone()[0]

    total_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    critical_alerts = conn.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'critical'
    """).fetchone()[0]
    water_torture_count = conn.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE alert_type = 'WATER_TORTURE'
    """).fetchone()[0]

    blocked_ips = 0

    try:
        with open(config.BLOCKLIST_FILE, "r") as f:
            blocked_ips = len([
                line.strip()
                for line in f
                if line.strip()
            ])
    except:
        pass

    noerror_events = conn.execute("""
        SELECT COUNT(*)
        FROM dns_events
        WHERE rcode = 'NOERROR'
    """).fetchone()[0]

    powerdns_events = conn.execute("""
        SELECT COUNT(*)
        FROM dns_events
        WHERE source_type = 'POWERDNS'
    """).fetchone()[0]

    simulator_events = conn.execute("""
        SELECT COUNT(*)
        FROM dns_events
        WHERE source_type = 'SIMULATOR'
    """).fetchone()[0]

    success_rate = 0
    alert_rate = 0

    if total_events > 0:
        success_rate = round((noerror_events / total_events) * 100, 2)
        alert_rate = round((total_alerts / total_events) * 100, 2)

    alert_types = conn.execute("""
        SELECT alert_type, COUNT(*)
        FROM alerts
        GROUP BY alert_type
        ORDER BY COUNT(*) DESC
    """).fetchall()

    top_ips = conn.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM alerts
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return {
        "events": total_events,
        "alerts": total_alerts,
        "critical": critical_alerts,
        "noerror_events": noerror_events,
        "success_rate": success_rate,
        "alert_rate": alert_rate,
        "powerdns_events": powerdns_events,
        "simulator_events": simulator_events,
        "alert_types": alert_types,
        "top_ips": top_ips,
        "simulation_running": simulation_running,
        "water_torture_count": water_torture_count,
        "blocked_ips": blocked_ips
    }


def get_recent_dns_events():
    conn = get_db_connection()

    events = conn.execute("""
        SELECT *
        FROM dns_events
        ORDER BY timestamp DESC
        LIMIT 50
    """).fetchall()

    conn.close()
    return events


def get_recent_alerts(severity=None, alert_type=None, search=None):
    conn = get_db_connection()

    query = """
        SELECT *
        FROM alerts
        WHERE 1=1
    """

    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if alert_type:
        query += " AND alert_type = ?"
        params.append(alert_type)

    if search:
        query += " AND (source_ip LIKE ? OR domain LIKE ?)"
        params.append(f"%{search}%")
        params.append(f"%{search}%")

    query += """
        ORDER BY timestamp DESC
        LIMIT 100
    """

    alerts = conn.execute(query, params).fetchall()

    conn.close()

    return alerts
def get_distinct_alert_types():
    conn = get_db_connection()

    results = conn.execute("""
        SELECT DISTINCT alert_type
        FROM alerts
        ORDER BY alert_type
    """).fetchall()

    conn.close()

    return results


def get_distinct_severities():
    conn = get_db_connection()

    results = conn.execute("""
        SELECT DISTINCT severity
        FROM alerts
        ORDER BY severity
    """).fetchall()

    conn.close()

    return results


def get_alerts_by_severity():
    conn = get_db_connection()

    results = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
        ORDER BY count DESC
    """).fetchall()

    conn.close()
    return results


def get_top_suspicious_ips():
    conn = get_db_connection()

    results = conn.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM alerts
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    conn.close()
    return results


def get_top_domains():
    conn = get_db_connection()

    results = conn.execute("""
        SELECT domain, COUNT(*) as count
        FROM alerts
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    conn.close()
    return results


def get_blocked_ips():
    try:
        with open(config.BLOCKLIST_FILE, "r") as file:
            return [
                line.strip()
                for line in file
                if line.strip()
            ]
    except FileNotFoundError:
        return []


def get_reports_status():
    csv_path = "exports/alerts.csv"
    json_path = "exports/alerts.json"
    pdf_path = "exports/soc_report.pdf"
    return {
        "csv_exists": os.path.exists(csv_path),
        "json_exists": os.path.exists(json_path),
        "csv_path": csv_path,
        "json_path": json_path,
        "pdf_exists": os.path.exists(pdf_path),
        "pdf_path": pdf_path
    }


def get_settings():
    return {
        "DB_PATH": config.DB_PATH,
        "ENTROPY_THRESHOLD": config.ENTROPY_THRESHOLD,
        "NXDOMAIN_BURST_THRESHOLD": config.NXDOMAIN_BURST_THRESHOLD,
        "NXDOMAIN_BURST_WINDOW": config.NXDOMAIN_BURST_WINDOW,
        "DNS_TUNNELING_LENGTH_THRESHOLD": config.DNS_TUNNELING_LENGTH_THRESHOLD,
        "DNS_TUNNELING_ENTROPY_THRESHOLD": config.DNS_TUNNELING_ENTROPY_THRESHOLD,
        "WATER_TORTURE_THRESHOLD": config.WATER_TORTURE_THRESHOLD,
        "WATER_TORTURE_WINDOW": config.WATER_TORTURE_WINDOW,
        "WATER_TORTURE_ENTROPY_RATIO": config.WATER_TORTURE_ENTROPY_RATIO,
        "WATER_TORTURE_IP_THRESHOLD": config.WATER_TORTURE_IP_THRESHOLD,
        "AUTO_BLOCK_SCORE_THRESHOLD": config.AUTO_BLOCK_SCORE_THRESHOLD,
        "LOG_FILE": config.LOG_FILE,
        "BLOCKLIST_FILE": config.BLOCKLIST_FILE
    }


def reset_demo_data():
    conn = get_db_connection()

    conn.execute("DELETE FROM dns_events")
    conn.execute("DELETE FROM alerts")

    conn.commit()
    conn.close()


def simulation_loop():
    global simulation_running

    while True:
        with simulation_lock:
            if not simulation_running:
                break

        process_dns_event()
        time.sleep(1)

def get_alert_by_id(alert_id):
    conn = get_db_connection()

    alert = conn.execute("""
        SELECT *
        FROM alerts
        WHERE id = ?
    """, (alert_id,)).fetchone()

    conn.close()
    return alert

def get_system_health():

    conn = get_db_connection()
    powerdns_monitor = get_powerdns_monitor_status()
    last_alert = conn.execute("""
        SELECT timestamp
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 1
    """).fetchone()

    conn.close()

    blocked_count = len(get_blocked_ips())

    return {
        "database_status": "Online",
        "powerdns_monitor": powerdns_monitor,
        "simulation_status": (
            "Running"
            if simulation_running
            else "Stopped"
        ),
        "blocked_ips": blocked_count,
        "last_alert": (
            last_alert["timestamp"]
            if last_alert
            else "No alerts"
        )
    }
def get_threat_intelligence():

    conn = get_db_connection()

    top_attack = conn.execute("""
        SELECT alert_type, COUNT(*) as count
        FROM alerts
        WHERE alert_type IN (
            'WATER_TORTURE',
            'DNS_TUNNELING_SUSPECT'
        )
        GROUP BY alert_type
        ORDER BY count DESC
        LIMIT 1
    """).fetchone()

    domains = conn.execute("""
        SELECT domain
        FROM alerts
    """).fetchall()

    root_domain_counts = {}

    for row in domains:
        domain = row["domain"]
        root_domain = get_root_domain(domain)

        root_domain_counts[root_domain] = (
            root_domain_counts.get(root_domain, 0) + 1
        )

    if root_domain_counts:
        top_domain = max(
            root_domain_counts.items(),
            key=lambda item: item[1]
        )[0]
    else:
        top_domain = "N/A"

    domains = conn.execute("""
        SELECT domain
        FROM alerts
    """).fetchall()

    root_domain_counts = {}

    for row in domains:
        root_domain = get_root_domain(row["domain"])
        root_domain_counts[root_domain] = (
            root_domain_counts.get(root_domain, 0) + 1
        )

    top_domains = sorted(
        root_domain_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:3]
    return {
        "top_attack": top_attack[0] if top_attack else "N/A",
        "top_domain": top_domain,
        "top_domains": top_domains,
        "traffic_source": "Simulator + PowerDNS"
    }  
  
def get_recent_activity(limit=10):

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT timestamp,
               source_ip,
               alert_type,
               severity
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()

    return rows


def explain_alert(alert_type):
    explanations = {
        "WATER_TORTURE": {
            "meaning": "Possible DNS Water Torture attack detected.",
            "reason": "The system observed multiple suspicious NXDOMAIN queries using random-looking subdomains targeting the same root domain.",
            "action": "Investigate the source IPs, verify the targeted domain, and consider keeping the IP in the logical blocklist."
        },
        "DNS_TUNNELING_SUSPECT": {
            "meaning": "Possible DNS tunneling activity detected.",
            "reason": "The queried domain contains a very long and high-entropy label, which may indicate encoded data inside DNS queries.",
            "action": "Inspect the source host and check whether DNS is being used as a covert communication channel."
        },
        "DGA_SUSPECT": {
            "meaning": "Possible domain generation algorithm activity detected.",
            "reason": "The domain contains suspicious patterns such as many digits or very few vowels, which can indicate algorithmically generated domains.",
            "action": "Investigate the host for malware or botnet activity."
        },
        "NXDOMAIN_BURST": {
            "meaning": "Burst of failed DNS lookups detected.",
            "reason": "The same source IP generated many NXDOMAIN responses in a short time window.",
            "action": "Check whether the host is infected, misconfigured, or scanning/generated domains."
        },
        "HIGH_ENTROPY_DOMAIN": {
            "meaning": "Suspicious high-entropy domain detected.",
            "reason": "The queried domain appears random or encoded based on its entropy score.",
            "action": "Review the domain and correlate with other alerts from the same source IP."
        },
        "NXDOMAIN_DETECTED": {
            "meaning": "Failed DNS lookup detected.",
            "reason": "The queried domain does not exist.",
            "action": "Monitor this source IP if repeated NXDOMAIN responses appear."
        }
    }

    return explanations.get(alert_type, {
        "meaning": "Unknown alert type.",
        "reason": "No explanation is currently available for this alert.",
        "action": "Review the event manually."
    })

def get_response_time_stats():
    conn = get_db_connection()

    stats = conn.execute("""
        SELECT
            ROUND(AVG(response_time_ms), 2) as avg_time,
            ROUND(MAX(response_time_ms), 2) as max_time,
            ROUND(MIN(response_time_ms), 2) as min_time
        FROM dns_response_metrics
    """).fetchone()

    last = conn.execute("""
        SELECT response_time_ms
        FROM dns_response_metrics
        ORDER BY timestamp DESC
        LIMIT 1
    """).fetchone()

    conn.close()

    return {
        "avg_time": stats["avg_time"] if stats["avg_time"] else 0,
        "max_time": stats["max_time"] if stats["max_time"] else 0,
        "min_time": stats["min_time"] if stats["min_time"] else 0,
        "last_time": last["response_time_ms"] if last else 0
    }
def get_detection_time_stats():
    conn = get_db_connection()

    stats = conn.execute("""
        SELECT
            ROUND(AVG(detection_time_ms), 4) as avg_time
        FROM alerts
        WHERE detection_time_ms > 0
    """).fetchone()

    conn.close()

    return {
        "avg_time": stats["avg_time"] if stats["avg_time"] else 0
    }


def get_powerdns_monitor_status():

    if os.path.exists("powerdns_monitor.status"):
        return "RUNNING"

    return "STOPPED"
@app.route("/")
def dashboard():

    stats = get_stats()
    health = get_system_health()
    intel = get_threat_intelligence()
    recent_activity = get_recent_activity()
    response_stats = get_response_time_stats()
    detection_stats = get_detection_time_stats()

    return render_template(
        "dashboard.html",
        stats=stats,
        health=health,
        intel=intel,
        recent_activity=recent_activity,
        response_stats=response_stats,
        detection_stats=detection_stats
    )

@app.route("/events")
def events():
    dns_events = get_recent_dns_events()

    return render_template(
        "events.html",
        dns_events=dns_events
    )


@app.route("/alerts")
def alerts():
    severity = request.args.get("severity")
    alert_type = request.args.get("alert_type")
    search = request.args.get("search")

    alerts_data = get_recent_alerts(
        severity=severity,
        alert_type=alert_type,
        search=search
    )

    alert_types = get_distinct_alert_types()
    severities = get_distinct_severities()

    return render_template(
        "alerts.html",
        alerts=alerts_data,
        alert_types=alert_types,
        severities=severities,
        selected_severity=severity,
        selected_alert_type=alert_type,
        search=search
    )

@app.route("/analytics")
def analytics():
    stats = get_stats()
    severities = get_alerts_by_severity()
    top_ips = get_top_suspicious_ips()
    top_domains = get_top_domains()

    return render_template(
        "analytics.html",
        stats=stats,
        severities=severities,
        top_ips=top_ips,
        top_domains=top_domains
    )


@app.route("/blocklist")
def blocklist():
    blocked_ips = get_blocked_ips()

    return render_template(
        "blocklist.html",
        blocked_ips=blocked_ips
    )


@app.route("/reports")
def reports():
    stats = get_stats()
    reports_status = get_reports_status()

    return render_template(
        "reports.html",
        stats=stats,
        reports_status=reports_status
    )


@app.route("/settings")
def settings():
    settings_data = get_settings()

    return render_template(
        "settings.html",
        settings=settings_data
    )


@app.route("/generate-traffic", methods=["POST"])
def generate_dns_traffic():
    generate_traffic(batch_size=10)
    return redirect(url_for("dashboard"))


@app.route("/generate-reports", methods=["POST"])
def generate_reports():
    os.makedirs("exports", exist_ok=True)
    run_exports()
    return redirect(url_for("reports"))


@app.route("/start-simulation", methods=["POST"])
def start_simulation():
    global simulation_running, simulation_thread

    with simulation_lock:
        if not simulation_running:
            simulation_running = True

            simulation_thread = threading.Thread(
                target=simulation_loop,
                daemon=True
            )

            simulation_thread.start()

    return redirect(url_for("dashboard"))


@app.route("/stop-simulation", methods=["POST"])
def stop_simulation():
    global simulation_running

    with simulation_lock:
        simulation_running = False

    return redirect(url_for("dashboard"))


@app.route("/reset-demo", methods=["POST"])
def reset_demo():
    global simulation_running

    with simulation_lock:
        simulation_running = False

    reset_demo_data()

    return redirect(url_for("dashboard"))

@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id):
    alert = get_alert_by_id(alert_id)

    if alert is None:
        return "Alert not found", 404
    explanation = explain_alert(alert["alert_type"])

    return render_template(
        "alert_detail.html",
        alert=alert,
        explanation=explanation
    )

@app.route("/unblock/<ip>", methods=["POST"])
def unblock(ip):

    unblock_ip(ip)

    return redirect(url_for("blocklist"))

@app.route("/generate-pdf-report", methods=["POST"])
def generate_pdf():
    generate_pdf_report()
    return redirect(url_for("reports"))

@app.route("/download-pdf")
def download_pdf():

    pdf_path = "exports/soc_report.pdf"

    if not os.path.exists(pdf_path):
        return "PDF report not generated yet", 404

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="DNS_Sentinel_SOC_Report.pdf"
    )
@app.route("/import-powerdns-logs", methods=["POST"])
def import_powerdns_logs():
    import_powerdns_log("powerdns.log")
    return redirect(url_for("reports"))

if __name__ == "__main__":

    monitor_thread = threading.Thread(
        target=start_powerdns_monitor,
        daemon=True
    )

    monitor_thread.start()

    app.run(
        debug=True,
        use_reloader=False
    )