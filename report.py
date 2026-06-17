import sqlite3
from config import DB_PATH, AUTO_BLOCK_SCORE_THRESHOLD, BLOCKLIST_FILE


def fetch_one(cursor, query):
    cursor.execute(query)
    result = cursor.fetchone()
    return result[0] if result else 0


def print_section(title):
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)


def get_root_domain(domain):
    parts = domain.split(".")

    simple_tlds = {"com", "org", "net", "io", "us", "fr"}

    if len(parts) >= 2 and parts[-1] in simple_tlds:
        return ".".join(parts[-2:])

    if len(parts) >= 3:
        return ".".join(parts[-3:])

    return domain


def severity_score(severity):
    scores = {
        "critical": 10,
        "high": 5,
        "medium": 2
    }

    return scores.get(severity, 0)

def generate_blocklist(ip_scores):
    blocked_ips = [
        ip
        for ip, score in ip_scores.items()
        if score >= AUTO_BLOCK_SCORE_THRESHOLD
    ]

    with open(BLOCKLIST_FILE, "w") as file:
        for ip in blocked_ips:
            file.write(ip + "\n")

    return blocked_ips

def show_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    total_events = fetch_one(cursor, "SELECT COUNT(*) FROM dns_events")
    total_alerts = fetch_one(cursor, "SELECT COUNT(*) FROM alerts")

    print_section("DNS SENTINEL SOC REPORT")

    print("Total DNS events :", total_events)
    print("Total alerts     :", total_alerts)

    print_section("ALERTS BY TYPE")

    cursor.execute("""
        SELECT alert_type, COUNT(*)
        FROM alerts
        GROUP BY alert_type
        ORDER BY COUNT(*) DESC
    """)

    for alert_type, count in cursor.fetchall():
        print(f"{alert_type:30} {count}")

    print_section("ALERTS BY SEVERITY")

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM alerts
        GROUP BY severity
        ORDER BY COUNT(*) DESC
    """)

    for severity, count in cursor.fetchall():
        print(f"{severity:10} {count}")
        
    print_section("TOP ATTACK TYPES")

    cursor.execute("""
        SELECT alert_type, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type
        ORDER BY count DESC
        LIMIT 5
    """)

    for alert_type, count in cursor.fetchall():
        print(f"{alert_type:30} {count}")   

    print_section("TOP SUSPICIOUS IPS")

    cursor.execute("""
        SELECT source_ip, COUNT(*)
        FROM alerts
        GROUP BY source_ip
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """)

    for source_ip, count in cursor.fetchall():
        print(f"{source_ip:20} {count}")

    print_section("TOP TARGETED ROOT DOMAINS")

    cursor.execute("""
        SELECT domain
        FROM alerts
    """)

    domains = {}

    for (domain,) in cursor.fetchall():
        root = get_root_domain(domain)

        domains[root] = domains.get(root, 0) + 1

    for root, count in sorted(
        domains.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:
        print(f"{root:40} {count}")

    print_section("RECENT CRITICAL ALERTS")

    cursor.execute("""
        SELECT timestamp, source_ip, domain, alert_type, severity
        FROM alerts
        WHERE severity = 'critical'
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    if not rows:
        print("No critical alerts found.")
    else:
        for timestamp, source_ip, domain, alert_type, severity in rows:
            print(f"{timestamp} | {source_ip} | {alert_type} | {domain}")
    print_section("SOC RISK SCORE BY IP")

    cursor.execute("""
        SELECT source_ip, severity
        FROM alerts
    """)

    ip_scores = {}

    for source_ip, severity in cursor.fetchall():
        score = severity_score(severity)

        ip_scores[source_ip] = (
            ip_scores.get(source_ip, 0)
            + score
        )

    for ip, score in sorted(
        ip_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]:
        print(f"{ip:20} {score}")

    blocked_ips = generate_blocklist(ip_scores)

    print_section("RECOMMENDED IP BLOCKLIST")

    if not blocked_ips:
        print("No IP reached the blocking threshold.")
    else:
        for ip in blocked_ips:
            print(ip)

    conn.close()


if __name__ == "__main__":
    show_report()