import sqlite3

from config import (
    DB_PATH,
    AUTO_BLOCK_SCORE_THRESHOLD,
    BLOCKLIST_FILE
)


def severity_score(severity):

    scores = {
        "critical": 10,
        "high": 5,
        "medium": 2
    }

    return scores.get(severity, 0)


def calculate_ip_scores():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

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

    conn.close()

    return ip_scores


def generate_blocklist():

    ip_scores = calculate_ip_scores()

    blocked_ips = [
        ip
        for ip, score in ip_scores.items()
        if score >= AUTO_BLOCK_SCORE_THRESHOLD
    ]

    with open(BLOCKLIST_FILE, "w") as file:

        for ip in blocked_ips:
            file.write(ip + "\n")

    return blocked_ips


def is_blocked_ip(ip):

    try:

        with open(BLOCKLIST_FILE, "r") as file:

            blocked_ips = {
                line.strip()
                for line in file
                if line.strip()
            }
            print( f"[BLOCKED] {source_ip} attempted " f"to query {domain}")
        return ip in blocked_ips

    except FileNotFoundError:

        return False


def count_blocked_ips():

    try:

        with open(BLOCKLIST_FILE, "r") as file:

            return len([
                line
                for line in file
                if line.strip()
            ])

    except FileNotFoundError:

        return 0

def unblock_ip(ip):

    try:

        with open(BLOCKLIST_FILE, "r") as file:

            ips = [
                line.strip()
                for line in file
                if line.strip()
            ]

        ips = [
            blocked_ip
            for blocked_ip in ips
            if blocked_ip != ip
        ]

        with open(BLOCKLIST_FILE, "w") as file:

            for blocked_ip in ips:
                file.write(blocked_ip + "\n")

        return True

    except FileNotFoundError:

        return False