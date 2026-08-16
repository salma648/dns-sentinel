import re
import time
import subprocess

from detector import calculate_entropy, detect
from storage import save_event, save_alert
from notifier import (
    save_notification,
    send_email_notification,
    can_send_email
)
from blocklist_manager import block_ip


KALI_HOST = "192.168.174.129"
KALI_USER = "kali"

BLOCKING_ALERTS = [
    "WATER_TORTURE",
    "SLOW_WATER_TORTURE"
]

def parse_powerdns_line(line):
    qname_match = re.search(r'qname="([^"]+)"', line)
    ip_match = re.search(r'remote="([\d\.]+):', line)

    if not qname_match:
        return None

    domain = qname_match.group(1).rstrip(".")
    source_ip = ip_match.group(1) if ip_match else "127.0.0.1"

    rcode = "UNKNOWN"

    if "[DNS_SENTINEL_BLOCKED_IP]" in line:
        rcode = "REFUSED"

    elif "NXDOMAIN" in line:
        rcode = "NXDOMAIN"

    elif "NOERROR" in line:
        rcode = "NOERROR"

    elif "SERVFAIL" in line:
        rcode = "SERVFAIL"

    elif "REFUSED" in line:
        rcode = "REFUSED"

    else:
        if "LuaPreResolve" in line and ",1,done)" in line:
            rcode = "REFUSED"
        else:
            sync_match = re.search(r'SyncRes\([^)]*,([0-9]+),done\)', line)

            if sync_match:
                code = int(sync_match.group(1))

                if code == 0:
                    rcode = "NOERROR"
                elif code == 2:
                    rcode = "SERVFAIL"
                elif code == 3:
                    rcode = "NXDOMAIN"
                elif code == 5:
                    rcode = "REFUSED"

    if rcode == "UNKNOWN":
        return None

    return {
        "source_ip": source_ip,
        "domain": domain,
        "rcode": rcode
    }
def format_alert_name(alert_type):
    return alert_type.replace("_", " ").title()


def handle_blocking_alert(
    alert_type,
    severity,
    source_ip,
    domain,
    reason="Blocked manually from dashboard"
):
    alert_name = format_alert_name(alert_type)

    save_notification(
        alert_type,
        severity,
        source_ip,
        domain,
        "DASHBOARD",
        "SENT",
        f"Manual block requested for {source_ip}"
    )

    try:
        result = block_ip(
            source_ip,
            alert_type,
            reason
        )

        if result is not None and result.returncode == 0:
            save_notification(
                alert_type,
                severity,
                source_ip,
                domain,
                "BLOCKLIST",
                "SENT",
                f"IP {source_ip} blocked manually"
            )
        else:
            save_notification(
                alert_type,
                severity,
                source_ip,
                domain,
                "BLOCKLIST",
                "FAILED",
                f"Failed to block IP {source_ip}"
            )

    except Exception as e:
        save_notification(
            alert_type,
            severity,
            source_ip,
            domain,
            "BLOCKLIST",
            "FAILED",
            f"Blocking error for IP {source_ip}: {e}"
        )

def process_powerdns_event(event):
    source_ip = event["source_ip"]
    domain = event["domain"]
    rcode = event["rcode"]

    detection_start = time.perf_counter()

    entropy = calculate_entropy(domain)

    alert_type, severity = detect(
        source_ip,
        domain,
        rcode,
        entropy
    )

    detection_end = time.perf_counter()

    detection_time_ms = round(
        (detection_end - detection_start) * 1000,
        4
    )

    save_event(
        source_ip,
        domain,
        rcode,
        entropy,
        source_type="POWERDNS",
        detection_time_ms=detection_time_ms
    )

    if not alert_type:
        return
    alert_type = alert_type.strip().upper()
    save_alert(
        source_ip,
        domain,
        rcode,
        entropy,
        alert_type,
        severity,
        detection_time_ms=detection_time_ms
    )
    if alert_type in ["WATER_TORTURE", "SLOW_WATER_TORTURE"]:
        print("WATER TORTURE NOTIFICATION TRIGGERED")
        save_notification(
            alert_type,
            severity,
            source_ip,
            domain,
            "DASHBOARD",
            "SENT",
            f"{alert_type} detected on {domain}"
        )

        if can_send_email(alert_type, domain):
            send_email_notification(
                alert_type,
                severity,
                source_ip,
                domain
            )

            save_notification(
                alert_type,
                severity,
                source_ip,
                domain,
                "EMAIL",
                "SENT",
                f"Email sent for {alert_type} detected on {domain}"
            )
        else:
            save_notification(
                alert_type,
                severity,
                source_ip,
                domain,
                "EMAIL",
                "SKIPPED",
                f"Email skipped to avoid notification spam for {domain}"
            )


def start_powerdns_monitor():
    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=3",
        f"{KALI_USER}@{KALI_HOST}",
        "sudo -n journalctl -u pdns-recursor -f -n 0 -o cat --no-pager"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1
    )

    with open("powerdns_monitor.status", "w") as f:
        f.write("RUNNING")

    print("PowerDNS live monitor started...")

    for line in process.stdout:
        event = parse_powerdns_line(line)

        if event:
            process_powerdns_event(event)


if __name__ == "__main__":
    start_powerdns_monitor()