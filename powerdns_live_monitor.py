import re
import time
import subprocess

from detector import calculate_entropy, detect
from storage import save_event, save_alert
from blocker import generate_blocklist


KALI_HOST = "192.168.174.129"
KALI_USER = "kali"


def parse_powerdns_line(line):
    qname_match = re.search(r'qname="([^"]+)"', line)
    ip_match = re.search(r'remote="([\d\.]+):', line)
    rcode_match = re.search(r'SyncRes\([^)]*,([0-9]+),done\)', line)

    if not qname_match:
        return None

    domain = qname_match.group(1).rstrip(".")
    source_ip = ip_match.group(1) if ip_match else "127.0.0.1"

    rcode = "UNKNOWN"

    if rcode_match:
        code = int(rcode_match.group(1))

        if code == 0:
            rcode = "NOERROR"
        elif code == 2:
            rcode = "SERVFAIL"
        elif code == 3:
            rcode = "NXDOMAIN"

    return {
        "source_ip": source_ip,
        "domain": domain,
        "rcode": rcode
    }


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

    if alert_type:
        save_alert(
            source_ip,
            domain,
            rcode,
            entropy,
            alert_type,
            severity,
            detection_time_ms=detection_time_ms
        )

        generate_blocklist()



def start_powerdns_monitor():
    command = [
        "ssh",
        "-tt",
        f"{KALI_USER}@{KALI_HOST}",
        "journalctl -u pdns-recursor -f -o cat --no-pager"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
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