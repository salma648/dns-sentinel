import subprocess


KALI_HOST = "192.168.174.129"
KALI_USER = "kali"


def get_powerdns_metric(metric_name):
    command = [
        "ssh",
        f"{KALI_USER}@{KALI_HOST}",
        f"sudo rec_control get {metric_name}"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return None

        return int(result.stdout.strip())

    except Exception:
        return None


def get_powerdns_stats():
    return {
        "questions": get_powerdns_metric("questions"),
        "nxdomain_answers": get_powerdns_metric("nxdomain-answers"),
        "servfail_answers": get_powerdns_metric("servfail-answers"),
        "cache_hits": get_powerdns_metric("cache-hits"),
        "cache_misses": get_powerdns_metric("cache-misses")
    }