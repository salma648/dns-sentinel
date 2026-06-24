import math
import time
import logging
from collections import Counter, defaultdict

from config import (
    ENTROPY_THRESHOLD,
    NXDOMAIN_BURST_THRESHOLD,
    NXDOMAIN_BURST_WINDOW,
    DNS_TUNNELING_LENGTH_THRESHOLD,
    DNS_TUNNELING_ENTROPY_THRESHOLD,
    WATER_TORTURE_THRESHOLD,
    WATER_TORTURE_WINDOW,
    WATER_TORTURE_ENTROPY_RATIO,
    WATER_TORTURE_IP_THRESHOLD,
    WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD,
    LOG_FILE
)


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s"
)


nxdomain_history = defaultdict(list)
subdomain_history = defaultdict(list)
water_torture_alert_history = defaultdict(float)


def calculate_entropy(domain):
    counts = Counter(domain)
    length = len(domain)

    if length == 0:
        return 0

    probabilities = [count / length for count in counts.values()]
    return -sum(p * math.log2(p) for p in probabilities)


def get_root_domain(domain):
    parts = domain.split(".")

    simple_tlds = {"com", "org", "net", "io", "us", "fr"}

    if len(parts) >= 2 and parts[-1] in simple_tlds:
        return ".".join(parts[-2:])

    if len(parts) >= 3:
        return ".".join(parts[-3:])

    return domain


def get_first_label(domain):
    return domain.split(".")[0]


def is_dga_like(domain):
    first_part = get_first_label(domain)

    if len(first_part) < 8:
        return False

    digits = sum(c.isdigit() for c in first_part)
    vowels = sum(c in "aeiou" for c in first_part.lower())

    digit_ratio = digits / len(first_part)
    vowel_ratio = vowels / len(first_part)

    if digit_ratio > 0.30:
        return True

    if vowel_ratio < 0.10:
        return True

    if len(first_part) > 15 and vowel_ratio < 0.25:
        return True

    return False


def is_dns_tunneling(domain, entropy):
    first_part = get_first_label(domain)

    return (
        len(first_part) >= DNS_TUNNELING_LENGTH_THRESHOLD
        and entropy >= DNS_TUNNELING_ENTROPY_THRESHOLD
    )


def detect_water_torture(source_ip, domain, current_time):
    root_domain = get_root_domain(domain)
    subdomain = get_first_label(domain)

    if not subdomain:
        return False

    subdomain_entropy = calculate_entropy(subdomain)

    subdomain_history[root_domain].append({
        "time": current_time,
        "subdomain": subdomain,
        "entropy": subdomain_entropy,
        "ip": source_ip
    })

    subdomain_history[root_domain] = [
        event
        for event in subdomain_history[root_domain]
        if current_time - event["time"] <= WATER_TORTURE_WINDOW
    ]

    events = subdomain_history[root_domain]

    unique_subdomains = {
        event["subdomain"]
        for event in events
    }

    unique_ips = {
        event["ip"]
        for event in events
    }

    high_entropy_events = [
        event
        for event in events
        if event["entropy"] >= WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD
    ]

    if not events:
        return False

    entropy_ratio = len(high_entropy_events) / len(events)

    conditions_met = (
        len(unique_subdomains) >= WATER_TORTURE_THRESHOLD
        and len(unique_ips) >= WATER_TORTURE_IP_THRESHOLD
        and entropy_ratio >= WATER_TORTURE_ENTROPY_RATIO
    )

    if not conditions_met:
        return False

    last_alert_time = water_torture_alert_history[root_domain]

    if current_time - last_alert_time < WATER_TORTURE_WINDOW:
        return False

    water_torture_alert_history[root_domain] = current_time
    return True


def get_water_torture_context(domain):
    root_domain = get_root_domain(domain)
    events = subdomain_history[root_domain]

    unique_subdomains = {
        event["subdomain"]
        for event in events
    }

    unique_ips = {
        event["ip"]
        for event in events
    }

    high_entropy_events = [
        event
        for event in events
        if event["entropy"] >= WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD
    ]

    entropy_ratio = 0

    if events:
        entropy_ratio = len(high_entropy_events) / len(events)

    return {
        "root_domain": root_domain,
        "unique_subdomains": len(unique_subdomains),
        "unique_ips": len(unique_ips),
        "entropy_ratio": entropy_ratio
    }


def log_detection(alert_type, severity, source_ip, domain, rcode, entropy):
    root_domain = get_root_domain(domain)

    if alert_type == "WATER_TORTURE":
        context = get_water_torture_context(domain)

        logging.warning(
            "DETECTION type=%s severity=%s source_ip=%s domain=%s root=%s rcode=%s entropy=%.2f unique_subdomains=%s unique_ips=%s entropy_ratio=%.2f",
            alert_type,
            severity,
            source_ip,
            domain,
            context["root_domain"],
            rcode,
            entropy,
            context["unique_subdomains"],
            context["unique_ips"],
            context["entropy_ratio"]
        )

    else:
        logging.warning(
            "DETECTION type=%s severity=%s source_ip=%s domain=%s root=%s rcode=%s entropy=%.2f",
            alert_type,
            severity,
            source_ip,
            domain,
            root_domain,
            rcode,
            entropy
        )


def detect(source_ip, domain, rcode, entropy):
    current_time = time.time()

    if is_dns_tunneling(domain, entropy):
        alert_type, severity = "DNS_TUNNELING_SUSPECT", "critical"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        return alert_type, severity

    if detect_water_torture(source_ip, domain, current_time):
        alert_type, severity = "WATER_TORTURE", "critical"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        return alert_type, severity

    if rcode == "NXDOMAIN":
        nxdomain_history[source_ip].append(current_time)

        nxdomain_history[source_ip] = [
            timestamp
            for timestamp in nxdomain_history[source_ip]
            if current_time - timestamp <= NXDOMAIN_BURST_WINDOW
        ]

        if len(nxdomain_history[source_ip]) >= NXDOMAIN_BURST_THRESHOLD:
            alert_type, severity = "NXDOMAIN_BURST", "high"
            log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
            return alert_type, severity

        if is_dga_like(domain):
            alert_type, severity = "DGA_SUSPECT", "high"
            log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
            return alert_type, severity


    return None, None