import time

from database import init_db
from simulator import generate_dns_event
from detector import calculate_entropy, detect
from storage import save_event, save_alert


def process_event():
    source_ip, domain, rcode = generate_dns_event()

    entropy = calculate_entropy(domain)

    save_event(source_ip, domain, rcode, entropy)

    alert_type, severity = detect(source_ip,domain, rcode, entropy)

    if alert_type:
        save_alert(source_ip, domain, rcode, entropy, alert_type, severity)
        print("[ALERT]", source_ip, domain, rcode, round(entropy, 2), alert_type, severity)
    else:
        print("[OK]", source_ip, domain, rcode, round(entropy, 2))


if __name__ == "__main__":
    init_db()

    while True:
        process_event()
        time.sleep(2)

