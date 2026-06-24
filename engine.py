from simulator import generate_dns_event, send_dns_query
from detector import calculate_entropy, detect
from storage import save_event, save_alert
from blocker import generate_blocklist
import time


def process_dns_event():
    source_ip, domain, rcode = generate_dns_event()
   # print("Sending DNS query for domain:", domain)
    send_dns_query(domain)

    return {
        "source_ip": source_ip,
        "domain": domain,
        "rcode": "SENT_TO_POWERDNS"
    }
def generate_traffic(batch_size=20):

    results = []

    for _ in range(batch_size):
        results.append(process_dns_event())

    return results