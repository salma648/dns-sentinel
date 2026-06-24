from powerdns_reader import read_powerdns_log
from detector import detect, calculate_entropy
from storage import save_event, save_alert
from blocker import generate_blocklist
import time


LOG_FILE = "powerdns.log"


def import_powerdns_log(log_file=LOG_FILE):
    events = read_powerdns_log(log_file)

    imported_events = 0
    generated_alerts = 0

    print(f"Loaded {len(events)} PowerDNS events")

    for event in events:
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

        imported_events += 1

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

            generated_alerts += 1

            print(
                f"[ALERT] {source_ip} {domain} "
                f"{rcode} {alert_type} {severity} "
                f"{detection_time_ms} ms"
            )

    generate_blocklist()

    print("\nImport completed")
    print("Imported events :", imported_events)
    print("Generated alerts:", generated_alerts)


if __name__ == "__main__":
    import_powerdns_log()