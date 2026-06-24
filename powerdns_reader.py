import re


import re


def parse_powerdns_line(line):

    qname_match = re.search(
        r'qname="([^"]+)"',
        line
    )

    ip_match = re.search(
        r'remote="([\d\.]+):',
        line
    )

    rcode_match = re.search(
        r'SyncRes\([^)]*,([0-9]+),done\)',
        line
    )

    if not qname_match:
        return None

    domain = qname_match.group(1).rstrip(".")

    source_ip = "127.0.0.1"

    if ip_match:
        source_ip = ip_match.group(1)

    rcode = "UNKNOWN"

    if rcode_match:

        code = int(rcode_match.group(1))

        if code == 0:
            rcode = "NOERROR"

        elif code == 3:
            rcode = "NXDOMAIN"

        elif code == 2:
            rcode = "SERVFAIL"

    return {
        "source_ip": source_ip,
        "domain": domain,
        "rcode": rcode
    }


def read_powerdns_log(log_path):
    events = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            event = parse_powerdns_line(line)

            if event:
                events.append(event)

    return events