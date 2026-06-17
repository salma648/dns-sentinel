import random
import string


CORPORATE_DOMAINS = [
    "mail.company.local",
    "vpn.company.local",
    "gitlab.company.local",
    "jira.company.local",
    "intranet.company.local",
    "files.company.local",
    "portal.company.local"
]


PUBLIC_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "office.com",
    "zoom.us",
    "slack.com"
]


WATER_TORTURE_TARGETS = [
    "api.company.local",
    "mail.company.local",
    "vpn.company.local"
]


def random_string(length):
    characters = string.ascii_lowercase + string.digits

    return "".join(
        random.choice(characters)
        for _ in range(length)
    )


def generate_typo(domain):
    parts = domain.split(".")
    label = parts[0]

    if len(label) < 3:
        return domain

    index = random.randint(1, len(label) - 1)

    modified_label = label[:index] + label[index + 1:]

    parts[0] = modified_label

    return ".".join(parts)


def generate_normal_domain():
    all_domains = CORPORATE_DOMAINS + PUBLIC_DOMAINS
    return random.choice(all_domains), "NOERROR"


def generate_simple_nxdomain():
    base_domain = random.choice(CORPORATE_DOMAINS + PUBLIC_DOMAINS)
    typo_domain = generate_typo(base_domain)

    return typo_domain, "NXDOMAIN"


def generate_dga_domain():
    label = random_string(random.randint(10, 16))
    domain = f"{label}.com"

    return domain, "NXDOMAIN"


def generate_dns_tunneling_domain():
    label = random_string(random.randint(30, 45))
    domain = f"{label}.company.local"

    return domain, "NOERROR"


def generate_water_torture_domain():
    label = random_string(random.randint(6, 10))
    target = random.choice(WATER_TORTURE_TARGETS)

    domain = f"{label}.{target}"

    return domain, "NXDOMAIN"


def generate_dns_event():
    traffic_type = random.choices(
        population=[
            "normal",
            "simple_nxdomain",
            "dga",
            "dns_tunneling",
            "water_torture"
        ],
        weights=[
            30,
            10,
            10,
            10,
            40
        ],
        k=1
    )[0]

    source_ip = "192.168.1." + str(random.randint(10, 50))

    if traffic_type == "normal":
        domain, rcode = generate_normal_domain()

    elif traffic_type == "simple_nxdomain":
        domain, rcode = generate_simple_nxdomain()

    elif traffic_type == "dga":
        domain, rcode = generate_dga_domain()

    elif traffic_type == "dns_tunneling":
        source_ip = "192.168.1.77"
        domain, rcode = generate_dns_tunneling_domain()

    elif traffic_type == "water_torture":
        source_ip = "192.168.1." + str(random.randint(90, 99))
        domain, rcode = generate_water_torture_domain()

    else:
        domain, rcode = generate_normal_domain()

    return source_ip, domain, rcode