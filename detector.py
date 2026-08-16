import math
import time
import logging
import ipaddress
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
    LOG_FILE,
    INTERNAL_NETWORKS,
    IP_SCORE_THRESHOLD,
    PSEUDO_RANDOM_MIN_LENGTH,
    PSEUDO_RANDOM_MAX_VOWEL_RATIO,
    PSEUDO_RANDOM_MIN_UNIQUE_BIGRAMS,
    WATER_TORTURE_NXDOMAIN_RATIO,
    WATER_TORTURE_QPS_THRESHOLD,
    WATER_TORTURE_SCORE_THRESHOLD,
    SLOW_WATER_TORTURE_WINDOW,
    SLOW_WATER_TORTURE_THRESHOLD,
    SLOW_WATER_TORTURE_NXDOMAIN_RATIO,
    SLOW_WATER_TORTURE_ENTROPY_RATIO,


)


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s"
)

nxdomain_history             = defaultdict(list)
subdomain_history            = defaultdict(list)
water_torture_alert_history  = defaultdict(float)
ip_score                     = defaultdict(float)


COMMON_WORDS = {
    "update", "service", "track", "patch", "sync", "mail",
    "web", "api", "app", "cdn", "login", "auth", "portal",
    "admin", "static", "media", "news", "blog", "shop",
    "store", "secure", "support", "help", "docs", "cloud",
    "server", "client", "host", "file", "data", "info",
    "home", "main", "core", "base", "global", "local",
    "internal", "external", "public", "private", "vpn",
    "proxy", "gate", "edge", "node", "hub", "link",
}


def calculate_entropy(domain):
    """
    Mesure le caractère aléatoire d'une chaîne.
    Retourne 0 si la chaîne est vide.

    "google"    → ~2.3  (naturel)
    "x7k2pqm9"  → ~3.8  (aléatoire)
    """
    counts = Counter(domain)
    length = len(domain)
    if length == 0:
        return 0
    probabilities = [count / length for count in counts.values()]
    return -sum(p * math.log2(p) for p in probabilities)


def get_root_domain(domain):
    """
    Extrait le domaine racine depuis n'importe quel sous-domaine.

    "a7f3k.google.com"           → "google.com"
    "a7f3k.target.company.local" → "target.company.local"
    "vpn.company.local"          → "company.local"
    """
    parts = domain.split(".")
    simple_tlds = {"com", "org", "net", "io", "us", "fr"}
    if len(parts) >= 2 and parts[-1] in simple_tlds:
        return ".".join(parts[-2:])
    if len(parts) >= 3:
        return ".".join(parts[-3:])
    return domain


def get_first_label(domain):
    """
    Extrait le premier label d'un domaine.

    "a7f3k.company.local" → "a7f3k"
    "www.google.com"      → "www"
    """
    return domain.split(".")[0]


def is_internal_ip(ip):
    """
    Retourne True si l'IP appartient à un réseau interne.
    Les IPs internes bénéficient d'une tolérance accrue.
    """
    try:
        addr = ipaddress.ip_address(ip)
        for network in INTERNAL_NETWORKS:
            if addr in ipaddress.ip_network(network):
                return True
    except ValueError:
        pass
    return False

ALERT_SCORES = {
    "DNS_TUNNELING_SUSPECT" : 5,
    "WATER_TORTURE"         : 5,
    "NXDOMAIN_BURST"        : 3,
    "DGA_SUSPECT"           : 2,
    "PSEUDO_RANDOM_DOMAIN"  : 2,
    "HIGH_ENTROPY_DOMAIN"   : 1,
    "SLOW_WATER_TORTURE"    : 5
}


def update_ip_score(source_ip, alert_type, current_time):
    """
    Accumule un score de menace par IP.
    Si le score dépasse IP_SCORE_THRESHOLD → ATTACKER_CONFIRMED.
    Réinitialise le score après confirmation pour éviter le spam.
    """
    score = ALERT_SCORES.get(alert_type, 0)
    ip_score[source_ip] += score

    if ip_score[source_ip] >= IP_SCORE_THRESHOLD:
        logging.warning(
            "ATTACKER_CONFIRMED source_ip=%s cumulative_score=%.1f",
            source_ip,
            ip_score[source_ip]
        )
        ip_score[source_ip] = 0



def is_dga_like(domain):
    """
    Détecte les domaines générés par un algorithme (DGA).
    Trois critères :
      1. Trop de chiffres (DGA classique)
      2. Trop peu de voyelles (DGA classique)
      3. Long et peu de voyelles (DGA moderne)
    """
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


def is_pseudo_random_domain(domain):
    """
    Détecte les domaines pseudo-aléatoires qui imitent
    de vrais mots pour échapper aux détections classiques.

    Exemple : "updateservice.com", "newpatchfile.com"
    → passent is_dga_like et calculate_entropy
    → mais détectés ici par analyse des bigrammes et mots connus

    Trois signaux :
      1. Aucun mot connu dans le label
      2. Ratio de voyelles anormalement bas pour sa longueur
      3. Peu de bigrammes naturels (combinaisons de lettres rares)
    """
    first_part = get_first_label(domain).lower()

    if len(first_part) < PSEUDO_RANDOM_MIN_LENGTH:
        return False

    contains_known_word = any(word in first_part for word in COMMON_WORDS)

    vowels = sum(c in "aeiou" for c in first_part)
    vowel_ratio = vowels / len(first_part)
    low_vowel_ratio = vowel_ratio < PSEUDO_RANDOM_MAX_VOWEL_RATIO

    # Un texte naturel a des bigrammes répétés (ex: "th", "er", "in")
    # Un texte aléatoire a presque tous ses bigrammes uniques.
    bigrams = [first_part[i:i+2] for i in range(len(first_part) - 1)]
    unique_bigrams = len(set(bigrams))
    few_repeated_bigrams = unique_bigrams >= PSEUDO_RANDOM_MIN_UNIQUE_BIGRAMS
    signals = sum([
        not contains_known_word,
        low_vowel_ratio,
        few_repeated_bigrams
    ])

    return signals >= 2


def is_dns_tunneling(domain, entropy):
    """
    Détecte l'exfiltration de données via DNS.
    Condition : label très long ET très aléatoire.

    Normal   : "www.google.com"           (3 chars)
    Tunneling: "aGVsbG8gd29ybGQ.evil.com" (16+ chars, entropie élevée)
    """
    first_part = get_first_label(domain)
    return (
        len(first_part) >= DNS_TUNNELING_LENGTH_THRESHOLD
        and entropy >= DNS_TUNNELING_ENTROPY_THRESHOLD
    )


def detect_water_torture(source_ip, domain, rcode, current_time):
    """
    Détecte une attaque water torture en analysant les sous-domaines
    d'un même domaine racine sur une fenêtre temporelle glissante.

    Trois conditions simultanées :
      1. Assez de sous-domaines uniques (volume)
      2. Assez d'IPs sources uniques (botnet)
      3. Ratio élevé de sous-domaines à haute entropie (aléatoire)

    Le reset via water_torture_alert_history évite les alertes
    en boucle si l'attaque continue.
    """
    parts = domain.split(".")
    if len(parts) <= 2:
            return False

    root_domain = get_root_domain(domain)
    subdomain = get_first_label(domain)

    if not subdomain:
        return False

    subdomain_entropy = calculate_entropy(subdomain)

    subdomain_history[root_domain].append({
        "time": current_time,
        "subdomain": subdomain,
        "entropy": subdomain_entropy,
        "ip": source_ip,
        "rcode": rcode
    })

    subdomain_history[root_domain] = [
        event
        for event in subdomain_history[root_domain]
        if current_time - event["time"] <= WATER_TORTURE_WINDOW
    ]

    events = subdomain_history[root_domain]

    if not events:
        return False

    unique_subdomains = {event["subdomain"] for event in events}
    unique_ips = {event["ip"] for event in events}

    high_entropy_events = [
        event for event in events
        if event["entropy"] >= WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD
    ]

    nxdomain_events = [
        event for event in events
        if event["rcode"] == "NXDOMAIN"
    ]

    entropy_ratio = len(high_entropy_events) / len(events)
    nxdomain_ratio = len(nxdomain_events) / len(events)
    qps = len(events) / WATER_TORTURE_WINDOW

    score = 0

    if len(unique_subdomains) >= WATER_TORTURE_THRESHOLD:
        score += 35

    if entropy_ratio >= WATER_TORTURE_ENTROPY_RATIO:
        score += 25

    if nxdomain_ratio >= WATER_TORTURE_NXDOMAIN_RATIO:
        score += 25

    if len(unique_ips) >= WATER_TORTURE_IP_THRESHOLD:
        score += 10

    if qps >= WATER_TORTURE_QPS_THRESHOLD:
        score += 5

    if score < WATER_TORTURE_SCORE_THRESHOLD:
        return False

    last_alert_time = water_torture_alert_history[root_domain]

    if current_time - last_alert_time < WATER_TORTURE_WINDOW:
        return False

    water_torture_alert_history[root_domain] = current_time
    return True



slow_water_torture_history = defaultdict(list)

def detect_slow_water_torture(source_ip, domain, rcode, current_time):
    parts = domain.split(".")

    if len(parts) <= 2:
        return False

    root_domain = get_root_domain(domain)
    subdomain = get_first_label(domain)

    if not subdomain:
        return False

    subdomain_entropy = calculate_entropy(subdomain)

    slow_water_torture_history[root_domain].append({
        "time": current_time,
        "subdomain": subdomain,
        "entropy": subdomain_entropy,
        "ip": source_ip,
        "rcode": rcode
    })

    slow_water_torture_history[root_domain] = [
        event
        for event in slow_water_torture_history[root_domain]
        if current_time - event["time"] <= SLOW_WATER_TORTURE_WINDOW
    ]

    events = slow_water_torture_history[root_domain]

    if not events:
        return False

    unique_subdomains = {event["subdomain"] for event in events}
    unique_ips = {event["ip"] for event in events}

    high_entropy_events = [
        event for event in events
        if event["entropy"] >= WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD
    ]

    nxdomain_events = [
        event for event in events
        if event["rcode"] == "NXDOMAIN"
    ]

    entropy_ratio = len(high_entropy_events) / len(events)
    nxdomain_ratio = len(nxdomain_events) / len(events)

    return (
        len(unique_subdomains) >= SLOW_WATER_TORTURE_THRESHOLD
        and nxdomain_ratio >= SLOW_WATER_TORTURE_NXDOMAIN_RATIO
        and entropy_ratio >= SLOW_WATER_TORTURE_ENTROPY_RATIO
        and len(unique_ips) >= 1
    )

def get_water_torture_context(domain):
    root_domain = get_root_domain(domain)
    events = subdomain_history[root_domain]

    unique_subdomains = {e["subdomain"] for e in events}
    unique_ips = {e["ip"] for e in events}

    high_entropy_events = [
        e for e in events
        if e["entropy"] >= WATER_TORTURE_SUBDOMAIN_ENTROPY_THRESHOLD
    ]

    nxdomain_events = [
        e for e in events
        if e["rcode"] == "NXDOMAIN"
    ]

    entropy_ratio = len(high_entropy_events) / len(events) if events else 0
    nxdomain_ratio = len(nxdomain_events) / len(events) if events else 0

    return {
        "root_domain": root_domain,
        "unique_subdomains": len(unique_subdomains),
        "unique_ips": len(unique_ips),
        "entropy_ratio": entropy_ratio,
        "nxdomain_ratio": nxdomain_ratio
    }

def log_detection(alert_type, severity, source_ip, domain, rcode, entropy):
    """
    Écrit l'alerte dans le fichier de log.
    La water torture a un format enrichi avec le contexte complet.
    """
    root_domain = get_root_domain(domain)

    if alert_type == "WATER_TORTURE":
        context = get_water_torture_context(domain)
        logging.warning(
            "DETECTION type=%s severity=%s source_ip=%s domain=%s "
            "root=%s rcode=%s entropy=%.2f unique_subdomains=%s "
            "unique_ips=%s entropy_ratio=%.2f",
            alert_type, severity, source_ip, domain,
            context["root_domain"], rcode, entropy,
            context["unique_subdomains"],
            context["unique_ips"],
            context["entropy_ratio"]
        )
    else:
        logging.warning(
            "DETECTION type=%s severity=%s source_ip=%s domain=%s "
            "root=%s rcode=%s entropy=%.2f",
            alert_type, severity, source_ip, domain,
            root_domain, rcode, entropy
        )


def detect(source_ip, domain, rcode, entropy):
    """
    Point d'entrée unique du module.
    Appelée pour chaque événement DNS.

    Ordre de priorité :
      1. DNS Tunneling        (critical) — tout trafic
      2. Water Torture        (critical) — tout trafic
      3. NXDOMAIN Burst       (high)     — NXDOMAIN uniquement
      4. DGA                  (high)     — tout trafic
      5. Pseudo-random domain (medium)   — tout trafic
      6. Haute entropie       (medium)   — tout trafic

    Retourne (alert_type, severity) ou (None, None).
    """
    current_time = time.time()
    internal     = is_internal_ip(source_ip)

    if is_dns_tunneling(domain, entropy):
        alert_type, severity = "DNS_TUNNELING_SUSPECT", "critical"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        update_ip_score(source_ip, alert_type, current_time)
        return alert_type, severity

    if detect_water_torture(source_ip, domain, rcode, current_time):
        alert_type, severity = "WATER_TORTURE", "critical"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        update_ip_score(source_ip, alert_type, current_time)
        return alert_type, severity

    if detect_slow_water_torture(source_ip, domain, rcode, current_time):
        alert_type, severity = "SLOW_WATER_TORTURE", "critical"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        update_ip_score(source_ip, alert_type, current_time)
        return alert_type, severity


    if rcode == "NXDOMAIN":
        nxdomain_history[source_ip].append(current_time)
        nxdomain_history[source_ip] = [
            t for t in nxdomain_history[source_ip]
            if current_time - t <= NXDOMAIN_BURST_WINDOW
        ]


        burst_threshold = (
            NXDOMAIN_BURST_THRESHOLD * 3 if internal
            else NXDOMAIN_BURST_THRESHOLD
        )

        if len(nxdomain_history[source_ip]) >= burst_threshold:
            alert_type, severity = "NXDOMAIN_BURST", "high"
            log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
            update_ip_score(source_ip, alert_type, current_time)
            return alert_type, severity

    if rcode == "NXDOMAIN" or not internal:
        if is_dga_like(domain):
            alert_type, severity = "DGA_SUSPECT", "high"
            log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
            update_ip_score(source_ip, alert_type, current_time)
            return alert_type, severity

  
    if is_pseudo_random_domain(domain):
        alert_type, severity = "PSEUDO_RANDOM_DOMAIN", "medium"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        update_ip_score(source_ip, alert_type, current_time)
        return alert_type, severity


    if entropy >= ENTROPY_THRESHOLD:
        alert_type, severity = "HIGH_ENTROPY_DOMAIN", "medium"
        log_detection(alert_type, severity, source_ip, domain, rcode, entropy)
        update_ip_score(source_ip, alert_type, current_time)
        return alert_type, severity

    return None, None