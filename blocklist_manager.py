import io
import sqlite3
import subprocess

import config
from docker_controller import KALI_HOST, KALI_USER, run_kali_command

# Plus de fichier local Windows
REMOTE_TEMP_FILE     = "/tmp/blocked_ips.lua"
REMOTE_BLOCKLIST_FILE = "/etc/powerdns/blocked_ips.lua"


def _generate_lua_content():
    """
    Génère le contenu Lua depuis SQLite.
    Retourne une string — aucun fichier local créé.
    SQLite est la seule source de vérité.
    """
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip
        FROM blocked_ips
        WHERE active = 1
        ORDER BY ip
    """)
    ips = cursor.fetchall()
    conn.close()

    print(f"[blocklist] Generating Lua content — active IPs: {[r[0] for r in ips]}")

    lines = ["blocked_ips = {\n"]
    for (ip,) in ips:
        lines.append(f'    ["{ip}"] = true,\n')
    lines.append("}\n")

    return "".join(lines)


def _upload_lua_content(lua_content):
    """
    Envoie le contenu Lua directement sur Kali via SSH stdin.
    Aucun fichier intermédiaire sur Windows.
    """
    ssh_command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        f"{KALI_USER}@{KALI_HOST}",
        f"cat > {REMOTE_TEMP_FILE}"
    ]

    result = subprocess.run(
        ssh_command,
        input=lua_content,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30
    )

    if result.returncode != 0:
        print(f"[blocklist] SSH upload failed: {result.stderr}")
    else:
        print(f"[blocklist] Lua content uploaded to {REMOTE_TEMP_FILE}")

    return result


def _apply_blocklist():
    """Lance le script Kali qui copie /tmp/ → /etc/powerdns/ et recharge."""
    command = "sudo -n /usr/local/bin/dns_sentinel_reload_blocklist.sh"
    return run_kali_command(command, timeout=20)


def sync_blocklist():
    """
    Workflow complet :
      1. Lire SQLite → générer Lua en mémoire
      2. Envoyer via SSH vers /tmp/blocked_ips.lua sur Kali
      3. Script Kali copie vers /etc/powerdns/ et recharge PowerDNS
    Aucun fichier local Windows créé.
    """
    lua_content = _generate_lua_content()

    upload_result = _upload_lua_content(lua_content)
    if upload_result.returncode != 0:
        print("[blocklist] Sync aborted — upload failed")
        return upload_result

    try:
        apply_result = _apply_blocklist()
        stdout = getattr(apply_result, "stdout", "") or ""
        stderr = getattr(apply_result, "stderr", "") or ""
        print(f"[blocklist] Reload result: {stdout.strip()} {stderr.strip()}")
        return apply_result
    except Exception as e:
        print(f"[blocklist] PowerDNS reload failed: {e}")
        return None


def sync_empty_blocklist():
    """
    Écrit explicitement blocked_ips = {} sur Kali et recharge.
    Utilisé par reset_demo_data pour garantir un état propre.
    """
    lua_content = "blocked_ips = {}\n"

    upload_result = _upload_lua_content(lua_content)
    if upload_result.returncode != 0:
        print("[blocklist] Empty sync aborted — upload failed")
        return upload_result

    try:
        apply_result = _apply_blocklist()
        print("[blocklist] Empty blocklist applied")
        return apply_result
    except Exception as e:
        print(f"[blocklist] Empty blocklist reload failed: {e}")
        return None


def block_ip(ip, attack_type, reason):
    """
    Insère ou réactive l'IP dans SQLite puis synchronise vers Kali.
    """
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO blocked_ips
        (ip, attack_type, reason, active)
        VALUES (?, ?, ?, 1)
    """, (ip, attack_type, reason))

    conn.commit()
    conn.close()

    print(f"[blocklist] IP {ip} marked active in SQLite")
    return sync_blocklist()


def unblock_ip(ip):
    """
    Désactive l'IP dans SQLite puis synchronise vers Kali.
    Le fichier /etc/powerdns/blocked_ips.lua est régénéré
    sans cette IP — PowerDNS arrête de la refuser.
    """
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE blocked_ips
        SET active = 0
        WHERE ip = ?
    """, (ip,))

    conn.commit()
    conn.close()

    print(f"[blocklist] IP {ip} marked inactive in SQLite")
    return sync_blocklist()   # ← corrigé : sync obligatoire


def get_blocked_ips():
    """Retourne les IPs actuellement actives dans SQLite."""
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, attack_type, reason, blocked_at
        FROM blocked_ips
        WHERE active = 1
        ORDER BY blocked_at DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows