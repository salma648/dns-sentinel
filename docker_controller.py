import subprocess

KALI_HOST = "192.168.174.129"
KALI_USER = "kali"
DOCKER_PROJECT_PATH = "~/dns_clients"


def run_kali_command(command, timeout=60):
    full_command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=3",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        f"{KALI_USER}@{KALI_HOST}",
        command
    ]

    return subprocess.run(
        full_command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout
    )


def start_dns_clients(scale=5):
    return run_kali_command(
        f"sudo -n /usr/local/bin/dns_sentinel_start_traffic.sh {scale}",
        timeout=30
    )


def stop_dns_clients():
    return run_kali_command(
        "sudo -n /usr/local/bin/dns_sentinel_stop_traffic.sh",
        timeout=30
    )


def remove_dns_clients():
    command = (
        f"cd {DOCKER_PROJECT_PATH} && "
        f"timeout 30s sudo -n docker-compose rm -f || true"
    )
    return run_kali_command(command, timeout=40)


def check_kali_connection():
    return run_kali_command("echo Connected", timeout=5)


def start_powerdns():
    return run_kali_command("sudo -n systemctl start pdns-recursor", timeout=20)


def stop_powerdns():
    return run_kali_command("sudo -n systemctl stop pdns-recursor", timeout=20)


def restart_powerdns():
    return run_kali_command("sudo -n systemctl restart pdns-recursor", timeout=30)


def get_powerdns_status():
    return run_kali_command("sudo -n systemctl is-active pdns-recursor", timeout=10)


def get_docker_clients_status():
    return run_kali_command(
        f"cd {DOCKER_PROJECT_PATH} && sudo -n docker-compose ps",
        timeout=20
    )