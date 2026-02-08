import subprocess


SENSITIVE_SERVICES = {
    "ssh.service",
    "sshd.service",
    "telnet.service",
    "vsftpd.service",
    "proftpd.service",
    "docker.service",
    "snapd.service",
}


def _run_command(cmd):
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.stdout.splitlines()


def inspect_services(config):
    checks = []

    try:
        enabled_services = set()
        for line in _run_command(
            ["systemctl", "list-unit-files", "--type=service", "--no-pager"]
        ):
            if not line or line.startswith("UNIT FILE"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "enabled":
                enabled_services.add(parts[0])

        running_services = set()
        for line in _run_command(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"]
        ):
            if not line or line.startswith("UNIT"):
                continue
            parts = line.split()
            if parts:
                running_services.add(parts[0])

    except Exception as exc:
        return [{
            "id": "services.execution_error",
            "category": "system",
            "severity": "warning",
            "message": f"Failed to query systemd services: {exc}",
            "data": {}
        }]

    active_and_enabled = sorted(enabled_services & running_services)

    if active_and_enabled:
        checks.append({
            "id": "services.active_enabled",
            "category": "system",
            "severity": "info",
            "message": "Services enabled and currently running",
            "data": {
                "services": active_and_enabled
            }
        })

    sensitive_active = sorted(active_and_enabled & SENSITIVE_SERVICES)

    if sensitive_active:
        checks.append({
            "id": "services.sensitive_active",
            "category": "system",
            "severity": "warning",
            "message": "Sensitive services running",
            "data": {
                "services": sensitive_active
            }
        })

    return checks