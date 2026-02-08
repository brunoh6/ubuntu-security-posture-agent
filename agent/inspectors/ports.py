import subprocess


SENSITIVE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}


def inspect_ports(config):
    checks = []
    listening = []

    try:
        result = subprocess.run(
            ["ss", "-tulnp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )

        for line in result.stdout.splitlines():
            if line.startswith("Netid") or not line.strip():
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            local_addr = parts[4]
            process_info = parts[-1] if parts[-1].startswith("users:") else ""

            if ":" in local_addr:
                try:
                    port = int(local_addr.rsplit(":", 1)[1])
                except ValueError:
                    continue
            else:
                continue

            listening.append({
                "port": port,
                "process": process_info,
            })

    except Exception as exc:
        return [{
            "id": "ports.execution_error",
            "category": "network",
            "severity": "warning",
            "message": f"Failed to inspect listening ports: {exc}",
            "data": {}
        }]

    if listening:
        checks.append({
            "id": "ports.listening",
            "category": "network",
            "severity": "info",
            "message": "Listening network ports detected",
            "data": {
                "ports": listening
            }
        })

    sensitive = [
        p for p in listening if p["port"] in SENSITIVE_PORTS
    ]

    if sensitive:
        checks.append({
            "id": "ports.sensitive",
            "category": "network",
            "severity": "warning",
            "message": "Sensitive ports are listening",
            "data": {
                "ports": sensitive
            }
        })

    return checks