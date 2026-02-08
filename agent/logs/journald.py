import subprocess
from collections import Counter


ERROR_PRIORITY = 3
RESTART_THRESHOLD = 3


def _run_journalctl(args):
    result = subprocess.run(
        ["journalctl"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.stdout.splitlines()


def inspect_journald(config):
    checks = []

    error_messages = []
    service_restarts = []

    try:
        # --- High priority messages (err, crit) ---
        lines = _run_journalctl([
            "--since", "24 hours ago",
            f"-p{ERROR_PRIORITY}",
            "--no-pager"
        ])

        for line in lines:
            if line.strip():
                error_messages.append(line.strip())

        # --- Service restarts ---
        restart_lines = _run_journalctl([
            "--since", "24 hours ago",
            "--no-pager"
        ])

        for line in restart_lines:
            lower = line.lower()
            if "started" in lower and "service" in lower:
                # crude but effective extraction
                parts = line.split()
                for part in parts:
                    if part.endswith(".service"):
                        service_restarts.append(part)
                        break

    except Exception as exc:
        return [{
            "id": "journald.execution_error",
            "category": "logs",
            "severity": "warning",
            "message": f"Failed to inspect journald: {exc}",
            "data": {}
        }]

    if error_messages:
        checks.append({
            "id": "journald.errors",
            "category": "logs",
            "severity": "warning",
            "message": "High-priority journald messages detected",
            "data": {
                "count": len(error_messages),
                "samples": error_messages[:5],
            }
        })

    restart_counts = Counter(service_restarts)
    frequent_restarts = {
        svc: count
        for svc, count in restart_counts.items()
        if count >= RESTART_THRESHOLD
    }

    if frequent_restarts:
        checks.append({
            "id": "journald.frequent_restarts",
            "category": "logs",
            "severity": "warning",
            "message": "Services with frequent restarts detected",
            "data": {
                "services": frequent_restarts
            }
        })

    return checks