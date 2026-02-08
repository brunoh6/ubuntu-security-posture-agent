import socket
from datetime import datetime

from agent.inspectors import users, sudo, services, ports, processes, permissions
from agent.logs import auth, journald
from agent.core.config import load_config


AGENT_VERSION = "0.1.0"


def _collect_metadata():
    return {
        "hostname": socket.gethostname(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "agent_version": AGENT_VERSION,
    }


def _run_inspectors(config):
    checks = []

    inspectors = [
        users.inspect_users,
        sudo.inspect_sudo,
        services.inspect_services,
        ports.inspect_ports,
        processes.inspect_processes,
        permissions.inspect_permissions,
    ]

    for inspector in inspectors:
        try:
            result = inspector(config)
            if result:
                checks.extend(result)
        except Exception as exc:
            checks.append({
                "id": f"{inspector.__name__}.error",
                "category": "internal",
                "severity": "warning",
                "message": f"Inspector failed: {exc}",
                "data": {}
            })

    return checks


def _run_log_checks(config):
    checks = []

    log_checks = [
        auth.inspect_auth_log,
        journald.inspect_journald,
    ]

    for check in log_checks:
        try:
            result = check(config)
            if result:
                checks.extend(result)
        except Exception as exc:
            checks.append({
                "id": f"{check.__name__}.error",
                "category": "internal",
                "severity": "warning",
                "message": f"Log check failed: {exc}",
                "data": {}
            })

    return checks


def _build_summary(checks):
    summary = {
        "info": 0,
        "warnings": 0,
        "critical": 0
    }

    for check in checks:
        severity = check.get("severity")
        if severity == "info":
            summary["info"] += 1
        elif severity == "warning":
            summary["warnings"] += 1
        elif severity == "critical":
            summary["critical"] += 1

    return summary


def run(config_path=None):
    config = load_config(config_path)

    checks = []
    checks.extend(_run_inspectors(config))
    checks.extend(_run_log_checks(config))

    result = {
        "metadata": _collect_metadata(),
        "checks": checks,
        "summary": _build_summary(checks),
    }

    return result