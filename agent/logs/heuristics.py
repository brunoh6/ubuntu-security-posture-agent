def apply_heuristics(checks):
    derived = []

    check_ids = {c["id"]: c for c in checks}

    # --- Heuristic 1: failed logins + sudo usage ---
    failed = check_ids.get("auth.failed_logins")
    sudo = check_ids.get("auth.sudo_usage")

    if failed and sudo:
        derived.append({
            "id": "heuristic.auth_compromise_suspected",
            "category": "heuristic",
            "severity": "critical",
            "message": "Failed logins combined with sudo usage detected",
            "data": {
                "failed_logins": failed.get("data", {}).get("count"),
                "sudo_events": sudo.get("data", {}).get("count"),
            }
        })

    # --- Heuristic 2: journald errors + frequent restarts ---
    errors = check_ids.get("journald.errors")
    restarts = check_ids.get("journald.frequent_restarts")

    if errors and restarts:
        derived.append({
            "id": "heuristic.system_instability",
            "category": "heuristic",
            "severity": "warning",
            "message": "System errors combined with frequent service restarts",
            "data": {
                "error_count": errors.get("data", {}).get("count"),
                "services": restarts.get("data", {}).get("services"),
            }
        })

    return derived