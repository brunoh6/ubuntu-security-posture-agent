def inspect_sudo(config):
    checks = []

    sudo_users = []
    nopasswd_rules = []
    broad_rules = []

    # --- Parse /etc/group for sudo group ---
    try:
        with open("/etc/group", "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue

                parts = line.strip().split(":")
                if len(parts) < 4:
                    continue

                group_name = parts[0]
                members = parts[3].split(",") if parts[3] else []

                if group_name == "sudo":
                    sudo_users.extend([m for m in members if m])

    except Exception as exc:
        return [{
            "id": "sudo.group_read_error",
            "category": "privilege",
            "severity": "warning",
            "message": f"Failed to read /etc/group: {exc}",
            "data": {}
        }]

    if sudo_users:
        checks.append({
            "id": "sudo.users",
            "category": "privilege",
            "severity": "warning",
            "message": "Users with sudo privileges detected",
            "data": {
                "users": sudo_users
            }
        })

    # --- Parse /etc/sudoers (best-effort) ---
    try:
        with open("/etc/sudoers", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                # Skip includes
                if line.startswith("include"):
                    continue

                if "NOPASSWD" in line:
                    nopasswd_rules.append(line)

                if "ALL=(ALL)" in line:
                    broad_rules.append(line)

    except Exception as exc:
        checks.append({
            "id": "sudo.sudoers_read_error",
            "category": "privilege",
            "severity": "warning",
            "message": f"Failed to read /etc/sudoers: {exc}",
            "data": {}
        })
        return checks

    if nopasswd_rules:
        checks.append({
            "id": "sudo.nopasswd",
            "category": "privilege",
            "severity": "critical",
            "message": "NOPASSWD sudo rules detected",
            "data": {
                "rules": nopasswd_rules
            }
        })

    if broad_rules:
        checks.append({
            "id": "sudo.broad_rules",
            "category": "privilege",
            "severity": "warning",
            "message": "Broad sudo rules detected (ALL=(ALL))",
            "data": {
                "rules": broad_rules
            }
        })

    return checks