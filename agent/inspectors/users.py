def inspect_users(config):
    checks = []

    users = []
    uid0_users = []
    interactive_users = []
    invalid_shell_users = []

    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue

                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue

                username = parts[0]
                uid = int(parts[2])
                shell = parts[6]

                users.append(username)

                if uid == 0:
                    uid0_users.append(username)

                if shell in ("/bin/bash", "/bin/sh", "/bin/zsh"):
                    interactive_users.append(username)

                if shell == "" or shell == "/usr/sbin/nologin" or shell == "/bin/false":
                    continue

                if not shell.startswith("/"):
                    invalid_shell_users.append(username)

    except Exception as exc:
        return [{
            "id": "users.read_error",
            "category": "system",
            "severity": "warning",
            "message": f"Failed to read /etc/passwd: {exc}",
            "data": {}
        }]

    if len(uid0_users) > 1:
        checks.append({
            "id": "users.multiple_uid0",
            "category": "system",
            "severity": "critical",
            "message": "Multiple UID 0 users detected",
            "data": {
                "users": uid0_users
            }
        })

    if interactive_users:
        checks.append({
            "id": "users.interactive_shells",
            "category": "system",
            "severity": "info",
            "message": "Users with interactive shells detected",
            "data": {
                "users": interactive_users
            }
        })

    if invalid_shell_users:
        checks.append({
            "id": "users.invalid_shells",
            "category": "system",
            "severity": "warning",
            "message": "Users with invalid or unexpected shells detected",
            "data": {
                "users": invalid_shell_users
            }
        })

    return checks