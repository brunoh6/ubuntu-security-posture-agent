from datetime import datetime, timedelta


AUTH_LOG_PATH = "/var/log/auth.log"
FAILED_LOGIN_THRESHOLD = 5


def _parse_timestamp(line):
    """
    Parse syslog timestamp (e.g. 'Jan 10 12:34:56').
    Year is assumed as current year.
    """
    try:
        now = datetime.utcnow()
        ts = datetime.strptime(line[:15], "%b %d %H:%M:%S")
        return ts.replace(year=now.year)
    except Exception:
        return None


def inspect_auth_log(config):
    checks = []

    failed_logins = []
    sudo_events = []

    since = datetime.utcnow() - timedelta(hours=24)

    try:
        with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ts = _parse_timestamp(line)
                if not ts or ts < since:
                    continue

                lower = line.lower()

                if "failed password" in lower:
                    failed_logins.append(line.strip())

                if "sudo:" in lower:
                    sudo_events.append(line.strip())

    except FileNotFoundError:
        return [{
            "id": "auth.log_missing",
            "category": "auth",
            "severity": "warning",
            "message": "auth.log not found on system",
            "data": {}
        }]
    except Exception as exc:
        return [{
            "id": "auth.log_read_error",
            "category": "auth",
            "severity": "warning",
            "message": f"Failed to read auth.log: {exc}",
            "data": {}
        }]

    if len(failed_logins) >= FAILED_LOGIN_THRESHOLD:
        checks.append({
            "id": "auth.failed_logins",
            "category": "auth",
            "severity": "warning",
            "message": "Multiple failed login attempts detected",
            "data": {
                "count": len(failed_logins),
                "samples": failed_logins[:5],
            }
        })

    if sudo_events:
        checks.append({
            "id": "auth.sudo_usage",
            "category": "auth",
            "severity": "info",
            "message": "Sudo usage detected in auth.log",
            "data": {
                "count": len(sudo_events),
                "samples": sudo_events[:5],
            }
        })

    return checks