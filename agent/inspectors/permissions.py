import os
import stat


CRITICAL_PATHS = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
)


def inspect_permissions(config):
    checks = []
    world_writable = []
    suid_files = []

    for base_path in CRITICAL_PATHS:
        if not os.path.exists(base_path):
            continue

        try:
            for root, dirs, files in os.walk(base_path):
                for name in files:
                    path = os.path.join(root, name)

                    try:
                        st = os.stat(path)
                    except (FileNotFoundError, PermissionError):
                        continue

                    # World-writable
                    if st.st_mode & stat.S_IWOTH:
                        world_writable.append(path)

                    # SUID bit
                    if st.st_mode & stat.S_ISUID:
                        suid_files.append(path)

        except Exception as exc:
            return [{
                "id": "permissions.scan_error",
                "category": "filesystem",
                "severity": "warning",
                "message": f"Failed to inspect permissions: {exc}",
                "data": {}
            }]

    if world_writable:
        checks.append({
            "id": "permissions.world_writable",
            "category": "filesystem",
            "severity": "warning",
            "message": "World-writable files detected in critical paths",
            "data": {
                "files": world_writable
            }
        })

    if suid_files:
        checks.append({
            "id": "permissions.suid",
            "category": "filesystem",
            "severity": "info",
            "message": "SUID files detected",
            "data": {
                "files": suid_files
            }
        })

    return checks