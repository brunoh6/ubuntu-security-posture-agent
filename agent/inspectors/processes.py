import subprocess


SUSPICIOUS_PATHS = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)


def inspect_processes(config):
    checks = []
    processes = []
    root_processes = []
    suspicious_exec = []

    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,user,comm,args"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )

        lines = result.stdout.splitlines()
        for line in lines[1:]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue

            pid, user, comm, args = parts

            proc = {
                "pid": pid,
                "user": user,
                "command": comm,
                "args": args,
            }
            processes.append(proc)

            if user == "root":
                root_processes.append(proc)

            for path in SUSPICIOUS_PATHS:
                if args.startswith(path):
                    suspicious_exec.append(proc)
                    break

    except Exception as exc:
        return [{
            "id": "processes.execution_error",
            "category": "runtime",
            "severity": "warning",
            "message": f"Failed to inspect processes: {exc}",
            "data": {}
        }]

    if root_processes:
        checks.append({
            "id": "processes.root",
            "category": "runtime",
            "severity": "info",
            "message": "Processes running as root",
            "data": {
                "processes": root_processes
            }
        })

    if suspicious_exec:
        checks.append({
            "id": "processes.suspicious_paths",
            "category": "runtime",
            "severity": "warning",
            "message": "Processes executed from suspicious paths",
            "data": {
                "processes": suspicious_exec
            }
        })

    return checks