def calculate_exit_code(result, fail_on="critical"):
    summary = result.get("summary", {})
    warnings = summary.get("warnings", 0)
    critical = summary.get("critical", 0)

    if fail_on == "warning" and warnings > 0:
        return 1

    if critical > 0:
        return 2

    return 0