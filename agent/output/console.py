def print_result(result, quiet=False):
    """
    Print human-readable output to console.

    Args:
        result (dict): Result object from runner
        quiet (bool): Suppress non-critical output
    """
    if quiet:
        return

    print("Ubuntu Security Posture Agent")
    print("Summary:")
    summary = result.get("summary", {})
    print(f"  Warnings: {summary.get('warnings', 0)}")
    print(f"  Critical: {summary.get('critical', 0)}")