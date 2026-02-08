import json
import sys


def emit_json(result):
    """
    Emit JSON output to stdout.

    Args:
        result (dict): Result object from runner
    """
    json.dump(result, sys.stdout, indent=2)
    print()