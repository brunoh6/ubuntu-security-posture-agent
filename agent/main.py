#!/usr/bin/env python3

import argparse
import sys

from agent.core.runner import run
from agent.output.console import print_result
from agent.output.json_output import emit_json
from agent.output.exit_codes import calculate_exit_code


VERSION = "0.1.0"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ubuntu Security Posture & Detection Agent"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit output as JSON"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-critical console output"
    )

    parser.add_argument(
        "--fail-on",
        choices=["warning", "critical"],
        default="critical",
        help="Exit with non-zero code on selected severity"
    )

    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if args.version:
        print(VERSION)
        sys.exit(0)

    try:
        result = run(config_path=args.config)
    except Exception as exc:
        print(f"[ERROR] Execution failed: {exc}", file=sys.stderr)
        sys.exit(3)

    if args.json:
        emit_json(result)
    else:
        print_result(result, quiet=args.quiet)

    exit_code = calculate_exit_code(
        result,
        fail_on=args.fail_on
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()