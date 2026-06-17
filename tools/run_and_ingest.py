"""Zenux Scan Toolkit: run a scan tool and ingest findings into Zenux.

A thin wrapper around run_all.py with an explicit --ingest-url / --ingest-token
CLI interface instead of requiring environment variables.

Usage:
  # Run one tool
  python run_and_ingest.py --tool 02 --target https://api.example.com \\
      --ingest-url https://security.example.com \\
      --ingest-token "$ZENUX_INGEST_TOKEN"

  # Run all tools
  python run_and_ingest.py --tool all --target https://api.example.com \\
      --ingest-url https://security.example.com \\
      --ingest-token "$ZENUX_INGEST_TOKEN"

Safety disclaimer: For authorized testing only.
"""

from __future__ import annotations

import argparse
import os
import sys


VALID_TOOL_IDS = {
    "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "10", "11", "12", "13",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Zenux scan tool(s) against a target and ingest findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--tool",
        required=True,
        metavar="ID_OR_ALL",
        help="Two-digit tool ID (e.g. 02) or 'all' to run every tool.",
    )
    parser.add_argument("--target", required=True, help="Scan target URL or hostname.")
    parser.add_argument(
        "--ingest-url",
        required=True,
        help="Base URL of the Zenux instance (e.g. https://security.example.com).",
    )
    parser.add_argument(
        "--ingest-token",
        required=True,
        help="Zenux ingest service token.",
    )
    parser.add_argument(
        "--endpoint",
        help="AI endpoint URL for prompt-level tools (defaults to --target).",
    )
    args = parser.parse_args()

    tool_arg = args.tool.lower()
    if tool_arg not in VALID_TOOL_IDS and tool_arg != "all":
        print(
            f"Unknown tool ID '{args.tool}'. "
            f"Valid: {', '.join(sorted(VALID_TOOL_IDS))} or 'all'",
            file=sys.stderr,
        )
        sys.exit(1)

    # Forward to run_all.py via its environment-variable interface
    os.environ["ZENUX_ENDPOINT"] = args.ingest_url
    os.environ["INGEST_SECRET"] = args.ingest_token

    # Import and call run_all directly (avoids subprocess + separate Python process)
    sys.path.insert(0, os.path.dirname(__file__))
    import run_all  # noqa: PLC0415

    # Patch sys.argv so run_all.main() sees the right arguments
    run_all_argv = [
        "run_all.py",
        "--target", args.target,
        "--endpoint", args.endpoint or args.target,
        "--output", "/tmp/run-and-ingest-results",
    ]
    if tool_arg != "all":
        run_all_argv += ["--tools", tool_arg]

    sys.argv = run_all_argv
    run_all.main()


if __name__ == "__main__":
    main()
