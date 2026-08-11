"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import Severity
from .reporting import render_json, render_sarif, render_text
from .scanner import ScanOptions, scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-repo-guard",
        description="Scan AI agent instructions and repository automation for security risks.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="files or directories to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="return exit code 2 at or above this severity (default: high)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="additional ignore pattern; may be repeated",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1_000_000,
        metavar="BYTES",
        help="skip files larger than this size",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = scan_paths(
        args.paths,
        options=ScanOptions(max_file_size=args.max_file_size, excludes=args.exclude),
    )
    renderers = {"text": render_text, "json": render_json, "sarif": render_sarif}
    report = renderers[args.format](findings)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 2 if any(item.severity >= threshold for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
