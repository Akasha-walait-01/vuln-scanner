"""
cli.py
------
Command-line entry point for Phase 0-1.

Usage:
    python -m scanner.cli --path ./my_project
    python -m scanner.cli --repo https://github.com/psf/requests
"""

import argparse
import sys
from pathlib import Path

from scanner.input_handler import walk_project, clone_repo, is_github_url


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="AI-powered code review & vulnerability scanner (Python).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--path",
        metavar="LOCAL_FOLDER",
        help="Path to a local folder to scan.",
    )
    source.add_argument(
        "--repo",
        metavar="GITHUB_URL",
        help="Public GitHub repository URL to clone and scan.",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """Resolve the input source (local path or GitHub URL) into a list
    of scanned files. Returns a process exit code (0 = success)."""

    if args.path:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            return 1
        files = walk_project(target)
        _print_summary(target, files)
        return 0

    # args.repo case
    if not is_github_url(args.repo):
        print(f"Error: not a valid GitHub repo URL: {args.repo}", file=sys.stderr)
        return 1

    print(f"Cloning {args.repo} ...")
    try:
        with clone_repo(args.repo) as local_path:
            files = walk_project(local_path)
            _print_summary(local_path, files, source_label=args.repo)
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def _print_summary(root: Path, files: list, source_label: str | None = None) -> None:
    label = source_label or str(root)
    print(f"\nScanned source: {label}")
    print(f"Python files found: {len(files)}\n")
    for f in files:
        print(f"  {f.relative_path}  ({f.size_bytes} bytes)")

    if not files:
        print("  (no .py files found -- check the path/excludes)")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    exit_code = run(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()