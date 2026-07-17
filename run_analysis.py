"""
run_analysis.py
----------------
Ties Phase 1 (input handling) + Phase 2 (AST parsing) + Phase 3 (code
quality analysis) together into one end-to-end run, so the whole
pipeline can be pointed at a local folder or a GitHub repo URL and
print a combined report.

Usage:
    python run_analysis.py --path C:\\some\\folder
    python run_analysis.py --repo https://github.com/pallets/flask
"""

import argparse
from contextlib import contextmanager
from pathlib import Path

from scanner.input_handler import walk_project, clone_repo, is_github_url
from scanner.parser import parse_project
from scanner.analysis import (
    find_complex_functions,
    find_unused_vars,
    find_deep_nesting,
    find_dead_code,
)


@contextmanager
def resolve_source(path: str = None, repo: str = None):
    """Yield a local folder path for either a --path or a --repo input,
    using the same clone-then-cleanup pattern as scanner/cli.py."""
    if path:
        yield Path(path)
    else:
        with clone_repo(repo) as local_path:
            yield local_path


def main():
    parser = argparse.ArgumentParser(description="Run Phase 1-3 pipeline on a project.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", metavar="LOCAL_FOLDER")
    group.add_argument("--repo", metavar="GITHUB_URL")
    args = parser.parse_args()

    with resolve_source(path=args.path, repo=args.repo) as source_path:
        print(f"Scanning: {args.path or args.repo}\n")

        scanned_files = walk_project(source_path)
        parsed_files = parse_project(scanned_files)
        ok_files = [p for p in parsed_files if p.ok]
        failed_files = [p for p in parsed_files if not p.ok]

        print(f"Files found:        {len(scanned_files)}")
        print(f"Parsed successfully: {len(ok_files)}")
        print(f"Failed to parse:     {len(failed_files)}")
        for f in failed_files:
            print(f"   - {f.relative_path}: {f.parse_error}")

        all_findings = []
        for pf in ok_files:
            all_findings += find_complex_functions(pf)
            all_findings += find_unused_vars(pf)
            all_findings += find_deep_nesting(pf)
            all_findings += find_dead_code(pf)

        by_check = {}
        for finding in all_findings:
            by_check.setdefault(finding.check, []).append(finding)

        print(f"\nTotal findings: {len(all_findings)}")
        for check_name, findings in by_check.items():
            print(f"  {check_name}: {len(findings)}")

        print("\n--- Top 15 findings ---")
        for finding in all_findings[:15]:
            print(f"  [{finding.check}] {finding.file_path}:{finding.line} - {finding.message}")


if __name__ == "__main__":
    main()