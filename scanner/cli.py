"""
cli.py
------
Command-line entry point tying together the full pipeline:
    Phase 1 (input handling) -> Phase 2 (AST parsing) ->
    Phase 3 (code quality analysis) + Phase 4/6 (security rules +
    taint tracking) -> Phase 5 (severity/risk scoring) ->
    Phase 7 (HTML report)

Usage:
    python -m scanner.cli --path ./my_project
    python -m scanner.cli --repo https://github.com/psf/requests
    python -m scanner.cli --path ./my_project --output report.html
"""

import argparse
import sys
from pathlib import Path

from scanner.analysis import find_complex_functions, find_dead_code, find_deep_nesting, find_unused_vars
from scanner.input_handler import clone_repo, is_github_url, walk_project
from scanner.parser import parse_project
from scanner.reporter import generate_html_report
from scanner.rules import ALL_RULES
from scanner.severity import calculate_risk_score, risk_level_label, severity_breakdown
from scanner.taint import CommandInjectionTaintTracker


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="AI-powered code review & vulnerability scanner (Python).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", metavar="LOCAL_FOLDER", help="Path to a local folder to scan.")
    source.add_argument("--repo", metavar="GITHUB_URL", help="Public GitHub repository URL to clone and scan.")
    parser.add_argument(
        "--output",
        metavar="REPORT.html",
        default="sample_reports/scan_report.html",
        help="Where to write the HTML report (default: sample_reports/scan_report.html).",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    if args.path:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            return 1
        return _scan_and_report(target, args.path, args.output)

    if not is_github_url(args.repo):
        print(f"Error: not a valid GitHub repo URL: {args.repo}", file=sys.stderr)
        return 1

    print(f"Cloning {args.repo} ...")
    try:
        with clone_repo(args.repo) as local_path:
            return _scan_and_report(local_path, args.repo, args.output)
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _scan_and_report(target: Path, source_label: str, output_path: str) -> int:
    print(f"\nScanning: {source_label}")

    scanned_files = walk_project(target)
    parsed_files = parse_project(scanned_files)
    ok_files = [p for p in parsed_files if p.ok]
    failed_files = [p for p in parsed_files if not p.ok]

    print(f"Files found:         {len(scanned_files)}")
    print(f"Parsed successfully: {len(ok_files)}")
    if failed_files:
        print(f"Failed to parse:     {len(failed_files)}")
        for f in failed_files:
            print(f"  - {f.relative_path}: {f.parse_error}")

    if not ok_files:
        print("No parseable Python files found -- nothing to report.")
        return 0

    # --- Phase 3: code quality analysis ---
    quality_findings = []
    for pf in ok_files:
        quality_findings += find_complex_functions(pf)
        quality_findings += find_unused_vars(pf)
        quality_findings += find_deep_nesting(pf)
        quality_findings += find_dead_code(pf)

    # --- Phase 4 + 6: security rules + taint tracker ---
    security_rules = [rule_cls() for rule_cls in ALL_RULES] + [CommandInjectionTaintTracker()]
    security_findings = []
    for pf in ok_files:
        for rule in security_rules:
            security_findings += rule.check(pf)

    # --- Phase 5: severity / risk score ---
    risk_score = calculate_risk_score(security_findings)
    risk_label = risk_level_label(risk_score)
    breakdown = severity_breakdown(security_findings)

    print(f"\nSecurity findings: {len(security_findings)}  ({breakdown})")
    print(f"Code quality notes: {len(quality_findings)}")
    print(f"Risk score: {risk_score}/100 -- {risk_label}")

    # --- Phase 7: HTML report ---
    report_path = generate_html_report(
        security_findings=security_findings,
        quality_findings=quality_findings,
        scanned_file_count=len(ok_files),
        source_label=source_label,
        output_path=output_path,
    )
    print(f"\nReport written to: {report_path.resolve()}")
    return 0


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()