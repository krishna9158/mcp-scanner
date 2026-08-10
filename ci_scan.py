"""
CI-friendly entry point for the scanner.

The web app clones a GitHub URL before scanning, which makes sense for
someone pasting a link into a browser - but in a CI pipeline, the repo
being scanned is already checked out on disk by the CI system itself.
This script scans a local folder directly instead, and exits with a
non-zero code when the result is bad enough - so a CI job can genuinely
FAIL the build on serious findings, not just print a report nobody reads.

Usage:
    python ci_scan.py /path/to/repo/to/scan
    python ci_scan.py /path/to/repo/to/scan --full-scan
    python ci_scan.py /path/to/repo/to/scan --json-out results.json
    python ci_scan.py /path/to/repo/to/scan --fail-on YELLOW
"""
import argparse
import json
import os
import sys

from compare import compare
from secret_detector import scan_folder_for_secrets
from dependency_check import scan_dependencies, parse_requirements_txt
from typosquat_check import scan_requirements_for_typosquatting


def compute_overall_score(report, secrets, dependencies, typosquats):
    if secrets:
        return "RED"
    if dependencies and dependencies.get("findings"):
        return "RED"
    if typosquats:
        return "RED"
    if report:
        scores = {entry["score"] for entry in report}
        if "RED" in scores:
            return "RED"
        if "YELLOW" in scores:
            return "YELLOW"
        return "GREEN"
    return "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(
        description="Scan a local MCP server repo for security issues (CI-friendly - no cloning, exits non-zero on bad results)."
    )
    parser.add_argument("path", help="Path to the already-checked-out repo to scan.")
    parser.add_argument("--full-scan", action="store_true", help="Scan every file with no limit.")
    parser.add_argument("--json-out", help="Write full JSON results to this file.")
    parser.add_argument(
        "--fail-on", default="RED", choices=["RED", "YELLOW", "NEVER"],
        help="Exit with a non-zero code if the overall score is at least this severe. Default: RED."
    )
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory.", file=sys.stderr)
        sys.exit(2)

    report, warning = compare(args.path, full_scan=args.full_scan)
    secrets = scan_folder_for_secrets(args.path)
    dependencies = scan_dependencies(args.path, max_packages=30)

    typosquats = []
    req_path = os.path.join(args.path, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                packages = parse_requirements_txt(f.read())
            typosquats = scan_requirements_for_typosquatting([name for name, _version in packages])
        except Exception:
            pass  # typosquat check is a bonus signal - never let it block a scan

    overall_score = compute_overall_score(report, secrets, dependencies, typosquats)

    print(f"\n=== MCP Security Scan: {overall_score} ===")
    if warning:
        print(f"⚠ {warning}")
    print(f"Tools scanned: {len(report)}")

    red_tools = [entry for entry in report if entry["score"] == "RED"]
    if red_tools:
        print(f"RED tools: {', '.join(t['name'] for t in red_tools)}")
    if secrets:
        print(f"Possible secrets found: {len(secrets)}")
    if dependencies.get("findings"):
        print(f"Vulnerable dependencies: {len(dependencies['findings'])}")
    if typosquats:
        print(f"Possible typosquatted packages: {len(typosquats)}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({
                "overall_score": overall_score,
                "warning": warning,
                "report": report,
                "secrets": secrets,
                "dependencies": dependencies,
                "typosquats": typosquats,
            }, f, indent=2)
        print(f"Full results written to {args.json_out}")

    severity_rank = {"GREEN": 0, "UNKNOWN": 0, "YELLOW": 1, "RED": 2}
    fail_threshold = {"RED": 2, "YELLOW": 1, "NEVER": 99}[args.fail_on]

    if severity_rank.get(overall_score, 0) >= fail_threshold:
        print(f"\nFailing build: overall score {overall_score} meets --fail-on={args.fail_on} threshold.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
