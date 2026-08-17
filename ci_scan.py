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
    python ci_scan.py /path/to/repo/to/scan --fail-on RED

    # Fine-grained thresholds (Feature 5):
    python ci_scan.py /path/to/repo \
        --fail-on-secret CRITICAL \
        --fail-on-dependency HIGH \
        --fail-on-typosquat MEDIUM \
        --fail-on-tool RED
"""
import argparse
import json
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from compare import compare

from secret_detector import scan_folder_for_secrets
from dependency_check import scan_dependencies, parse_requirements_txt
from typosquat_check import scan_requirements_for_typosquatting

# Severity rank: higher = worse
SEVERITY_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "RED": 4,
    "YELLOW": 2,
}


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


def severity_meets_threshold(finding_severity, threshold):
    """
    Check if a finding's severity meets or exceeds the configured threshold.
    """
    rank = SEVERITY_RANK.get(finding_severity, 0)
    threshold_rank = SEVERITY_RANK.get(threshold, 0)
    return rank >= threshold_rank


def evaluate_findings_against_thresholds(report, secrets, dependencies, typosquats, thresholds):
    """
    Fine-grained evaluation: check each finding category against its own
    severity threshold. Returns a dict of category -> (pass/fail, details).
    """
    results = {}

    # Overall score check
    overall = compute_overall_score(report, secrets, dependencies, typosquats)
    results["overall"] = {
        "passed": not severity_meets_threshold(overall, thresholds.get("overall", "RED")),
        "score": overall,
        "threshold": thresholds.get("overall", "RED"),
    }

    # Secret findings: each secret has a confidence level mapped to severity
    secret_threshold = thresholds.get("secret", "HIGH")
    secret_failures = []
    for s in (secrets or []):
        conf = s.get("confidence", "LOW")
        if severity_meets_threshold(conf, secret_threshold):
            secret_failures.append(s)
    results["secrets"] = {
        "passed": len(secret_failures) == 0,
        "failed_count": len(secret_failures),
        "threshold": secret_threshold,
        "failures": secret_failures,
    }

    # Dependency vulnerabilities: use the worst severity found
    dep_threshold = thresholds.get("dependency", "HIGH")
    dep_failures = []
    for dep in (dependencies or {}).get("findings", []):
        for vuln in dep.get("vulnerabilities", []):
            vuln_severity = vuln.get("severity", "MEDIUM")
            if severity_meets_threshold(vuln_severity, dep_threshold):
                dep_failures.append({"package": dep.get("package"), "vuln": vuln})
                break  # one failing vuln per package is enough
    results["dependencies"] = {
        "passed": len(dep_failures) == 0,
        "failed_count": len(dep_failures),
        "threshold": dep_threshold,
        "failures": dep_failures,
    }

    # Typosquats: always fail if any exist (they're always a risk)
    typo_threshold = thresholds.get("typosquat", "LOW")
    typo_failures = typosquats or []
    results["typosquats"] = {
        "passed": len(typo_failures) == 0 or not severity_meets_threshold("MEDIUM", typo_threshold),
        "failed_count": len(typo_failures),
        "threshold": typo_threshold,
        "failures": typo_failures,
    }

    # Tool findings: check each tool's score + injection/shadowing severity
    tool_threshold = thresholds.get("tool", "YELLOW")
    tool_failures = []
    for entry in (report or []):
        if severity_meets_threshold(entry.get("score", "GREEN"), tool_threshold):
            tool_failures.append(entry)
        # Also check injection findings severity
        for inj in entry.get("injection_findings", []):
            if severity_meets_threshold(inj.get("severity", "MEDIUM"), thresholds.get("injection", "MEDIUM")):
                if entry not in tool_failures:
                    tool_failures.append(entry)
                break
        # Check shadowing findings severity
        for shad in entry.get("shadowing_findings", []):
            if severity_meets_threshold(shad.get("severity", "HIGH"), thresholds.get("shadowing", "HIGH")):
                if entry not in tool_failures:
                    tool_failures.append(entry)
                break
    results["tools"] = {
        "passed": len(tool_failures) == 0,
        "failed_count": len(tool_failures),
        "threshold": tool_threshold,
        "failures": tool_failures,
    }

    # Overall pass/fail
    any_failed = any(not v.get("passed", True) for v in results.values())
    results["all_passed"] = not any_failed

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan a local MCP server repo for security issues (CI-friendly)."
    )
    parser.add_argument("path", help="Path to the already-checked-out repo to scan.")
    parser.add_argument("--full-scan", action="store_true", help="Scan every file with no limit.")
    parser.add_argument("--json-out", help="Write full JSON results to this file.")
    parser.add_argument(
        "--fail-on", default="RED", choices=["RED", "YELLOW", "NEVER"],
        help="Exit with a non-zero code if overall score is at least this severe. Default: RED.",
    )
    # Fine-grained thresholds (Feature 5)
    parser.add_argument(
        "--fail-on-secret", default="HIGH",
        choices=sorted(SEVERITY_RANK.keys()),
        help="Minimum secret confidence to fail on. Default: HIGH.",
    )
    parser.add_argument(
        "--fail-on-dependency", default="HIGH",
        choices=sorted(SEVERITY_RANK.keys()),
        help="Minimum dependency vulnerability severity to fail on. Default: HIGH.",
    )
    parser.add_argument(
        "--fail-on-typosquat", default="LOW",
        choices=sorted(SEVERITY_RANK.keys()),
        help="Minimum severity for typosquat findings to fail on. Default: LOW.",
    )
    parser.add_argument(
        "--fail-on-tool", default="YELLOW",
        choices=["GREEN", "YELLOW", "RED"],
        help="Minimum tool score to fail on. Default: YELLOW.",
    )
    parser.add_argument(
        "--fail-on-injection", default="MEDIUM",
        choices=sorted(SEVERITY_RANK.keys()),
        help="Minimum injection finding confidence to fail on. Default: MEDIUM.",
    )
    parser.add_argument(
        "--fail-on-shadowing", default="HIGH",
        choices=sorted(SEVERITY_RANK.keys()),
        help="Minimum shadowing finding severity to fail on. Default: HIGH.",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a directory.", file=sys.stderr)
        sys.exit(2)

    report, warning = compare(args.path, full_scan=args.full_scan)
    secrets = scan_folder_for_secrets(args.path, max_files=None if args.full_scan else 5000)
    dependencies = scan_dependencies(args.path, max_packages=100 if args.full_scan else 30)


    typosquats = []
    req_path = os.path.join(args.path, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                packages = parse_requirements_txt(f.read())
            typosquats = scan_requirements_for_typosquatting([name for name, _version in packages])
        except Exception:
            pass  # typosquat check is a bonus signal

    overall_score = compute_overall_score(report, secrets, dependencies, typosquats)

    # Build fine-grained thresholds dict
    thresholds = {
        "overall": args.fail_on,
        "secret": args.fail_on_secret,
        "dependency": args.fail_on_dependency,
        "typosquat": args.fail_on_typosquat,
        "tool": args.fail_on_tool,
        "injection": args.fail_on_injection,
        "shadowing": args.fail_on_shadowing,
    }

    # Fine-grained fail: skip when --fail-on NEVER (meaning: never fail the build)
    evaluation = None
    if args.fail_on != "NEVER":
        evaluation = evaluate_findings_against_thresholds(
            report, secrets, dependencies, typosquats, thresholds
        )

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

    # Print per-category results
    if evaluation:
        print(f"\n--- Threshold evaluation ---")
        for category, data in evaluation.items():
            if category == "all_passed":
                continue
            status = "PASS" if data["passed"] else "FAIL"
            threshold = data.get("threshold", "N/A")
            if "failed_count" in data:
                print(f"  [{status}] {category}: threshold={threshold}, failures={data['failed_count']}")
            else:
                print(f"  [{status}] {category}: score={data.get('score', 'N/A')}, threshold={threshold}")

    if args.json_out:
        output = {
            "overall_score": overall_score,
            "warning": warning,
            "report": report,
            "secrets": secrets,
            "dependencies": dependencies,
            "typosquats": typosquats,
            "thresholds": thresholds,
        }
        if evaluation:
            output["evaluation"] = {k: v for k, v in evaluation.items() if k != "all_passed"}
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"\nFull results written to {args.json_out}")

    # Legacy fail-on (overall score only) for backward compatibility
    severity_rank = {"GREEN": 0, "UNKNOWN": 0, "YELLOW": 1, "RED": 2}
    fail_threshold = {"RED": 2, "YELLOW": 1, "NEVER": 99}[args.fail_on]

    if severity_rank.get(overall_score, 0) >= fail_threshold:
        print(f"\nFailing build: overall score {overall_score} meets --fail-on={args.fail_on} threshold.")
        sys.exit(1)

    # Fine-grained fail: if any category failed its threshold
    if evaluation and not evaluation["all_passed"]:
        print("\nFailing build: one or more finding categories exceed their configured threshold.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()