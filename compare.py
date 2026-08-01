import os
from extract_tools import scan_folder_for_tools
from scan_behavior import scan_folder
from run_semgrep import run_semgrep_scan

EXPECTED_KEYWORDS = {
    "file_access": ["file", "disk", "read", "write", "save", "load"],
    "network_access": ["url", "http", "web", "internet", "fetch", "download", "api", "request"],
    "subprocess_execution": ["run", "execute", "command", "process", "shell"],
    "environment_access": ["environment", "config", "variable", "setting"],
}

def description_mentions_capability(description, category):
    description_lower = description.lower()
    keywords = EXPECTED_KEYWORDS.get(category, [])
    return any(keyword in description_lower for keyword in keywords)


def group_semgrep_findings_by_file(semgrep_results, folder):
    """
    Semgrep reports paths relative to the current working directory
    (not relative to `folder`), since that's what we passed it as the
    scan target. Normalize to absolute paths so lookups by our own
    `tool['file']` (also absolute-ish, from os.walk) match reliably.
    """
    grouped = {}
    for finding in semgrep_results:
        raw_path = finding.get("path", "")
        if not raw_path:
            continue
        abs_path = os.path.normpath(os.path.abspath(raw_path))
        grouped.setdefault(abs_path, []).append({
            "line": finding.get("start", {}).get("line", "?"),
            "message": finding.get("extra", {}).get("message", "No message"),
            "severity": finding.get("extra", {}).get("severity", "INFO"),
        })
    return grouped


def compare(folder, run_semgrep=True):
    tools = scan_folder_for_tools(folder)
    behavior_flags = scan_folder(folder)

    semgrep_by_file = {}
    if run_semgrep:
        semgrep_results = run_semgrep_scan(folder)
        semgrep_by_file = group_semgrep_findings_by_file(semgrep_results, folder)

    report = []

    for tool in tools:
        filepath = tool["file"]
        abs_filepath = os.path.normpath(os.path.abspath(filepath))
        flags_for_file = behavior_flags.get(filepath, [])
        semgrep_findings = semgrep_by_file.get(abs_filepath, [])

        mismatches = []
        for flag in flags_for_file:
            if not description_mentions_capability(tool["description"], flag):
                mismatches.append(flag)

        # Semgrep findings are proven code-level issues, not just
        # description mismatches -> they push severity up on their own.
        has_high_severity_semgrep = any(
            f["severity"] in ("ERROR", "WARNING") for f in semgrep_findings
        )

        if has_high_severity_semgrep or len(mismatches) > 1:
            score = "RED"
        elif len(mismatches) == 1 or semgrep_findings:
            score = "YELLOW"
        else:
            score = "GREEN"

        report.append({
            "name": tool["name"],
            "description": tool["description"],
            "file": filepath,
            "actual_behavior": flags_for_file,
            "mismatches": mismatches,
            "semgrep_findings": semgrep_findings,
            "score": score
        })

    return report

def print_report(report):
    if not report:
        print("No tools found to compare.")
        return

    for entry in report:
        print(f"\nTool: {entry['name']}")
        print(f"Claims to do: {entry['description'][:100]}")
        print(f"Actual behavior detected: {entry['actual_behavior'] or 'None'}")
        print(f"Mismatches: {entry['mismatches'] or 'None'}")
        print(f"Semgrep findings: {entry.get('semgrep_findings') or 'None'}")
        print(f"SCORE: {entry['score']}")
        print("-" * 60)

if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder (e.g. downloaded_repo): ")
    report = compare(folder)
    print_report(report)