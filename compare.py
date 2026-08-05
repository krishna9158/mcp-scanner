import os
from extract_tools import scan_folder_for_tools, find_server_files
from scan_behavior import scan_folder, scan_text
from run_semgrep import run_semgrep_scan

# Tool/description scanning is cheap (just reads files and runs regex), so
# it can handle a much larger repo before it's worth worrying about.
MAX_FILES_FOR_TOOL_SCAN = 2000

# Semgrep is the truly slow part (deep static analysis per file), so it
# needs a smaller, safer limit to avoid the whole request running too long.
# (Semgrep also has its own internal timeout in run_semgrep.py as a backup
# safety net, in case a repo with fewer files than this still runs slow.)
MAX_FILES_FOR_SEMGREP = 350

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


def compare(folder, run_semgrep=True, full_scan=False):
    warning = None

    if full_scan:
        # Deliberately no limits - only use this for local/CLI runs where
        # you control the machine and are willing to wait. Never expose
        # this on the public web app: an unlimited scan on a huge repo
        # could hang the server for every visitor, not just you.
        tools = scan_folder_for_tools(folder)
        behavior_flags = scan_folder(folder)
    else:
        # Fast pre-check: count files up to the higher tool-scan limit, without
        # reading their contents, to decide how much of this repo we can afford
        # to look at.
        sample_files = find_server_files(folder, max_files=MAX_FILES_FOR_TOOL_SCAN + 1)
        file_count = len(sample_files)
        tool_scan_capped = file_count > MAX_FILES_FOR_TOOL_SCAN
        semgrep_too_large = file_count > MAX_FILES_FOR_SEMGREP

        if tool_scan_capped:
            tools = scan_folder_for_tools(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)
            behavior_flags = scan_folder(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)
        else:
            tools = scan_folder_for_tools(folder)
            behavior_flags = scan_folder(folder)

        if semgrep_too_large:
            run_semgrep = False

        if tool_scan_capped:
            warning = (
                f"This repo has more than {MAX_FILES_FOR_TOOL_SCAN} Python files - "
                f"only the first {MAX_FILES_FOR_TOOL_SCAN} were scanned for tools, "
                f"and Semgrep was skipped entirely. Try a smaller/more focused "
                f"MCP server repo for a fully complete scan."
            )
        elif semgrep_too_large:
            warning = (
                f"This repo has more than {MAX_FILES_FOR_SEMGREP} Python files, so "
                f"Semgrep was skipped to avoid timing out (tool names/descriptions "
                f"were still scanned across up to {MAX_FILES_FOR_TOOL_SCAN} files)."
            )

    semgrep_by_file = {}
    if run_semgrep:
        semgrep_results = run_semgrep_scan(folder)
        semgrep_by_file = group_semgrep_findings_by_file(semgrep_results, folder)

    report = []

    for tool in tools:
        filepath = tool["file"]
        abs_filepath = os.path.normpath(os.path.abspath(filepath))
        semgrep_findings = semgrep_by_file.get(abs_filepath, [])

        if tool.get("code_snippet"):
            # Decorator-style tool: we know exactly which function
            # implements it, so check behavior against just that function's
            # code instead of the whole file.
            flags_for_file = scan_text(tool["code_snippet"])
        else:
            # Explicit Tool(...) style: the tool's registration and its
            # actual implementation are often in different places in the
            # file, so we fall back to file-level behavior checking here.
            # This is coarser and can occasionally attribute another
            # function's behavior to this tool - a known limitation.
            flags_for_file = behavior_flags.get(filepath, [])

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

    return report, warning

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
    choice = input("Scan ALL files with no limit? This may take a while on huge repos. (y/N): ")
    full_scan = choice.strip().lower() == "y"

    report, warning = compare(folder, full_scan=full_scan)
    if warning:
        print(f"\n⚠ {warning}\n")
    print_report(report)