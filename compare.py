import os
from extract_tools import scan_folder_for_tools, find_server_files
from scan_behavior import scan_folder, scan_text
from js_ts_scanner import scan_folder_for_js_tools, find_js_ts_files, scan_js_folder, scan_js_text, JS_TS_EXTENSIONS
from run_semgrep import run_semgrep_scan
from semantic_check import semantic_check_available, verify_mismatch_with_llm
from risk_classifier import classify_tool_risk
from prompt_injection_check import check_description_for_injection
from tool_shadowing_check import scan_tools_for_shadowing
from impact_guide import get_capability_impact, get_risk_prevention, INJECTION_IMPACT, SHADOWING_IMPACT

# Tool/description scanning is cheap (just reads files and runs regex), so
# it can handle a much larger repo before it's worth worrying about. This
# limit is applied to Python and JS/TS files separately (each language
# gets its own budget), since a repo could be almost entirely one
# language or a genuine mix of both.
MAX_FILES_FOR_TOOL_SCAN = 5000

# Semgrep is the truly slow part (deep static analysis per file), so it
# needs a smaller, safer limit to avoid the whole request running too long.
#
# This was raised to 2000 at one point on the theory that the 300-second
# process-level timeout would safely catch anything that ran too long -
# but that was tested directly against a real large repo
# (awslabs/mcp, 2000+ files) and it genuinely hit the full 5-minute
# timeout with ZERO results returned, since the whole scan is one
# all-or-nothing unit up to that point. Brought back down to 350, which
# was tested and confirmed to complete quickly by skipping Semgrep (with
# a clear warning) instead of gambling the whole scan on it finishing in
# time. This is checked against the COMBINED Python + JS/TS file count,
# since Semgrep scans both.
MAX_FILES_FOR_SEMGREP = 350

# Cap on how many LLM verification calls one scan can make.
MAX_LLM_VERIFICATIONS_PER_SCAN = 20

EXPECTED_KEYWORDS = {
    "file_access": ["file", "disk", "read", "write", "save", "load"],
    "network_access": ["url", "http", "web", "internet", "fetch", "download", "api", "request"],
    "subprocess_execution": ["run", "execute", "command", "process", "shell"],
    "environment_access": ["environment", "config", "variable", "setting"],
}

CAPABILITY_SEVERITY = {
    "environment_access": "HIGH",
    "subprocess_execution": "HIGH",
    "network_access": "MEDIUM",
    "file_access": "LOW",
}

def description_mentions_capability(description, category):
    description_lower = description.lower()
    keywords = EXPECTED_KEYWORDS.get(category, [])
    return any(keyword in description_lower for keyword in keywords)


def group_semgrep_findings_by_file(semgrep_results, folder):
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


def _is_js_file(filepath):
    return filepath.lower().endswith(JS_TS_EXTENSIONS)


def compare(folder, run_semgrep=True, full_scan=False):
    warning = None

    if full_scan:
        tools = scan_folder_for_tools(folder)
        behavior_flags = scan_folder(folder)
        js_tools = scan_folder_for_js_tools(folder)
        js_behavior_flags = scan_js_folder(folder)
    else:
        sample_files = find_server_files(folder, max_files=MAX_FILES_FOR_TOOL_SCAN + 1)
        js_sample_files = find_js_ts_files(folder, max_files=MAX_FILES_FOR_TOOL_SCAN + 1)
        py_file_count = len(sample_files)
        js_file_count = len(js_sample_files)
        combined_file_count = py_file_count + js_file_count

        tool_scan_capped = py_file_count > MAX_FILES_FOR_TOOL_SCAN or js_file_count > MAX_FILES_FOR_TOOL_SCAN
        semgrep_too_large = combined_file_count > MAX_FILES_FOR_SEMGREP

        tools = scan_folder_for_tools(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)
        behavior_flags = scan_folder(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)
        js_tools = scan_folder_for_js_tools(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)
        js_behavior_flags = scan_js_folder(folder, max_files=MAX_FILES_FOR_TOOL_SCAN)

        if semgrep_too_large:
            run_semgrep = False

        if tool_scan_capped:
            warning = (
                f"This repo has more than {MAX_FILES_FOR_TOOL_SCAN} files in one "
                f"language - only the first {MAX_FILES_FOR_TOOL_SCAN} of that "
                f"language were scanned for tools, and Semgrep was skipped "
                f"entirely. Try a smaller/more focused MCP server repo for a "
                f"fully complete scan."
            )
        elif semgrep_too_large:
            warning = (
                f"This repo has more than {MAX_FILES_FOR_SEMGREP} Python + JS/TS "
                f"files combined, so Semgrep was skipped to avoid timing out "
                f"(tool names/descriptions were still scanned across up to "
                f"{MAX_FILES_FOR_TOOL_SCAN} files per language)."
            )

    # Merge Python and JS/TS results into one unified list/dict so the
    # rest of the pipeline (mismatch checking, risk scoring, Semgrep
    # matching, prompt-injection checking) treats every tool the same way
    # regardless of which language it was found in.
    tools = tools + js_tools
    behavior_flags = {**behavior_flags, **js_behavior_flags}

    # Tool-shadowing findings are computed once across the WHOLE repo (not
    # per-tool) since duplicate-name detection needs to see every tool at
    # once - then grouped by name so each tool's report entry can look up
    # just the findings that concern it.
    shadowing_findings_by_name = {}
    for finding in scan_tools_for_shadowing(tools):
        shadowing_findings_by_name.setdefault(finding["tool"], []).append(finding)

    semgrep_by_file = {}
    if run_semgrep:
        semgrep_results = run_semgrep_scan(folder)
        semgrep_by_file = group_semgrep_findings_by_file(semgrep_results, folder)

    report = []
    llm_calls_used = 0
    llm_available = semantic_check_available()

    for tool in tools:
        filepath = tool["file"]
        abs_filepath = os.path.normpath(os.path.abspath(filepath))
        semgrep_findings = semgrep_by_file.get(abs_filepath, [])
        is_js = _is_js_file(filepath)

        if tool.get("code_snippet"):
            flags_for_file = scan_js_text(tool["code_snippet"]) if is_js else scan_text(tool["code_snippet"])
        else:
            flags_for_file = behavior_flags.get(filepath, [])

        mismatches = []
        for flag in flags_for_file:
            if not description_mentions_capability(tool["description"], flag):
                mismatches.append(flag)

        semantic_notes = []
        if llm_available and mismatches:
            code_for_check = tool.get("code_snippet", "")
            confirmed_mismatches = []
            for flag in mismatches:
                if llm_calls_used >= MAX_LLM_VERIFICATIONS_PER_SCAN:
                    confirmed_mismatches.append(flag)
                    continue
                result = verify_mismatch_with_llm(tool["name"], tool["description"], flag, code_for_check)
                llm_calls_used += 1
                semantic_notes.append({"category": flag, **result})
                if not result["covered"]:
                    confirmed_mismatches.append(flag)
            mismatches = confirmed_mismatches

        has_high_severity_semgrep = any(
            f["severity"] in ("ERROR", "WARNING") for f in semgrep_findings
        )

        mismatch_severities = {CAPABILITY_SEVERITY.get(m, "LOW") for m in mismatches}

        # Inherent risk classification: independent of whether the
        # description matches the code. A tool honestly named and
        # described as "delete_all_records" is still a CRITICAL-risk tool
        # to expose to an AI agent, even with zero mismatch - an honest
        # description doesn't make a dangerous action safe.
        risk_info = classify_tool_risk(tool["name"], tool["description"])

        # Prompt-injection ("tool poisoning") check: does this tool's own
        # description contain hidden instructions aimed at the AI agent
        # reading it, rather than documentation for a human? This is
        # independent of everything else above - a tool can have perfectly
        # matched, low-risk behavior and still be actively malicious via
        # its description alone.
        injection_findings = check_description_for_injection(tool["name"], tool["description"])

        # Tool-shadowing findings for this specific tool, looked up from
        # the whole-repo pass computed above.
        shadowing_findings = shadowing_findings_by_name.get(tool["name"], [])

        if injection_findings or shadowing_findings or has_high_severity_semgrep or "HIGH" in mismatch_severities or risk_info["risk_level"] == "CRITICAL":
            score = "RED"
        elif "MEDIUM" in mismatch_severities or risk_info["risk_level"] == "HIGH":
            score = "YELLOW"
        elif "LOW" in mismatch_severities or semgrep_findings or risk_info["risk_level"] == "MEDIUM":
            score = "YELLOW"
        else:
            score = "GREEN"

        report.append({
            "name": tool["name"],
            "description": tool["description"],
            "file": filepath,
            "language": "JS/TS" if is_js else "Python",
            "actual_behavior": flags_for_file,
            "mismatches": mismatches,
            "mismatch_impacts": [
                {"category": m, **(get_capability_impact(m) or {})} for m in mismatches
            ],
            "semgrep_findings": semgrep_findings,
            "semantic_notes": semantic_notes,
            "risk_level": risk_info["risk_level"],
            "risk_explanation": risk_info["explanation"],
            "risk_prevention": get_risk_prevention(risk_info["risk_level"]),
            "injection_findings": injection_findings,
            "injection_impact": INJECTION_IMPACT if injection_findings else None,
            "shadowing_findings": shadowing_findings,
            "shadowing_impact": SHADOWING_IMPACT if shadowing_findings else None,
            "score": score
        })

    return report, warning

def print_report(report):
    if not report:
        print("No tools found to compare.")
        return

    for entry in report:
        print(f"\nTool: {entry['name']} ({entry.get('language', 'Python')})")
        print(f"Claims to do: {entry['description'][:100]}")
        print(f"Risk level: {entry.get('risk_level', 'UNKNOWN')}")
        print(f"Actual behavior detected: {entry['actual_behavior'] or 'None'}")
        print(f"Mismatches: {entry['mismatches'] or 'None'}")
        print(f"Semgrep findings: {entry.get('semgrep_findings') or 'None'}")
        if entry.get("injection_findings"):
            print(f"⚠ Prompt-injection findings: {entry['injection_findings']}")
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
