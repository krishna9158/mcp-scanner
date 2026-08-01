from extract_tools import scan_folder_for_tools
from scan_behavior import scan_folder

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

def compare(folder):
    tools = scan_folder_for_tools(folder)
    behavior_flags = scan_folder(folder)

    report = []

    for tool in tools:
        filepath = tool["file"]
        flags_for_file = behavior_flags.get(filepath, [])

        mismatches = []
        for flag in flags_for_file:
            if not description_mentions_capability(tool["description"], flag):
                mismatches.append(flag)

        if len(mismatches) == 0:
            score = "GREEN"
        elif len(mismatches) <= 1:
            score = "YELLOW"
        else:
            score = "RED"

        report.append({
            "name": tool["name"],
            "description": tool["description"],
            "file": filepath,
            "actual_behavior": flags_for_file,
            "mismatches": mismatches,
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
        print(f"SCORE: {entry['score']}")
        print("-" * 60)

if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder (e.g. downloaded_repo): ")
    report = compare(folder)
    print_report(report)