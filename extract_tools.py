import os
import re

def find_server_files(folder):
    matches = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(".py"):
                matches.append(os.path.join(root, file))
    return matches

def extract_tools_from_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if "Tool(" not in content:
        return []

    tools_found = []
    tool_blocks = re.findall(r'Tool\s*\((.*?)\)\s*,?\s*\n', content, re.DOTALL)

    for block in tool_blocks:
        name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
        desc_match = re.search(r'description\s*=\s*"""(.*?)"""', block, re.DOTALL)
        if not desc_match:
            desc_match = re.search(r'description\s*=\s*"([^"]+)"', block)

        name = name_match.group(1) if name_match else "UNKNOWN"
        description = desc_match.group(1).strip() if desc_match else "No description found"

        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description[:200]
        })

    return tools_found

def scan_folder_for_tools(folder):
    all_tools = []
    files = find_server_files(folder)
    for filepath in files:
        tools = extract_tools_from_file(filepath)
        all_tools.extend(tools)
    return all_tools

if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder (e.g. downloaded_repo): ")
    results = scan_folder_for_tools(folder)

    if not results:
        print("No tools found.")
    else:
        print(f"\nFound {len(results)} tool(s):\n")
        for tool in results:
            print(f"Tool name: {tool['name']}")
            print(f"Description: {tool['description']}")
            print(f"Found in: {tool['file']}")
            print("-" * 50)