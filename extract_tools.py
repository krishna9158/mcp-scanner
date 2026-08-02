import os
import re

def find_server_files(folder, max_files=None):
    matches = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(".py"):
                matches.append(os.path.join(root, file))
                if max_files is not None and len(matches) >= max_files:
                    return matches
    return matches

def build_enum_value_map(content):
    """
    Finds enum classes like:
        class GitTools(str, Enum):
            STATUS = "git_status"
    and returns a map: {"GitTools.STATUS": "git_status"}
    so tool names written as `name=GitTools.STATUS` can be resolved
    to their real string value.
    """
    enum_map = {}
    class_blocks = re.finditer(
        r'class\s+(\w+)\s*\([^)]*\):\s*\n((?:[ \t]+.*\n?)+)',
        content
    )
    for class_match in class_blocks:
        class_name = class_match.group(1)
        body = class_match.group(2)
        for member_match in re.finditer(r'^\s*(\w+)\s*=\s*["\']([^"\']+)["\']', body, re.MULTILINE):
            member_name, member_value = member_match.groups()
            enum_map[f"{class_name}.{member_name}"] = member_value
    return enum_map


def resolve_name(raw_name, enum_map):
    """raw_name is whatever followed `name=` before the next comma,
    e.g. '"fetch"' or 'GitTools.STATUS' or 'self.tool_name'."""
    raw_name = raw_name.strip()

    quoted = re.match(r'^["\'](.+)["\']$', raw_name)
    if quoted:
        return quoted.group(1)

    if raw_name in enum_map:
        return enum_map[raw_name]

    base = raw_name.rsplit(".value", 1)[0]
    if base in enum_map:
        return enum_map[base]

    return None


def extract_tools_from_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if "Tool(" not in content:
        return []

    enum_map = build_enum_value_map(content)

    tools_found = []
    tool_blocks = re.findall(r'Tool\s*\((.*?)\)\s*,?\s*\n', content, re.DOTALL)

    for block in tool_blocks:
        raw_name_match = re.search(r'name\s*=\s*([^\n,]+),?', block)
        desc_match = re.search(r'description\s*=\s*"""(.*?)"""', block, re.DOTALL)
        if not desc_match:
            desc_match = re.search(r'description\s*=\s*"([^"]+)"', block)

        name = None
        if raw_name_match:
            name = resolve_name(raw_name_match.group(1), enum_map)

        if not name:
            name = "UNKNOWN"

        description = desc_match.group(1).strip() if desc_match else "No description found"

        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description[:200]
        })

    return tools_found

def scan_folder_for_tools(folder, max_files=None):
    all_tools = []
    files = find_server_files(folder, max_files=max_files)
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