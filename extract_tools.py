import os
import re

def is_test_path(path):
    normalized = path.replace("\\", "/").lower()
    parts = normalized.split("/")
    if any(part in ("test", "tests", "testing") for part in parts):
        return True
    filename = parts[-1]
    return filename.startswith("test_") or filename.endswith("_test.py") or filename == "conftest.py"


def find_server_files(folder, max_files=None):
    matches = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                if is_test_path(filepath):
                    continue
                matches.append(filepath)
                if max_files is not None and len(matches) >= max_files:
                    return matches
    return matches

def build_enum_value_map(content):
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


def _extract_function_body(content, def_line_start_index):
    remainder = content[def_line_start_index:]
    lines = remainder.split("\n")
    body_lines = [lines[0]]
    for line in lines[1:]:
        if line.strip() == "":
            body_lines.append(line)
            continue
        if line[0] not in (" ", "\t"):
            break
        body_lines.append(line)
    return "\n".join(body_lines)


DECORATOR_PATTERN = re.compile(
    r'@(?:mcp\.tool\s*\([^)]*\)'
    r'|(?:app|router)\.(?:get|post|put|delete|patch)\s*\([^)]*\))'
    r'\s*\n'
    r'(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^:]+)?:\s*\n'
    r'\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\')?',
    re.DOTALL
)


def extract_decorator_tools_from_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if "@mcp.tool" not in content and "@app." not in content and "@router." not in content:
        return []

    tools_found = []
    for match in DECORATOR_PATTERN.finditer(content):
        name = match.group(1)
        description = match.group(2) or match.group(3)
        description = description.strip() if description else "No description found"

        def_start = content.find("def ", match.start())
        code_snippet = _extract_function_body(content, def_start) if def_start != -1 else ""

        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description[:200],
            "code_snippet": code_snippet,
        })

    return tools_found


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

        if not name and not desc_match:
            continue

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
        explicit_tools = extract_tools_from_file(filepath)
        decorator_tools = extract_decorator_tools_from_file(filepath)

        all_tools.extend(explicit_tools)

        seen_names = {t["name"] for t in explicit_tools}
        for tool in decorator_tools:
            if tool["name"] not in seen_names:
                all_tools.append(tool)

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
