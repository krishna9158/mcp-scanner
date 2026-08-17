import ast
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
        dirs[:] = [d for d in dirs if d.lower() not in (".git", "node_modules", "dist", "build", "vendor", "third_party", ".pytest_cache", ".venv", "venv")]
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
    r'@(?:mcp\.tool(?:\s*\([^)]*\))?'
    r'|(?:app|router)\.(?:get|post|put|delete|patch)\s*\([^)]*\))'
    r'\s*\n'
    r'(?:[ \t]*@\w+(?:\([^)]*\))?\s*\n)*'
    r'[ \t]*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^:]+)?:\s*'
    r'(?:\n[ \t]*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'))?',
    re.DOTALL
)


def extract_tools_with_ast(content, filepath):
    """
    Parses Python code with the ast module for 100% accurate tool
    definitions, decorator arguments, docstrings, and code snippets.
    Returns None if parsing fails (syntax error), signaling fallback to regex.
    """
    tools = []
    try:
        tree = ast.parse(content)
    except Exception:
        return None

    enum_map = build_enum_value_map(content)

    for node in ast.walk(tree):
        # 1. Check FunctionDef and AsyncFunctionDef
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_tool = False
            custom_name = None
            custom_desc = None

            for dec in node.decorator_list:
                call_node = None
                target_dec = dec
                if isinstance(target_dec, ast.Call):
                    call_node = target_dec
                    target_dec = target_dec.func

                if isinstance(target_dec, ast.Attribute):
                    dec_name = target_dec.attr
                    val_id = getattr(target_dec.value, "id", "")
                    if dec_name == "tool" or (val_id in ("app", "router") and dec_name in ("get", "post", "put", "delete", "patch")):
                        is_tool = True
                elif isinstance(target_dec, ast.Name):
                    if target_dec.id in ("tool",):
                        is_tool = True

                if is_tool and call_node:
                    for kw in call_node.keywords:
                        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                            custom_name = str(kw.value.value)
                        elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                            custom_desc = str(kw.value.value)

            if is_tool:
                doc = ast.get_docstring(node) or ""
                name = custom_name or node.name
                desc = custom_desc or doc or "No description found"
                try:
                    snippet = ast.get_source_segment(content, node) or ""
                except Exception:
                    snippet = ""
                tools.append({
                    "file": filepath,
                    "name": name,
                    "description": desc.strip(),
                    "code_snippet": snippet
                })

        # 2. Check explicit Tool(...) constructor calls
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name == "Tool":
                name = None
                desc = None
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
                    name = str(node.args[0].value)
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    desc = str(node.args[1].value)

                for kw in node.keywords:
                    if kw.arg == "name":
                        if isinstance(kw.value, ast.Constant):
                            name = str(kw.value.value)
                        elif isinstance(kw.value, ast.Attribute):
                            raw = f"{getattr(kw.value.value, 'id', '')}.{kw.value.attr}"
                            name = resolve_name(raw, enum_map)
                    elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        desc = str(kw.value.value)

                if name or desc:
                    name = name or "UNKNOWN"
                    desc = desc or "No description found"
                    try:
                        snippet = ast.get_source_segment(content, node) or ""
                    except Exception:
                        snippet = ""
                    tools.append({
                        "file": filepath,
                        "name": name,
                        "description": desc.strip(),
                        "code_snippet": snippet
                    })

    return tools


def extract_decorator_tools_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    if "@mcp.tool" not in content and "@app." not in content and "@router." not in content:
        return []

    # Try AST first
    ast_tools = extract_tools_with_ast(content, filepath)
    if ast_tools is not None:
        # Filter to decorator tools (those with code snippets or non-explicit)
        return ast_tools

    tools_found = []
    for match in DECORATOR_PATTERN.finditer(content):
        func_name = match.group(1)
        doc = match.group(2) or match.group(3)

        dec_text = content[match.start():match.start() + match.group(0).find("def ")]
        name_arg = re.search(r'name\s*=\s*["\']([^"\']+)["\']', dec_text)
        desc_arg = re.search(r'description\s*=\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|["\']([^"\']+)["\'])', dec_text, re.DOTALL)

        name = name_arg.group(1) if name_arg else func_name
        description = (desc_arg.group(1) or desc_arg.group(2) or desc_arg.group(3)) if desc_arg else (doc or "No description found")

        def_start = content.find("def ", match.start())
        code_snippet = _extract_function_body(content, def_start) if def_start != -1 else ""

        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description.strip(),
            "code_snippet": code_snippet,
        })

    return tools_found


def extract_tools_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    if "Tool(" not in content:
        return []

    # Try AST first
    ast_tools = extract_tools_with_ast(content, filepath)
    if ast_tools is not None:
        return ast_tools

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
            "description": description
        })

    return tools_found


def scan_folder_for_tools(folder, max_files=None):
    all_tools = []
    files = find_server_files(folder, max_files=max_files)
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        tools = extract_tools_with_ast(content, filepath)
        if tools is not None:
            all_tools.extend(tools)
        else:
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

