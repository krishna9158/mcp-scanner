"""
JS/TypeScript support for the scanner.

A large share of real-world MCP servers are written in JavaScript/
TypeScript (the official MCP SDK ships in both Python and TS), so a
scanner that only reads .py files silently reports "no tools found" on a
huge portion of real repos - not because they're clean, but because it
never actually looked at them. This module gives the scanner the same
two capabilities it already has for Python (find tool definitions, flag
suspicious behavior in their code), just aimed at .js/.ts files instead.

The tool dicts this produces ({file, name, description, code_snippet})
are the same shape extract_tools.py produces for Python, so the rest of
compare.py's pipeline (mismatch checking, risk scoring, Semgrep matching)
treats every tool identically regardless of which language it came from.
"""
import os
import re

JS_TS_EXTENSIONS = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")


def is_test_or_build_path(path):
    """
    Skips test files and build/dependency output, which would otherwise
    flood results with noise or duplicated/vendored code: node_modules is
    other people's installed packages, not this project's own code, and
    dist/build is just compiled output of the same source already scanned.
    """
    normalized = path.replace("\\", "/").lower()
    parts = normalized.split("/")
    if any(part in ("node_modules", "dist", "build", "test", "tests", "__tests__", ".next", "coverage") for part in parts):
        return True
    filename = parts[-1]
    return (
        filename.endswith(".test.js") or filename.endswith(".test.ts") or
        filename.endswith(".spec.js") or filename.endswith(".spec.ts") or
        filename.endswith(".d.ts")  # type declaration files never contain real tool logic
    )


def find_js_ts_files(folder, max_files=None):
    matches = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", "dist", "build", ".next", "coverage", ".git", ".venv", "venv", ".pytest_cache")]
        for file in files:
            if file.endswith(JS_TS_EXTENSIONS):
                filepath = os.path.join(root, file)
                if is_test_or_build_path(filepath):
                    continue
                matches.append(filepath)
                if max_files is not None and len(matches) >= max_files:
                    return matches
    return matches


# --- Tool extraction -----------------------------------------------------

def _extract_balanced_braces(content, start_index, max_length=100000):
    """
    Isolates tool handler blocks in JS/TS by walking matching brace/paren
    depth up to max_length (100k chars) to support large tools in big files.
    """
    depth = 0
    started = False
    end = min(len(content), start_index + max_length)
    for i in range(start_index, end):
        ch = content[i]
        if ch in "({":
            depth += 1
            started = True
        elif ch in ")}":
            depth -= 1
            if started and depth <= 0:
                return content[start_index:i + 1]
    return content[start_index:end]


def extract_tools_from_js_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    if ".tool(" not in content and ".registerTool(" not in content and ".addTool(" not in content and "description" not in content:
        return []

    tools_found = []
    seen_names = set()

    # 1. Matches .tool(...) or .registerTool(...) or .addTool(...)
    call_matches = re.finditer(r'\.(?:tool|registerTool|addTool)\s*\(', content)
    for call_match in call_matches:
        start_idx = call_match.start()
        call_snippet = _extract_balanced_braces(content, start_idx, max_length=100000)

        # Positional string name first: .tool("name", ...)
        pos_match = re.match(
            r'\.(?:tool|registerTool|addTool)\s*\(\s*["\'`]([^"\'`]+)["\'`]',
            call_snippet
        )
        if pos_match:
            name = pos_match.group(1)
            desc = "No description found"
            desc_arg_match = re.match(
                r'\.(?:tool|registerTool|addTool)\s*\(\s*["\'`][^"\'`]+["\'`]\s*,\s*["\'`]([^"\'`]*)["\'`]',
                call_snippet
            )
            if desc_arg_match:
                desc = desc_arg_match.group(1)
            else:
                desc_obj_match = re.search(r'description\s*:\s*["\'`]([^"\'`]*)["\'`]', call_snippet)
                if desc_obj_match:
                    desc = desc_obj_match.group(1)

            if name not in seen_names:
                tools_found.append({
                    "file": filepath,
                    "name": name,
                    "description": desc.strip(),
                    "code_snippet": call_snippet,
                })
                seen_names.add(name)
            continue

        # Options object argument: .tool({ name: "...", description: "..." })
        name_match = re.search(r'name\s*:\s*["\'`]([^"\'`]+)["\'`]', call_snippet)
        desc_match = re.search(r'description\s*:\s*["\'`]([^"\'`]*)["\'`]', call_snippet)
        if name_match:
            name = name_match.group(1)
            desc = desc_match.group(1) if desc_match else "No description found"
            if name not in seen_names:
                tools_found.append({
                    "file": filepath,
                    "name": name,
                    "description": desc.strip(),
                    "code_snippet": call_snippet,
                })
                seen_names.add(name)

    # 2. Raw tool object literals in arrays/variables
    obj_matches = re.finditer(
        r'\{[^{}]*?name\s*:\s*["\'`]([^"\'`]+)["\'`][^{}]*?\}|\{[^{}]*?description\s*:\s*["\'`]([^"\'`]+)["\'`][^{}]*?\}',
        content,
        re.DOTALL
    )
    for obj_match in obj_matches:
        block = obj_match.group(0)
        name_m = re.search(r'name\s*:\s*["\'`]([^"\'`]+)["\'`]', block)
        desc_m = re.search(r'description\s*:\s*["\'`]([^"\'`]*)["\'`]', block)
        if name_m and desc_m:
            name = name_m.group(1)
            if name not in seen_names and name not in ("type", "string", "number", "boolean", "object", "array"):
                desc = desc_m.group(1)
                snippet = _extract_balanced_braces(content, obj_match.start(), max_length=100000)
                tools_found.append({
                    "file": filepath,
                    "name": name,
                    "description": desc.strip(),
                    "code_snippet": snippet,
                })
                seen_names.add(name)

    return tools_found


def scan_folder_for_js_tools(folder, max_files=None):
    all_tools = []
    for filepath in find_js_ts_files(folder, max_files=max_files):
        all_tools.extend(extract_tools_from_js_file(filepath))
    return all_tools



# --- Behavior scanning (JS/TS equivalent of scan_behavior.py) -----------

SUSPICIOUS_PATTERNS_JS = {
    "file_access": [r'\brequire\(\s*["\']fs["\']', r'\bfrom\s+["\']fs["\']', r'\bfs\.', r'\breadFile', r'\bwriteFile', r'\bunlink'],
    "network_access": [r'\bfetch\s*\(', r'\baxios\.', r'\bhttp\.request', r'\bhttps\.request', r'\bXMLHttpRequest', r'\brequire\(\s*["\'](?:http|https|node-fetch)["\']'],
    "subprocess_execution": [r'\bchild_process', r'\bexec\s*\(', r'\bexecSync\s*\(', r'\bspawn\s*\(', r'\bspawnSync\s*\('],
    "environment_access": [r'\bprocess\.env'],
}


def scan_js_text(content):
    findings = []
    for category, patterns in SUSPICIOUS_PATTERNS_JS.items():
        for pattern in patterns:
            if re.search(pattern, content):
                findings.append(category)
                break
    return findings


def scan_js_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []
    return scan_js_text(content)


def scan_js_folder(folder, max_files=None):
    results = {}
    count = 0
    for filepath in find_js_ts_files(folder, max_files=max_files):
        findings = scan_js_file(filepath)
        if findings:
            results[filepath] = findings
        count += 1
        if max_files is not None and count >= max_files:
            break
    return results



if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder: ")
    results = scan_folder_for_js_tools(folder)
    if not results:
        print("No JS/TS tools found.")
    else:
        print(f"\nFound {len(results)} tool(s):\n")
        for tool in results:
            print(f"Tool name: {tool['name']}")
            print(f"Description: {tool['description']}")
            print(f"Found in: {tool['file']}")
            print("-" * 50)
