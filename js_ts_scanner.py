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
        # Prune noisy/huge directories BEFORE descending into them - far
        # faster than walking into node_modules (which can be tens of
        # thousands of files) and filtering afterwards.
        dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", "dist", "build", ".next", "coverage", ".git")]
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

# Matches the two common ways an MCP tool is registered with the official
# JS/TS SDK:
#   server.tool("name", "description", schema, handler)
#   server.registerTool("name", { title, description: "...", ... }, handler)
TOOL_CALL_PATTERN = re.compile(
    r'\.(?:tool|registerTool)\s*\(\s*'
    r'["\'`]([^"\'`]+)["\'`]'
    r'\s*,\s*'
    r'(?:'
    r'["\'`]([^"\'`]*)["\'`]'
    r'|'
    r'\{[^{}]*?description\s*:\s*["\'`]([^"\'`]*)["\'`]'
    r')',
    re.DOTALL
)

# Matches raw tool object literals some servers build by hand, e.g.:
#   { name: "search", description: "Searches the web", inputSchema: {...} }
RAW_TOOL_OBJECT_PATTERN = re.compile(
    r'\{\s*name\s*:\s*["\'`]([^"\'`]+)["\'`]\s*,\s*description\s*:\s*["\'`]([^"\'`]*)["\'`]',
    re.DOTALL
)


def _extract_balanced_braces(content, start_index, max_length=4000):
    """
    JS/TS has no indentation rule like Python, so isolating "just this
    one tool's code" needs a different approach than extract_tools.py's
    indentation-based function extractor. This walks forward from an
    opening ( or { counting matching brace/paren depth until it returns
    to zero, which marks where this call/block actually ends - capped at
    max_length as a safety limit against unusually large or malformed
    files.
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

    if ".tool(" not in content and ".registerTool(" not in content and "description" not in content:
        return []

    tools_found = []
    seen_names = set()

    for match in TOOL_CALL_PATTERN.finditer(content):
        name = match.group(1)
        description = match.group(2) or match.group(3) or "No description found"
        code_snippet = _extract_balanced_braces(content, match.start())
        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description.strip()[:200],
            "code_snippet": code_snippet,
        })
        seen_names.add(name)

    for match in RAW_TOOL_OBJECT_PATTERN.finditer(content):
        name = match.group(1)
        if name in seen_names:
            continue
        description = match.group(2)
        code_snippet = _extract_balanced_braces(content, match.start())
        tools_found.append({
            "file": filepath,
            "name": name,
            "description": description.strip()[:200],
            "code_snippet": code_snippet,
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
    for filepath in find_js_ts_files(folder, max_files=None):
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
