import os
import re
from extract_tools import is_test_path

SUSPICIOUS_PATTERNS = {
    "file_access": [r'\bopen\s*\(', r'\bos\.remove\(', r'\bos\.rename\(', r'\bshutil\.'],
    "network_access": [r'\brequests\.', r'\burllib\.', r'\bsocket\.', r'\baiohttp\.'],
    "subprocess_execution": [r'\bsubprocess\.', r'\bos\.system\(', r'\bos\.popen\('],
    "environment_access": [r'\bos\.environ'],
}

def scan_text(content):
    findings = []
    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content):
                findings.append(category)
                break
    return findings


def scan_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []
    return scan_text(content)

def scan_folder(folder, max_files=None):
    results = {}
    count = 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in (".git", "node_modules", "dist", "build", "vendor", "third_party", ".pytest_cache", ".venv", "venv", ".next", "coverage")]
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                if is_test_path(filepath):
                    continue
                findings = scan_file(filepath)
                if findings:
                    results[filepath] = findings
                count += 1
                if max_files is not None and count >= max_files:
                    return results
    return results


if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder (e.g. downloaded_repo): ")
    results = scan_folder(folder)
    if not results:
        print("No suspicious patterns found.")
    else:
        print(f"\nFound behavior flags in {len(results)} file(s):\n")
        for filepath, categories in results.items():
            print(f"File: {filepath}")
            print(f"Flags: {', '.join(categories)}")
            print("-" * 50)