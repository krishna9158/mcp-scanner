import json
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

OSV_API_URL = "https://api.osv.dev/v1/query"
DEPENDENCY_CHECK_TIME_BUDGET_SECONDS = 25


def parse_requirements_txt(content):
    """Parses pinned dependencies from requirements.txt."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r'^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)', line)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def parse_package_json(content):
    """Parses dependencies from package.json or package-lock.json."""
    packages = []
    try:
        data = json.loads(content)
    except Exception:
        return packages

    # Check dependencies & devDependencies in package.json
    for dep_key in ("dependencies", "devDependencies"):
        deps = data.get(dep_key, {})
        if isinstance(deps, dict):
            for name, ver in deps.items():
                clean_ver = re.sub(r'[\^~>=<]', '', ver).strip()
                if clean_ver and re.match(r'^\d', clean_ver):
                    packages.append((name, clean_ver))

    # Check packages in package-lock.json
    lock_pkgs = data.get("packages", {})
    if isinstance(lock_pkgs, dict):
        for pkg_path, meta in lock_pkgs.items():
            if isinstance(meta, dict) and "version" in meta and meta.get("version"):
                name = meta.get("name") or pkg_path.replace("node_modules/", "")
                if name and not name.startswith("node_modules/"):
                    packages.append((name, meta["version"]))

    return list(dict.fromkeys(packages))  # deduplicate preserving order


def check_package_vulnerability(package_name, version, ecosystem="PyPI"):
    """
    Queries the OSV.dev database for known CVEs / advisories affecting
    the specified package version.
    """
    if requests is None:
        return []

    try:
        response = requests.post(
            OSV_API_URL,
            json={
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version,
            },
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulns", [])
        results = []
        for v in vulns:
            vid = v.get("id", "UNKNOWN")
            summary = v.get("summary") or v.get("details", "No summary available")
            
            # Extract severity
            severity = "HIGH"
            if "severity" in v and isinstance(v["severity"], list):
                for s in v["severity"]:
                    if isinstance(s, dict) and "score" in s:
                        severity = s.get("type", "CVSS")
            
            # Extract fixed version if available
            fixed_version = None
            for aff in v.get("affected", []):
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed_version = ev["fixed"]
                            break

            results.append({
                "id": vid,
                "summary": summary[:300],
                "severity": severity,
                "fixed_version": fixed_version,
                "aliases": v.get("aliases", []),
                "advisory_url": f"https://osv.dev/vulnerability/{vid}",
                "recommendation": f"Upgrade {package_name} to version {fixed_version} or latest secure release." if fixed_version else f"Upgrade {package_name} to latest secure release."
            })
        return results
    except Exception:
        return []


def scan_dependencies(folder, max_packages=100):
    findings = []
    checked = 0
    timed_out = False
    manifest_found = False

    all_targets = []  # list of (name, version, ecosystem)

    # 1. Python: requirements.txt
    req_path = os.path.join(folder, "requirements.txt")
    if os.path.exists(req_path):
        manifest_found = True
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                py_pkgs = parse_requirements_txt(f.read())
                for name, ver in py_pkgs:
                    all_targets.append((name, ver, "PyPI"))
        except Exception:
            pass

    # 2. Node.js: package.json / package-lock.json
    pkg_json_path = os.path.join(folder, "package.json")
    if os.path.exists(pkg_json_path):
        manifest_found = True
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                js_pkgs = parse_package_json(f.read())
                for name, ver in js_pkgs:
                    all_targets.append((name, ver, "npm"))
        except Exception:
            pass

    if not manifest_found:
        return {"findings": [], "checked": 0, "skipped_unpinned": 0, "requirements_found": False, "timed_out": False}

    targets = all_targets[:max_packages]
    if requests is None or not targets:
        return {
            "findings": [], "checked": 0, "skipped_unpinned": 0,
            "requirements_found": True, "timed_out": False,
        }

    executor = ThreadPoolExecutor(max_workers=10)
    future_to_package = {
        executor.submit(check_package_vulnerability, name, version, eco): (name, version, eco)
        for name, version, eco in targets
    }

    try:
        for future in as_completed(future_to_package, timeout=DEPENDENCY_CHECK_TIME_BUDGET_SECONDS):
            name, version, eco = future_to_package[future]
            try:
                vulns = future.result(timeout=0)
                checked += 1
                if vulns:
                    findings.append({
                        "package": name,
                        "version": version,
                        "ecosystem": eco,
                        "vulnerabilities": vulns
                    })
            except Exception:
                pass
    except Exception:
        timed_out = checked < len(targets)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return {
        "findings": findings,
        "checked": checked,
        "skipped_unpinned": 0,
        "requirements_found": True,
        "timed_out": timed_out,
    }

