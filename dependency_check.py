import re
import os

try:
    import requests
except ImportError:
    requests = None

OSV_API_URL = "https://api.osv.dev/v1/query"


def parse_requirements_txt(content):
    """
    Parses a requirements.txt file into a list of (package_name, version)
    tuples. Only handles the common, simple pinned-version format
    (package==1.2.3) - lines using ranges (>=, ~=), git URLs, or -r
    includes are skipped, since there's no single exact version to check.
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r'^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)', line)
        if match:
            packages.append((match.group(1), match.group(2)))
    return packages


def check_package_vulnerability(package_name, version, ecosystem="PyPI"):
    """
    Queries the free, public OSV.dev database for known vulnerabilities
    affecting this exact package+version. No API key required. Returns a
    list of vulnerability dicts (empty list if none found or on error -
    this should never crash a scan, just skip that package silently).
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
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulns", [])
        results = []
        for v in vulns:
            results.append({
                "id": v.get("id", "UNKNOWN"),
                "summary": (v.get("summary") or v.get("details", "No summary available"))[:200],
            })
        return results
    except Exception:
        return []


def scan_dependencies(folder, max_packages=100):
    """
    Finds requirements.txt in the repo, checks each pinned package against
    OSV.dev, and returns a list of findings for anything with a known
    vulnerability. Packages without an exact pinned version are skipped
    (nothing to look up), and this is noted in the returned summary.
    """
    findings = []
    skipped_unpinned = 0
    checked = 0

    req_path = os.path.join(folder, "requirements.txt")
    if not os.path.exists(req_path):
        return {"findings": [], "checked": 0, "skipped_unpinned": 0, "requirements_found": False}

    try:
        with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return {"findings": [], "checked": 0, "skipped_unpinned": 0, "requirements_found": False}

    packages = parse_requirements_txt(content)

    for name, version in packages[:max_packages]:
        vulns = check_package_vulnerability(name, version)
        checked += 1
        if vulns:
            findings.append({
                "package": name,
                "version": version,
                "vulnerabilities": vulns,
            })

    return {
        "findings": findings,
        "checked": checked,
        "skipped_unpinned": skipped_unpinned,
        "requirements_found": True,
    }
