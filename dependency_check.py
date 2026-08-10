import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None

OSV_API_URL = "https://api.osv.dev/v1/query"

# Hard cap on how long the WHOLE dependency check step is allowed to run,
# regardless of how many packages there are. Previously, up to 30 packages
# were checked one at a time with a 10-second timeout EACH - in the worst
# case (a slow/unresponsive OSV.dev) that alone could eat the entire
# scan's time budget, even for a small code repo. Now: checks run in
# parallel, and this step gives up and returns whatever it has so far once
# this many seconds have passed, rather than potentially blocking
# everything else. This is the fix for "any MCP server should scan
# reliably, big or small" - a repo's dependency list, not its code size,
# was the hidden variable causing unpredictable timeouts.
DEPENDENCY_CHECK_TIME_BUDGET_SECONDS = 25


def parse_requirements_txt(content):
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
    if requests is None:
        return []

    try:
        response = requests.post(
            OSV_API_URL,
            json={
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version,
            },
            timeout=5,  # shorter per-call timeout - a slow individual call
                        # shouldn't be able to eat much of the shared budget
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
    findings = []
    checked = 0
    timed_out = False

    req_path = os.path.join(folder, "requirements.txt")
    if not os.path.exists(req_path):
        return {"findings": [], "checked": 0, "skipped_unpinned": 0, "requirements_found": False, "timed_out": False}

    try:
        with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return {"findings": [], "checked": 0, "skipped_unpinned": 0, "requirements_found": False, "timed_out": False}

    packages = parse_requirements_txt(content)[:max_packages]

    if requests is None or not packages:
        return {
            "findings": [], "checked": 0, "skipped_unpinned": 0,
            "requirements_found": True, "timed_out": False,
        }

    # Check all packages concurrently instead of one at a time - this is
    # the main fix. 30 packages checked in parallel takes roughly as long
    # as the SLOWEST single check, not the sum of all of them.
    #
    # Important: we do NOT use `with ThreadPoolExecutor() as executor:`
    # here. That context manager waits for every submitted thread to
    # finish before letting the code continue - including threads we've
    # already decided to give up on, which would silently defeat the
    # whole point of this fix. Shutting down with wait=False lets this
    # function return on time; any already-running background requests
    # are still bounded by their own 5-second timeout, and this whole
    # scan already runs inside an isolated, killable process, so nothing
    # lingers indefinitely.
    executor = ThreadPoolExecutor(max_workers=10)
    future_to_package = {
        executor.submit(check_package_vulnerability, name, version): (name, version)
        for name, version in packages
    }

    try:
        for future in as_completed(future_to_package, timeout=DEPENDENCY_CHECK_TIME_BUDGET_SECONDS):
            name, version = future_to_package[future]
            try:
                vulns = future.result(timeout=0)
                checked += 1
                if vulns:
                    findings.append({"package": name, "version": version, "vulnerabilities": vulns})
            except Exception:
                pass  # a single package's check failing shouldn't affect the others
    except Exception:
        # as_completed itself raises a TimeoutError once the overall
        # `timeout=` is exceeded with futures still pending - that's our
        # signal to stop waiting and move on with partial results.
        timed_out = checked < len(packages)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return {
        "findings": findings,
        "checked": checked,
        "skipped_unpinned": 0,
        "requirements_found": True,
        "timed_out": timed_out,
    }
