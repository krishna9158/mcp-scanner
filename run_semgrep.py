import subprocess
import sys
import json
import os
import shutil
import site
import sysconfig


def _get_semgrep_env_and_candidates():
    """Finds available candidate commands for semgrep and sets up PATH."""
    dirs_to_check = []
    if hasattr(site, "getuserbase"):
        ub = site.getuserbase()
        py_ver = f"Python{sys.version_info.major}{sys.version_info.minor}"
        dirs_to_check.append(os.path.join(ub, py_ver, "Scripts"))
        dirs_to_check.append(os.path.join(ub, "Scripts"))
    try:
        dirs_to_check.append(sysconfig.get_path("scripts"))
    except Exception:
        pass
    dirs_to_check.append(os.path.join(sys.prefix, "Scripts"))

    valid_dirs = [d for d in dirs_to_check if d and os.path.isdir(d)]
    env = os.environ.copy()
    if valid_dirs:
        env["PATH"] = os.pathsep.join(valid_dirs) + os.pathsep + env.get("PATH", "")

    candidates = []
    # Look for semgrep or pysemgrep in PATH (including python scripts folders)
    for bin_name in ["semgrep", "pysemgrep", "semgrep.exe", "pysemgrep.exe"]:
        bin_path = shutil.which(bin_name, path=env.get("PATH"))
        if bin_path and [bin_path] not in candidates:
            candidates.append([bin_path])

    if ["semgrep"] not in candidates:
        candidates.append(["semgrep"])
    if ["pysemgrep"] not in candidates:
        candidates.append(["pysemgrep"])

    return candidates, env


SEMGREP_EXCLUDES = [
    "--exclude=.git",
    "--exclude=node_modules",
    "--exclude=dist",
    "--exclude=build",
    "--exclude=.venv",
    "--exclude=venv",
    "--exclude=vendor",
    "--exclude=third_party",
    "--exclude=.next",
    "--exclude=coverage",
    "--exclude=.pytest_cache",
    "--exclude=*.min.js",
    "--exclude=*.min.css",
    "--exclude=*-lock.json",
    "--exclude=*.lock",
    "--max-target-bytes=2000000",
]


def _run_semgrep_command(command, folder, env=None):
    """Runs one candidate way of invoking Semgrep. Returns the completed
    process, or raises FileNotFoundError/TimeoutExpired for the caller to
    handle."""
    return subprocess.run(
        command + ["--config=auto", "--json"] + SEMGREP_EXCLUDES + [folder],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=45,
        env=env,
    )



def run_semgrep_scan(folder):
    print(f"Scanning {folder} with Semgrep... this may take a minute.")

    candidates, env = _get_semgrep_env_and_candidates()

    result = None
    last_error = None
    for command in candidates:
        try:
            res = _run_semgrep_command(command, folder, env=env)
            if res.stdout and res.stdout.strip().startswith("{"):
                result = res
                break
            elif res.returncode == 0:
                result = res
                break
            else:
                last_error = f"Command {command} returned code {res.returncode}: {res.stderr.strip() if res.stderr else res.stdout.strip()}"
                continue
        except FileNotFoundError as e:
            last_error = e
            continue
        except subprocess.TimeoutExpired:
            print("Semgrep timed out on this repo (likely too large) - skipping semgrep findings.")
            return []
        except Exception as e:
            last_error = e
            continue

    if result is None or not result.stdout.strip():
        print(
            f"Semgrep is not available or failed to produce JSON output ({last_error or 'no output'}) - skipping semgrep findings. "
            "Install it with: pip install semgrep"
        )
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("results", [])
    except Exception as e:
        print(f"Something went wrong parsing Semgrep's output: {e}")
        return []

def summarize_findings(findings):
    if not findings:
        print("No issues flagged by Semgrep.")
        return
    print(f"\nSemgrep flagged {len(findings)} issue(s):\n")
    for finding in findings:
        path = finding.get("path", "unknown file")
        line = finding.get("start", {}).get("line", "?")
        message = finding.get("extra", {}).get("message", "No message")
        print(f"File: {path} (line {line})")
        print(f"Issue: {message}")
        print("-" * 50)

if __name__ == "__main__":
    folder = input("Path to the downloaded repo folder (e.g. downloaded_repo): ")
    findings = run_semgrep_scan(folder)
    summarize_findings(findings)

