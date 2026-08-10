import subprocess
import sys
import json


def _run_semgrep_command(command, folder):
    """Runs one candidate way of invoking Semgrep. Returns the completed
    process, or raises FileNotFoundError/TimeoutExpired for the caller to
    handle."""
    return subprocess.run(
        command + ["--config=auto", "--json", folder],
        capture_output=True, text=True, timeout=120
    )


def run_semgrep_scan(folder):
    print(f"Scanning {folder} with Semgrep... this may take a minute.")

    # Two ways to invoke Semgrep, tried in order:
    #   1. The plain "semgrep" command - works when it's on the system PATH.
    #   2. "python -m semgrep" - works even when the "semgrep" command isn't
    #      on PATH (a common situation right after "pip install semgrep" on
    #      Windows), since this runs it through the exact same Python
    #      interpreter that's already running this script, with no
    #      dependency on PATH at all.
    candidate_commands = [["semgrep"], [sys.executable, "-m", "semgrep"]]

    result = None
    last_error = None
    for command in candidate_commands:
        try:
            result = _run_semgrep_command(command, folder)
            break
        except FileNotFoundError as e:
            last_error = e
            continue
        except subprocess.TimeoutExpired:
            print("Semgrep timed out on this repo (likely too large) - skipping semgrep findings.")
            return []
        except Exception as e:
            print(f"Semgrep failed to run: {e}")
            return []

    if result is None:
        print(
            "Semgrep is not installed/available on this system (tried both "
            "'semgrep' and 'python -m semgrep') - skipping semgrep findings. "
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
