import subprocess
import json

def run_semgrep_scan(folder):
    print(f"Scanning {folder} with Semgrep... this may take a minute.")

    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", folder],
            capture_output=True,
            text=True,
            timeout=120  # don't let one huge repo hang the whole app
        )
    except subprocess.TimeoutExpired:
        print("Semgrep timed out on this repo (likely too large) - skipping semgrep findings.")
        return []
    except FileNotFoundError:
        print("Semgrep is not installed/available on this system - skipping semgrep findings.")
        return []
    except Exception as e:
        print(f"Semgrep failed to run: {e}")
        return []

    print("---- RAW OUTPUT START ----")
    print(result.stdout[:500])  # print first 500 characters only
    print("---- RAW OUTPUT END ----")
    print("---- ERRORS (if any) ----")
    print(result.stderr[:500])
    print("---- END ----")

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