from flask import Flask, request, render_template_string
from download_repo import download_repo
from compare import compare
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

app = Flask(__name__)

# Hard wall-clock cap on the whole scan (download + analysis combined).
# File-count limits in compare.py help, but they can't catch every slow
# case (a huge/slow clone, antivirus scanning downloaded files, a network
# hiccup). This is the real backstop: no matter what's slow, the request
# always comes back within this many seconds instead of hanging forever.
SCAN_TIMEOUT_SECONDS = 90

_executor = ThreadPoolExecutor(max_workers=2)


def run_scan(github_url, full_scan):
    folder = download_repo(github_url)
    if not folder:
        raise RuntimeError("Could not download that repo. Double-check the GitHub URL is correct and public.")
    return compare(folder, full_scan=full_scan)

PAGE = """
<!doctype html>
<html>
<head><title>MCP Server Scanner</title></head>
<body style="font-family: sans-serif; max-width: 700px; margin: 40px auto;">
    <h1>MCP Server Security Scanner</h1>
    <form method="POST">
        <input type="text" name="github_url" placeholder="Paste a GitHub URL"
               style="width: 400px; padding: 8px;">
        <button type="submit" style="padding: 8px;">Scan</button>
        <br><br>
        <label style="font-size: 14px; color: #555;">
            <input type="checkbox" name="full_scan" value="yes">
            Full scan - no file limit (may be slow on huge repos, use with care)
        </label>
    </form>

    {% if error %}
        <h2 style="color: red;">Scan failed</h2>
        <p>{{ error }}</p>
    {% endif %}

    {% if warning %}
        <div style="background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 15px 0;">
            ⚠ {{ warning }}
        </div>
    {% endif %}

    {% if report is not none %}
        <h2>Results</h2>
        {% if report|length == 0 %}
            <p>No MCP tool definitions were found in this repo. This scanner currently only
               recognizes Python-based MCP servers (looking for <code>Tool(...)</code> patterns) -
               it may not support this repo's language or structure yet.</p>
        {% endif %}
        {% for entry in report %}
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <b>Tool:</b> {{ entry.name }}<br>
                <b>Claims to do:</b> {{ entry.description[:150] }}<br>
                <b>Actual behavior:</b> {{ entry.actual_behavior or "None" }}<br>
                <b>Mismatches:</b> {{ entry.mismatches or "None" }}<br>
                <b>Semgrep findings:</b>
                {% if entry.semgrep_findings %}
                    <ul>
                    {% for f in entry.semgrep_findings %}
                        <li>[{{ f.severity }}] Line {{ f.line }}: {{ f.message }}</li>
                    {% endfor %}
                    </ul>
                {% else %}
                    None
                {% endif %}<br>
                <b>Score:</b>
                <span style="color: {{ 'green' if entry.score == 'GREEN' else ('orange' if entry.score == 'YELLOW' else 'red') }}; font-weight: bold;">
                    {{ entry.score }}
                </span>
            </div>
        {% endfor %}
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    warning = None
    if request.method == "POST":
        github_url = request.form.get("github_url")
        full_scan = request.form.get("full_scan") == "yes"
        try:
            future = _executor.submit(run_scan, github_url, full_scan)
            report, warning = future.result(timeout=SCAN_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            error = (
                f"This scan took longer than {SCAN_TIMEOUT_SECONDS} seconds and was stopped "
                f"to keep the site responsive. This usually means the repo is very large or "
                f"slow to download. Try a smaller/more focused MCP server repo, or use the "
                f"'Full scan' option only for repos you know are small."
            )
        except Exception as e:
            error = f"Something went wrong while scanning this repo: {e}"
    return render_template_string(PAGE, report=report, error=error, warning=warning)

if __name__ == "__main__":
    app.run(debug=True, threaded=True)