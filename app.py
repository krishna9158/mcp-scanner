import os
import shutil
import tempfile
import threading
import uuid
import multiprocessing

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, request, render_template_string, Response, jsonify

from download_repo import download_repo, remove_readonly
from badge import generate_badge_svg
from badge_store import save_scan_result, get_last_scan_result
from scan_worker import run_scan_worker
from impact_guide import SECRET_IMPACT, DEPENDENCY_IMPACT, TYPOSQUAT_IMPACT

app = Flask(__name__)

# Hard wall-clock cap on the whole scan (download + analysis combined).
SCAN_TIMEOUT_SECONDS = 300

_scan_semaphore = threading.Semaphore(2)  # at most 2 scans running at once


def compute_overall_score(report, secrets, dependencies, typosquats):
    """
    Rolls up every finding (tool mismatches, secrets, vulnerable deps,
    typosquatted packages) into a single overall score for the whole repo -
    this is what the README badge shows. Worst finding wins: any
    RED-equivalent issue anywhere makes the whole repo RED, regardless of
    how many tools are otherwise clean.
    """
    if secrets:
        return "RED"
    if dependencies and dependencies.get("findings"):
        return "RED"
    if typosquats:
        return "RED"
    if report:
        scores = {entry["score"] for entry in report}
        if "RED" in scores:
            return "RED"
        if "YELLOW" in scores:
            return "YELLOW"
        return "GREEN"
    return "UNKNOWN"


def run_scan_with_hard_timeout(github_url, full_scan):
    """
    Spawns the scan in its own process, waits up to SCAN_TIMEOUT_SECONDS,
    and force-kills it if it's still running. Always cleans up the
    downloaded repo folder afterwards, whether the scan succeeded, failed,
    or had to be killed - so a timed-out scan doesn't leave temp files on
    disk forever.
    """
    destination_folder = os.path.join(
        tempfile.gettempdir(), f"mcp_scan_{uuid.uuid4().hex[:12]}"
    )
    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=run_scan_worker,
        args=(github_url, full_scan, destination_folder, result_queue),
    )

    try:
        process.start()
        # Read from the queue BEFORE joining the process. If a large report
        # is put into the queue, the background feeder thread blocks until
        # the parent drains the pipe. Calling process.join() before result_queue.get()
        # causes a classic multiprocessing pipe-buffer deadlock.
        try:
            status, payload = result_queue.get(timeout=SCAN_TIMEOUT_SECONDS)
        except Exception:
            if process.is_alive():
                process.terminate()
                process.join(5)
                if process.is_alive():
                    process.kill()
            raise TimeoutError(
                f"This scan took longer than {SCAN_TIMEOUT_SECONDS} seconds and was stopped "
                f"to keep the site responsive. This usually means the repo is very large or "
                f"slow to download. Try a smaller/more focused MCP server repo, or use the "
                f"'Full scan' option only for repos you know are small."
            )

        process.join(timeout=10)
        if process.is_alive():
            process.terminate()
            process.join(2)

        if status == "error":
            raise RuntimeError(payload)

        report, warning, secrets, dependencies, typosquats = payload
        return report, warning, secrets, dependencies, typosquats
    finally:
        if os.path.exists(destination_folder):
            shutil.rmtree(destination_folder, onerror=remove_readonly, ignore_errors=True)


def execute_scan(github_url, full_scan):
    """
    Runs one full scan (semaphore + hard timeout + scoring + result
    persistence) and returns a plain dict. Shared by both the HTML form
    route and the JSON API route so the two never drift out of sync -
    they should always mean the same thing by "a scan".
    """
    with _scan_semaphore:
        report, warning, secrets, dependencies, typosquats = run_scan_with_hard_timeout(github_url, full_scan)

    overall_score = compute_overall_score(report, secrets, dependencies, typosquats)
    save_scan_result(github_url, overall_score)

    return {
        "github_url": github_url,
        "overall_score": overall_score,
        "warning": warning,
        "report": report,
        "secrets": secrets,
        "dependencies": dependencies,
        "typosquats": typosquats,
    }


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
    <p style="font-size: 12px; color: #888; margin-top: 8px;">
        Also available as a JSON API: <code>POST /api/scan</code> with
        <code>{"github_url": "...", "full_scan": false}</code>
    </p>

    {% if error %}
        <h2 style="color: red;">Scan failed</h2>
        <p>{{ error }}</p>
    {% endif %}

    {% if warning %}
        <div style="background: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 15px 0;">
            ⚠ {{ warning }}
        </div>
    {% endif %}

    {% if badge_markdown %}
        <div style="border: 1px solid #ccc; padding: 10px; margin: 15px 0; background: #f7f7f7;">
            <b>Add this badge to your README:</b><br>
            <img src="{{ badge_url }}" alt="MCP Security Badge"><br><br>
            <code style="font-size: 12px;">{{ badge_markdown }}</code>
        </div>
    {% endif %}

    {% if typosquats %}
        <h2 style="color: #b30000;">⚠ Possible Typosquatted Packages Found</h2>
        <div style="background: #f7f7f7; border-left: 3px solid #b30000; padding: 8px 12px; margin-bottom: 10px; font-size: 13px;">
            <b>Why this matters:</b> {{ typosquat_impact.impact }}<br><br>
            <b>How to fix it:</b> {{ typosquat_impact.prevention }}
        </div>
        {% for t in typosquats %}
            <div style="border: 1px solid #b30000; padding: 10px; margin: 10px 0; background: #fff5f5;">
                <b>Package:</b> {{ t.package }}<br>
                <b>Resembles trusted package:</b> {{ t.resembles }} (edit distance {{ t.distance }})<br>
                <b>Why:</b> {{ t.reason }}
            </div>
        {% endfor %}
    {% endif %}

    {% if dependencies and dependencies.requirements_found %}
        {% if dependencies.findings %}
            <h2 style="color: #b30000;">⚠ Vulnerable Dependencies Found</h2>
            <div style="background: #f7f7f7; border-left: 3px solid #b30000; padding: 8px 12px; margin-bottom: 10px; font-size: 13px;">
                <b>Why this matters:</b> {{ dependency_impact.impact }}<br><br>
                <b>How to fix it:</b> {{ dependency_impact.prevention }}
            </div>
            {% for dep in dependencies.findings %}
                <div style="border: 1px solid #b30000; padding: 10px; margin: 10px 0; background: #fff5f5;">
                    <b>Package:</b> {{ dep.package }}=={{ dep.version }}<br>
                    <b>Known issues:</b>
                    <ul>
                    {% for v in dep.vulnerabilities %}
                        <li>{{ v.id }}: {{ v.summary }}</li>
                    {% endfor %}
                    </ul>
                </div>
            {% endfor %}
        {% else %}
            <p style="color: #2e7d32;">✓ Checked {{ dependencies.checked }} pinned dependencies against known vulnerabilities - none found.</p>
            {% if dependencies.timed_out %}
                <p style="color: #8a7500; font-size: 13px;">⚠ Note: this check ran out of time before checking every dependency - results above may be incomplete.</p>
            {% endif %}
        {% endif %}
    {% endif %}

    {% if secrets %}
        <h2 style="color: #b30000;">⚠ Possible Hardcoded Secrets Found</h2>
        <div style="background: #f7f7f7; border-left: 3px solid #b30000; padding: 8px 12px; margin-bottom: 10px; font-size: 13px;">
            <b>Why this matters:</b> {{ secret_impact.impact }}<br><br>
            <b>How to fix it:</b> {{ secret_impact.prevention }}
        </div>
        {% for s in secrets %}
            <div style="border: 1px solid #b30000; padding: 10px; margin: 10px 0; background: #fff5f5;">
                <b>Type:</b> {{ s.type }}<br>
                <b>File:</b> {{ s.file }}<br>
                <b>Preview:</b> <code>{{ s.value_preview }}</code><br>
                <b>Confidence:</b> {{ s.confidence }}<br>
                <b>Why:</b> {{ s.reason }}
            </div>
        {% endfor %}
    {% endif %}

    {% if report is not none %}
        <h2>Results</h2>
        {% if report|length == 0 %}
            <p>No MCP tool definitions were found in this repo. This scanner recognizes
               Python (<code>Tool(...)</code> and <code>@mcp.tool</code> patterns) and
               JS/TypeScript (<code>.tool(...)</code> and <code>.registerTool(...)</code>
               patterns) - it may not support this repo's language or structure yet.</p>
        {% endif %}
        {% for entry in report %}
            <div style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
                <b>Tool:</b> {{ entry.name }}
                <span style="font-size: 11px; color: #666; border: 1px solid #ccc; border-radius: 3px; padding: 1px 5px;">{{ entry.language }}</span><br>
                <b>Claims to do:</b> {{ entry.description[:150] }}<br>
                {% if entry.injection_findings %}
                    <div style="background: #ffe0e0; border: 1px solid #b30000; padding: 8px; margin: 8px 0;">
                        <b style="color: #b30000;">⚠ Possible prompt injection in this tool's description:</b>
                        <ul>
                        {% for finding in entry.injection_findings %}
                            <li>{{ finding.type }}: {{ finding.detail }}</li>
                        {% endfor %}
                        </ul>
                        {% if entry.injection_impact %}
                            <div style="font-size: 13px; margin-top: 6px;">
                                <b>Why this matters:</b> {{ entry.injection_impact.impact }}<br><br>
                                <b>How to fix it:</b> {{ entry.injection_impact.prevention }}
                            </div>
                        {% endif %}
                    </div>
                {% endif %}
                {% if entry.shadowing_findings %}
                    <div style="background: #ffe0e0; border: 1px solid #b30000; padding: 8px; margin: 8px 0;">
                        <b style="color: #b30000;">⚠ Possible tool-shadowing:</b>
                        <ul>
                        {% for finding in entry.shadowing_findings %}
                            <li>{{ finding.type }}: {{ finding.detail }}</li>
                        {% endfor %}
                        </ul>
                        {% if entry.shadowing_impact %}
                            <div style="font-size: 13px; margin-top: 6px;">
                                <b>Why this matters:</b> {{ entry.shadowing_impact.impact }}<br><br>
                                <b>How to fix it:</b> {{ entry.shadowing_impact.prevention }}
                            </div>
                        {% endif %}
                    </div>
                {% endif %}
                <b>Inherent risk:</b>
                <span style="font-weight: bold; color: {{ '#b30000' if entry.risk_level == 'CRITICAL' else ('#d17b00' if entry.risk_level == 'HIGH' else ('#8a7500' if entry.risk_level == 'MEDIUM' else '#2e7d32')) }};">
                    {{ entry.risk_level }}
                </span> - {{ entry.risk_explanation }}
                {% if entry.risk_prevention %}
                    <div style="font-size: 13px; color: #555; margin: 4px 0 4px 12px;">
                        <b>What to do:</b> {{ entry.risk_prevention }}
                    </div>
                {% endif %}

                {# Blast Radius (Feature 2) #}
                {% if entry.blast_radius %}
                    <b>Blast radius:</b>
                    {% set br_score = entry.blast_radius.score %}
                    {% set br_label = entry.blast_radius.label %}
                    <span style="font-weight: bold; color: {{ '#b30000' if br_score >= 75 else ('#d17b00' if br_score >= 50 else ('#8a7500' if br_score >= 25 else '#2e7d32')) }};">
                        {{ br_score }}/100 — {{ br_label }}
                    </span>
                    {% if entry.blast_radius.attack_paths %}
                        <div style="font-size: 13px; color: #555; margin: 4px 0 4px 12px;">
                            <b>Attack paths:</b>
                            <ul style="margin: 4px 0 4px 16px; padding: 0;">
                            {% for ap in entry.blast_radius.attack_paths %}
                                <li>{{ ap }}</li>
                            {% endfor %}
                            </ul>
                        </div>
                    {% endif %}
                {% endif %}

                {# Permission Matrix (Feature 1) #}
                {% if entry.permission_matrix %}
                    {% set pm = entry.permission_matrix %}
                    <b>Permission analysis:</b>
                    <span style="font-size: 12px; color: {{ '#b30000' if pm.severity == 'HIGH' else ('#d17b00' if pm.severity == 'MEDIUM' else '#555') }};">
                        severity={{ pm.severity }}
                    </span>
                    {% if pm.findings %}
                        <div style="font-size: 13px; color: #555; margin: 4px 0 4px 12px;">
                            <b>Findings:</b>
                            <ul style="margin: 4px 0 4px 16px; padding: 0;">
                            {% for f in pm.findings %}
                                <li>[{{ f.severity }}] {{ f.type }}: {{ f.detail }}</li>
                            {% endfor %}
                            </ul>
                        </div>
                    {% endif %}
                {% endif %}

                <b>Actual behavior:</b> {{ entry.actual_behavior or "None" }}<br>
                <b>Mismatches:</b> {{ entry.mismatches or "None" }}<br>
                {% if entry.mismatch_impacts %}
                    {% for mi in entry.mismatch_impacts %}
                        {% if mi.impact %}
                            <div style="background: #fff8e1; border-left: 3px solid #d17b00; padding: 6px 10px; margin: 6px 0; font-size: 13px;">
                                <b>{{ mi.category }} - why this matters:</b> {{ mi.impact }}<br><br>
                                <b>How to fix it:</b> {{ mi.prevention }}
                            </div>
                        {% endif %}
                    {% endfor %}
                {% endif %}
                {% if entry.semantic_notes %}
                    <b>Semantic check notes:</b>
                    <ul>
                    {% for note in entry.semantic_notes %}
                        <li>{{ note.category }}: {{ "covered" if note.covered else "not covered" }} - {{ note.reasoning }}</li>
                    {% endfor %}
                    </ul>
                {% endif %}
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
    secrets = None
    dependencies = None
    typosquats = None
    badge_markdown = None
    badge_url = None
    if request.method == "POST":
        github_url = request.form.get("github_url")
        full_scan = request.form.get("full_scan") == "yes"
        try:
            result = execute_scan(github_url, full_scan)
            report = result["report"]
            warning = result["warning"]
            secrets = result["secrets"]
            dependencies = result["dependencies"]
            typosquats = result["typosquats"]
            badge_url = f"{request.host_url.rstrip('/')}/badge?repo={github_url}"
            badge_markdown = f"[![MCP Security]({badge_url})]({github_url})"
        except TimeoutError as e:
            error = str(e)
        except Exception as e:
            error = f"Something went wrong while scanning this repo: {e}"
    return render_template_string(
        PAGE, report=report, error=error, warning=warning, secrets=secrets,
        dependencies=dependencies, typosquats=typosquats,
        badge_markdown=badge_markdown, badge_url=badge_url,
        secret_impact=SECRET_IMPACT, dependency_impact=DEPENDENCY_IMPACT,
        typosquat_impact=TYPOSQUAT_IMPACT
    )


@app.route("/badge")
def badge_endpoint():
    github_url = request.args.get("repo", "")
    result = get_last_scan_result(github_url) if github_url else None
    score = result["score"] if result else "UNKNOWN"
    svg = generate_badge_svg("MCP Security", score)
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-cache, max-age=0"})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    JSON API for programmatic access - e.g. a CI/CD pipeline, a pre-commit
    hook, or another internal tool that wants scan results as data instead
    of an HTML page to scrape. Accepts:
        POST /api/scan
        { "github_url": "https://github.com/owner/repo", "full_scan": false }
    Returns the same scan data the web UI shows, as JSON.
    """
    data = request.get_json(silent=True) or {}
    github_url = data.get("github_url")
    full_scan = bool(data.get("full_scan", False))

    if not github_url:
        return jsonify({"error": "Missing required field: github_url"}), 400

    try:
        result = execute_scan(github_url, full_scan)
        return jsonify(result), 200
    except TimeoutError as e:
        return jsonify({"error": str(e), "error_type": "timeout"}), 504
    except Exception as e:
        return jsonify({"error": str(e), "error_type": "scan_failed"}), 500


if __name__ == "__main__":
    # debug=True was turned OFF on purpose: Flask's debug mode exposes an
    # interactive in-browser console on unhandled errors, which lets
    # anyone who triggers a crash run arbitrary Python on the server.
    # Since this app clones and analyzes untrusted, attacker-controlled
    # repo content, an unexpected crash is a realistic scenario - so this
    # console must never be reachable, even accidentally.
    app.run(debug=False, threaded=True)
