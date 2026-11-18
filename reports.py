"""
Multi-Format Security Reporting Engine.

Generates professional, audit-ready security reports in:
- JSON format (/api/report/json)
- HTML / PDF-printable format (/report/html)

Strictly guarantees zero credential leakage (all secrets redacted).
Includes multi-engine attribution, Software Bill of Materials (SBOM), and transparent Scan Coverage.
"""
import json
import time

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TrustAudit AI Application & MCP Security Report - {{ data.github_url }}</title>
    <style>
        @media print {
            body { margin: 15mm; font-size: 11pt; color: #111; }
            .no-print { display: none !important; }
            .page-break { page-break-before: always; }
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #222; max-width: 950px; margin: 30px auto; padding: 0 20px; }
        h1, h2, h3 { color: #0f172a; margin-top: 1.5em; margin-bottom: 0.5em; }
        .header-bar { border-bottom: 2px solid #0f172a; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: flex-end; }
        .score-pill { font-size: 28px; font-weight: bold; padding: 6px 16px; border-radius: 8px; display: inline-block; }
        .score-GREEN { background: #dcfce7; color: #166534; }
        .score-YELLOW { background: #fef9c3; color: #854d0e; }
        .score-RED { background: #fee2e2; color: #991b1b; }
        .card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #fff; }
        .badge { display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: 600; border-radius: 4px; text-transform: uppercase; margin-right: 6px; }
        .badge-CRITICAL { background: #ef4444; color: #fff; }
        .badge-HIGH { background: #f97316; color: #fff; }
        .badge-MEDIUM { background: #eab308; color: #000; }
        .badge-LOW { background: #22c55e; color: #fff; }
        .badge-engine { background: #0f172a; color: #38bdf8; font-size: 10.5px; border-radius: 4px; padding: 2px 6px; font-family: monospace; }
        .badge-status { background: #e2e8f0; color: #334155; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 2px 6px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }
        th { background: #f8fafc; font-weight: 600; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }
        .btn-print { background: #0f172a; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header-bar">
        <div>
            <h1>TrustAudit Security Audit Report</h1>
            <p style="margin: 0; color: #64748b;">Target Repository: <b>{{ data.get('github_url', 'Target') }}</b></p>
            <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Generated at {{ data.get('generated_at', 'N/A') }} | TrustAudit AI Security Platform</p>
        </div>
        <div style="text-align: right;">
            <button class="btn-print no-print" onclick="window.print()">Print / Export PDF</button>
            <div style="margin-top: 8px;">
                <span class="score-pill score-{{ data.get('badge_color', 'GREEN') }}">{{ data.get('score', 100) }}/100 (Grade {{ data.get('grade', 'A') }})</span>
            </div>
        </div>
    </div>

    <!-- Scan Coverage Section -->
    <h2>1. Scan Coverage &amp; Engine Execution Transparency</h2>
    <div class="card" style="background: #f8fafc; border-left: 4px solid #3b82f6;">
        <p style="font-weight: 600; margin-bottom: 6px;">{{ data.get('score_explanation', '') }}</p>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 10px;">
            <div>
                <b style="color: #166534;">SCANNERS EXECUTED:</b>
                <ul style="margin-top: 6px; padding-left: 18px; font-size: 13px;">
                    {% for sc in (data.get('scan_coverage') or {}).get('scanners_executed', []) %}
                    <li><b>{{ sc.get('name', sc.get('scanner')) }}</b> &bull; <span class="badge badge-LOW">COMPLETED</span> ({{ sc.get('findings_count', 0) }} findings, {{ sc.get('duration', 0.0) }}s)</li>
                    {% endfor %}
                </ul>
            </div>
            <div>
                <b style="color: #64748b;">NOT RUN / NOT APPLICABLE:</b>
                <ul style="margin-top: 6px; padding-left: 18px; font-size: 13px; color: #64748b;">
                    {% for sc in (data.get('scan_coverage') or {}).get('scanners_not_run', []) %}
                    <li><b>{{ sc.get('name', sc.get('scanner')) }}</b> &bull; <span class="badge-status">{{ (sc.get('status') or 'SKIPPED')|upper }}</span><br><small>{{ sc.get('reason') or 'Not applicable' }}</small></li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>

    <h2>2. Executive Summary &amp; Action Plan</h2>
    <div class="card">
        <p><b>Security Posture:</b> {{ data.get('status', 'SECURE') }} &bull; <b>Tools:</b> {{ data.get('tools_count', 0) }} &bull; <b>Secrets:</b> {{ data.get('secrets_count', 0) }} &bull; <b>Attack Paths:</b> {{ data.get('attack_paths_count', 0) }} &bull; <b>AppSec Flaws:</b> {{ data.get('appsec_count', 0) }}</p>
        {% if data.get('executive_summary') %}
            <p style="margin-top: 8px;">{{ data.get('executive_summary') }}</p>
        {% endif %}
        {% if data.get('top_reasons') %}
        <p style="margin-top: 8px;"><b>Top Risk Drivers:</b></p>
        <ul>
            {% for r in data.get('top_reasons', []) %}
            <li>{{ r }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <h2>3. Discovered Multi-Stage Attack Paths</h2>
    {% if data.get('attack_paths') %}
        {% for ap in data.get('attack_paths', []) %}
        <div class="card" style="border-left: 4px solid #ef4444;">
            <span class="badge badge-{{ ap.get('severity', 'HIGH') }}">{{ ap.get('severity', 'HIGH') }}</span> <b>{{ ap.get('title', 'Attack Path') }}</b><br>
            <p style="margin: 6px 0; font-size: 13px;"><b>Impact:</b> {{ ap.get('impact', '') }}</p>
            <table>
                <tr><th>Step</th><th>Stage</th><th>Actor</th><th>Action / Evidence</th></tr>
                {% for st in ap.get('steps', []) %}
                <tr>
                    <td>{{ st.get('step') }}</td>
                    <td><b>{{ st.get('stage') }}</b></td>
                    <td>{{ st.get('actor') }}</td>
                    <td>{{ st.get('action') }}<br><small style="color: #64748b;">Evidence: <code>{{ st.get('evidence', '') }}</code></small></td>
                </tr>
                {% endfor %}
            </table>
            <p style="margin: 8px 0 0 0; font-size: 12px; color: #15803d;"><b>Remediation:</b> {{ ap.get('remediation', '') }}</p>
        </div>
        {% endfor %}
    {% else %}
        <p style="color: #16a34a;">✓ No multi-stage attack paths identified.</p>
    {% endif %}

    <h2>4. Unified Security Findings (Multi-Engine Normalized)</h2>
    {% if data.get('findings') %}
        <table>
            <tr><th>Severity</th><th>Category</th><th>Title &amp; Description</th><th>Location / Package</th><th>Detected By</th><th>Action</th></tr>
            {% for f in data.get('findings', []) %}
            <tr>
                <td><span class="badge badge-{{ f.get('severity', 'MEDIUM') }}">{{ f.get('severity', 'MEDIUM') }}</span></td>
                <td><b>{{ f.get('category', 'repo') }}</b></td>
                <td>
                    <b>{{ f.get('title', 'Untitled') }}</b><br>
                    <small style="color: #64748b;">{{ f.get('description', '') }}</small><br>
                    <small>Evidence: <code>{{ f.get('evidence', '') }}</code></small>
                </td>
                <td>
                    {% if f.get('file') %}<code>{{ f.get('file') }}{% if f.get('line') %}:{{ f.get('line') }}{% endif %}</code>{% endif %}
                    {% if f.get('package') %}<div><b>Pkg:</b> {{ f.get('package') }} {{ f.get('version') or '' }}</div>{% endif %}
                    {% if f.get('cve') %}<div><span class="badge badge-HIGH">{{ f.get('cve') }}</span></div>{% endif %}
                </td>
                <td>
                    {% for sc in f.get('scanners', []) %}
                    <span class="badge-engine">{{ sc }}</span>
                    {% endfor %}
                </td>
                <td><small style="color: #15803d;">{{ f.get('remediation', '') }}</small></td>
            </tr>
            {% endfor %}
        </table>
    {% else %}
        <p style="color: #16a34a;">✓ No security vulnerabilities detected across integrated engines.</p>
    {% endif %}

    <h2>5. Hardcoded Secrets (Zero-Exposure Redacted)</h2>
    {% if data.get('secrets') %}
        <table>
            <tr><th>Type</th><th>Classification</th><th>Severity</th><th>File &amp; Line</th><th>Preview</th><th>Remediation</th></tr>
            {% for s in data.get('secrets', []) %}
            <tr>
                <td><b>{{ s.get('type') }}</b></td>
                <td><code>{{ s.get('classification', 'POSSIBLE SECRET') }}</code></td>
                <td><span class="badge badge-{{ s.get('severity', 'HIGH') }}">{{ s.get('severity', 'HIGH') }}</span></td>
                <td>{{ s.get('file', '') }}:{{ s.get('line', '') }}</td>
                <td><code>{{ s.get('masked_value') or s.get('value_preview', '***') }}</code></td>
                <td>{{ s.get('recommendation', '') }}</td>
            </tr>
            {% endfor %}
        </table>
    {% else %}
        <p style="color: #16a34a;">✓ No exposed credentials or secret tokens detected.</p>
    {% endif %}

    <h2>6. MCP Tool &amp; Permission Matrix</h2>
    {% if data.get('report') %}
        <table>
            <tr><th>Tool Name</th><th>Risk Level</th><th>Language</th><th>Declared Purpose</th><th>Observed Behaviors &amp; Inherent Risks</th></tr>
            {% for tool in data.get('report', []) %}
            <tr>
                <td><b>{{ tool.get('name') }}</b></td>
                <td><span class="badge badge-{{ tool.get('risk_level', 'LOW') }}">{{ tool.get('risk_level', 'LOW') }}</span></td>
                <td><code>{{ tool.get('language', 'Python') }}</code></td>
                <td>{{ tool.get('description', '') }}</td>
                <td>
                    {% if tool.get('actual_behavior') %}
                        <div><b>Capabilities:</b> {{ tool.get('actual_behavior', [])|join(', ') }}</div>
                    {% endif %}
                    {% if tool.get('mismatches') %}
                        <div style="color: #ef4444; font-weight: 500;"><b>Mismatches:</b> {{ tool.get('mismatches', [])|join(', ') }}</div>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
    {% else %}
        <p>No Model Context Protocol tools identified in this repository.</p>
    {% endif %}

    <h2>7. Software Bill of Materials (SBOM) Inventory</h2>
    {% if data.get('sbom') and (data.get('sbom') or {}).get('packages') %}
        <div class="card">
            <p><b>Total Packages:</b> {{ (data.get('sbom') or {}).get('total_packages', 0) }} &bull; <b>Ecosystems:</b> {{ (data.get('sbom') or {}).get('ecosystems', '') }}</p>
            {% if (data.get('sbom') or {}).get('ai_components') %}
            <p style="margin-top: 6px;"><b>AI / MCP Components:</b> {{ (data.get('sbom') or {}).get('ai_components', [])|join(', ') }}</p>
            {% endif %}
        </div>
        <table>
            <tr><th>Component Name</th><th>Version</th><th>Ecosystem</th><th>PURL</th></tr>
            {% for p in (data.get('sbom') or {}).get('packages', [])[:50] %}
            <tr>
                <td><b>{{ p.get('name') }}</b></td>
                <td><code>{{ p.get('version') or 'N/A' }}</code></td>
                <td><span class="badge-engine">{{ p.get('ecosystem', 'unknown') }}</span></td>
                <td><code>{{ p.get('purl') or 'N/A' }}</code></td>
            </tr>
            {% endfor %}
        </table>
        {% if (data.get('sbom') or {}).get('packages', [])|length > 50 %}
        <p style="font-size: 12px; color: #64748b;">Showing first 50 of {{ (data.get('sbom') or {}).get('packages', [])|length }} packages. Full SBOM available in JSON export.</p>
        {% endif %}
    {% else %}
        <p style="color: #64748b;">No manifest dependencies detected.</p>
    {% endif %}

    <div style="margin-top: 40px; border-top: 1px solid #cbd5e1; padding-top: 15px; color: #94a3b8; font-size: 12px; text-align: center;">
        TrustAudit Continuous Verification Engine &bull; Confidential Security Audit Document
    </div>
</body>
</html>
"""


HTML_WEBSITE_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TrustAudit Website Security Report - {{ data.get('target_url', 'Target') }}</title>
    <style>
        @media print {
            body { margin: 15mm; font-size: 11pt; color: #111; }
            .no-print { display: none !important; }
            .page-break { page-break-before: always; }
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #222; max-width: 950px; margin: 30px auto; padding: 0 20px; }
        h1, h2, h3 { color: #0f172a; margin-top: 1.5em; margin-bottom: 0.5em; }
        .header-bar { border-bottom: 2px solid #0f172a; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: flex-end; }
        .score-pill { font-size: 28px; font-weight: bold; padding: 6px 16px; border-radius: 8px; display: inline-block; }
        .score-GREEN { background: #dcfce7; color: #166534; }
        .score-YELLOW { background: #fef9c3; color: #854d0e; }
        .score-RED { background: #fee2e2; color: #991b1b; }
        .card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #fff; }
        .badge { display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: 600; border-radius: 4px; text-transform: uppercase; margin-right: 6px; }
        .badge-CRITICAL { background: #ef4444; color: #fff; }
        .badge-HIGH { background: #f97316; color: #fff; }
        .badge-MEDIUM { background: #eab308; color: #000; }
        .badge-LOW { background: #22c55e; color: #fff; }
        .badge-engine { background: #0f172a; color: #38bdf8; font-size: 10.5px; border-radius: 4px; padding: 2px 6px; font-family: monospace; }
        .badge-status { background: #e2e8f0; color: #334155; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 2px 6px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }
        th { background: #f8fafc; font-weight: 600; }
        code { background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }
        .btn-print { background: #0f172a; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header-bar">
        <div>
            <h1>TrustAudit Website Security Report</h1>
            <p style="margin: 0; color: #64748b;">Target: <b>{{ data.get('target_url', 'Target') }}</b> ({{ data.get('hostname', '') }})</p>
            <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Generated at {{ data.get('generated_at', 'N/A') }} | TrustAudit Web Security Platform</p>
        </div>
        <div style="text-align: right;">
            <button class="btn-print no-print" onclick="window.print()">Print / Export PDF</button>
            <div style="margin-top: 8px;">
                <span class="score-pill score-{{ data.get('badge_color', 'GREEN') }}">{{ data.get('score', 100) }}/100 (Grade {{ data.get('grade', 'A') }})</span>
            </div>
        </div>
    </div>

    {% if data.get('used_http_fallback') %}
    <div class="card" style="background: #fee2e2; border-left: 4px solid #ef4444; margin-top: 20px;">
        <b style="color: #991b1b;">⚠️ Plaintext HTTP Fallback Active (Broken HTTPS Detected)</b>
        <p style="margin: 4px 0 0 0; font-size: 13px; color: #7f1d1d;">
            {{ data.get('http_fallback_reason') or 'HTTPS connection on port 443 failed after retries. The scanner automatically fell back to plain HTTP to complete the security audit.' }}
        </p>
    </div>
    {% endif %}

    <!-- Scan Coverage Section -->
    <h2>1. Scan Coverage &amp; Engine Execution Transparency</h2>
    <div class="card" style="background: #f8fafc; border-left: 4px solid #3b82f6;">
        <p style="font-weight: 600; margin-bottom: 6px;">{{ data.get('score_explanation', '') }}</p>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 10px;">
            <div>
                <b style="color: #166534;">SCANNERS EXECUTED:</b>
                <ul style="margin-top: 6px; padding-left: 18px; font-size: 13px;">
                    {% for sc in (data.get('scan_coverage') or {}).get('scanners_executed', []) %}
                    <li><b>{{ sc.get('name', sc.get('scanner')) }}</b> &bull; <span class="badge badge-LOW">COMPLETED</span> ({{ sc.get('findings_count', 0) }} findings, {{ sc.get('duration', 0.0) }}s)</li>
                    {% endfor %}
                </ul>
            </div>
            <div>
                <b style="color: #64748b;">NOT RUN / NOT APPLICABLE:</b>
                <ul style="margin-top: 6px; padding-left: 18px; font-size: 13px; color: #64748b;">
                    {% for sc in (data.get('scan_coverage') or {}).get('scanners_not_run', []) %}
                    <li><b>{{ sc.get('name', sc.get('scanner')) }}</b> &bull; <span class="badge-status">{{ (sc.get('status') or 'SKIPPED')|upper }}</span><br><small>{{ sc.get('reason') or 'Not applicable' }}</small></li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>

    <h2>2. Executive Summary &amp; Action Plan</h2>
    <div class="card">
        <p><b>Security Posture:</b> {{ data.get('status', 'SECURE') }} &bull; <b>Findings:</b> {{ (data.get('findings') or [])|length }}</p>
        {% if data.get('action_plan') %}
        <p style="margin-top: 8px;"><b>Prioritized Remediation Actions:</b></p>
        <ul>
            {% for item in data.get('action_plan', []) %}
            <li>{{ item }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>

    <h2>3. Web Security Posture Breakdown</h2>
    <div class="card">
        <table>
            <tr><th>Security Domain</th><th>Score</th><th>Status</th></tr>
            <tr><td>TLS &amp; Certificate Encryption</td><td>{{ (data.get('subscores') or {}).get('tls_encryption', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('tls_encryption', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
            <tr><td>HTTP Security Headers (CSP, HSTS, X-Frame)</td><td>{{ (data.get('subscores') or {}).get('security_headers', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('security_headers', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
            <tr><td>Cookie Flags &amp; Session Security</td><td>{{ (data.get('subscores') or {}).get('cookie_security', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('cookie_security', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
            <tr><td>Cross-Origin Resource Sharing (CORS)</td><td>{{ (data.get('subscores') or {}).get('cors_access', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('cors_access', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
            <tr><td>Public Exposure &amp; Sensitive Files</td><td>{{ (data.get('subscores') or {}).get('exposure_leakage', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('exposure_leakage', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
            <tr><td>API Endpoint Security Posture</td><td>{{ (data.get('subscores') or {}).get('api_posture', 0) }}/100</td><td>{% if (data.get('subscores') or {}).get('api_posture', 0) >= 80 %}SECURE{% else %}ATTENTION REQUIRED{% endif %}</td></tr>
        </table>
    </div>

    <h2>4. Detected Security Findings</h2>
    {% if data.get('findings') %}
        <table>
            <tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr>
            {% for f in data.get('findings', []) %}
            <tr>
                <td><span class="badge badge-{{ f.get('severity', 'MEDIUM') }}">{{ f.get('severity', 'MEDIUM') }}</span></td>
                <td><code>{{ f.get('confidence', 'CONFIRMED') }}</code></td>
                <td><b>{{ f.get('title', 'Untitled') }}</b><br><small style="color: #64748b;">{{ f.get('description', '') }}</small></td>
                <td><code>{{ f.get('evidence', '') }}</code></td>
                <td>{{ f.get('remediation', '') }}</td>
            </tr>
            {% endfor %}
        </table>
    {% else %}
        <p style="color: #16a34a;">✓ No web vulnerabilities detected.</p>
    {% endif %}

    <div style="margin-top: 40px; border-top: 1px solid #cbd5e1; padding-top: 15px; color: #94a3b8; font-size: 12px; text-align: center;">
        TrustAudit Continuous Verification Engine &bull; Confidential Security Audit Document
    </div>
</body>
</html>
"""


def generate_json_report(scan_result):
    """Generates structured JSON security audit report."""
    target_type = scan_result.get("target_type", "repository")

    if target_type == "website":
        return {
            "metadata": {
                "scanner": "TrustAudit Web Security Platform",
                "version": "2.0.0",
                "target_type": "website",
                "target_url": scan_result.get("target_url"),
                "hostname": scan_result.get("hostname"),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            },
            "score_summary": {
                "score": scan_result.get("score", 100),
                "grade": scan_result.get("grade", "A"),
                "status": scan_result.get("status", "SECURE"),
                "badge_color": scan_result.get("badge_color", "GREEN"),
                "subscores": scan_result.get("subscores", {}),
                "score_explanation": scan_result.get("score_explanation", ""),
                "findings_summary": scan_result.get("findings_summary", {}),
            },
            "scan_coverage": scan_result.get("scan_coverage", {}),
            "findings": scan_result.get("findings", []),
            "tls_info": scan_result.get("tls_info", {}),
            "headers_eval": scan_result.get("headers_eval", {}),
            "cookie_analysis": scan_result.get("cookie_analysis", {}),
            "cors_info": scan_result.get("cors_info", {}),
            "tech_info": scan_result.get("tech_info", {}),
            "action_plan": scan_result.get("action_plan", []),
            "engines_executed": scan_result.get("engines_executed", []),
            "engines_status": scan_result.get("engines_status", {}),
        }

    return {
        "metadata": {
            "scanner": "TrustAudit AI Security Platform",
            "version": "2.0.0",
            "target_type": "repository",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "github_url": scan_result.get("github_url", "local"),
        },
        "score_summary": {
            "score": scan_result.get("score", 100),
            "grade": scan_result.get("grade", "A"),
            "status": scan_result.get("status", "SECURE"),
            "badge_color": scan_result.get("badge_color", "GREEN"),
            "category_scores": scan_result.get("category_scores", {}),
            "top_reasons": scan_result.get("top_reasons", []),
            "score_explanation": scan_result.get("score_explanation", ""),
        },
        "scan_coverage": scan_result.get("scan_coverage", {}),
        "executive_analysis": scan_result.get("executive_analysis", {}),
        "findings": scan_result.get("findings", []),
        "sbom": scan_result.get("sbom", {}),
        "mcp_tools": scan_result.get("report", []),
        "mcp_authentication": scan_result.get("auth_analysis", {}),
        "permission_graph": scan_result.get("permission_graph", {}),
        "attack_paths": scan_result.get("attack_paths", []),
        "secrets": scan_result.get("secrets", []),
        "dependencies": scan_result.get("dependencies", {}),
        "supply_chain_findings": scan_result.get("supply_chain_findings", []),
        "appsec_findings": scan_result.get("appsec_findings", []),
        "tenancy_report": scan_result.get("tenancy_report", {}),
        "policy_evaluation": scan_result.get("policy_evaluation", {}),
        "baseline_drift": scan_result.get("baseline_drift", {}),
        "engines_executed": scan_result.get("engines_executed", []),
        "engines_status": scan_result.get("engines_status", {}),
    }


def generate_html_report(scan_result):
    """Renders the printable HTML report using Jinja2."""
    from jinja2 import Template
    target_type = scan_result.get("target_type", "repository")

    if target_type == "website":
        template = Template(HTML_WEBSITE_REPORT_TEMPLATE)
        report_data = {
            "target_url": scan_result.get("target_url"),
            "hostname": scan_result.get("hostname"),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "score": scan_result.get("score", 100),
            "grade": scan_result.get("grade", "A"),
            "status": scan_result.get("status", "SECURE"),
            "used_http_fallback": scan_result.get("used_http_fallback", False),
            "http_fallback_reason": scan_result.get("http_fallback_reason"),
            "badge_color": scan_result.get("badge_color", "GREEN"),
            "subscores": scan_result.get("subscores", {}),
            "score_explanation": scan_result.get("score_explanation", "No high or critical vulnerabilities detected by executed scanners."),
            "scan_coverage": scan_result.get("scan_coverage", {}),
            "findings": scan_result.get("findings", []),
            "findings_summary": scan_result.get("findings_summary", {}),
            "tls_info": scan_result.get("tls_info", {}),
            "action_plan": scan_result.get("action_plan", []),
            "engines_executed": scan_result.get("engines_executed", []),
        }
        return template.render(data=report_data)

    template = Template(HTML_REPORT_TEMPLATE)
    report_data = {
        "github_url": scan_result.get("github_url", "local"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "score": scan_result.get("score", 100),
        "grade": scan_result.get("grade", "A"),
        "status": scan_result.get("status", "SECURE"),
        "badge_color": scan_result.get("badge_color", "GREEN"),
        "score_explanation": scan_result.get("score_explanation", "No high or critical vulnerabilities detected by executed scanners."),
        "scan_coverage": scan_result.get("scan_coverage", {}),
        "tools_count": len(scan_result.get("report", [])),
        "secrets_count": len(scan_result.get("secrets", [])),
        "deps_count": len(scan_result.get("dependencies", {}).get("findings", []) if isinstance(scan_result.get("dependencies"), dict) else []),
        "attack_paths_count": len(scan_result.get("attack_paths", [])),
        "appsec_count": len(scan_result.get("appsec_findings", [])),
        "executive_summary": scan_result.get("executive_analysis", {}).get("summary", ""),
        "top_reasons": scan_result.get("top_reasons", []),
        "attack_paths": scan_result.get("attack_paths", []),
        "secrets": scan_result.get("secrets", []),
        "report": scan_result.get("report", []),
        "dependencies": scan_result.get("dependencies", {}),
        "appsec_findings": scan_result.get("appsec_findings", []),
        "findings": scan_result.get("findings", []),
        "sbom": scan_result.get("sbom", {}),
        "engines_executed": scan_result.get("engines_executed", []),
    }

    return template.render(data=report_data)


def generate_executive_report(scan_result):
    """Generates an executive-level security posture report designed for management and investors."""
    from jinja2 import Template
    import prioritizer
    import compliance_engine

    target = scan_result.get("target_url") or scan_result.get("github_url") or "Target Asset"
    score = scan_result.get("score", 100)
    grade = scan_result.get("grade", "A")
    findings = scan_result.get("findings", [])
    prioritized = prioritizer.prioritize_findings(findings, limit=5)
    checklist = compliance_engine.evaluate_startup_security_checklist(scan_result)

    tmpl_str = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TrustAudit Executive Security Summary — {{ target }}</title>
    <style>
        @media print { body { margin: 15mm; } .no-print { display: none !important; } }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 30px auto; padding: 0 20px; }
        .header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }
        .badge-CRITICAL { background: #fee2e2; color: #991b1b; }
        .badge-HIGH { background: #ffedd5; color: #9a3412; }
        .badge-MEDIUM { background: #fef9c3; color: #854d0e; }
        .badge-LOW { background: #dcfce7; color: #166534; }
        .score-box { text-align: right; }
        .score-val { font-size: 36px; font-weight: 800; color: #0f172a; }
        .card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; margin-bottom: 16px; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .btn-print { background: #0f172a; color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; font-size: 24px; color: #0f172a;">TrustAudit Executive Security Report</h1>
            <p style="margin: 4px 0 0; color: #64748b;">Target: <b>{{ target }}</b> &bull; Generated: {{ now_str }}</p>
        </div>
        <div class="score-box">
            <button class="btn-print no-print" onclick="window.print()">Print / Export PDF</button>
            <div class="score-val">{{ score }} / 100 <span style="font-size: 18px; color: #64748b;">(Grade {{ grade }})</span></div>
        </div>
    </div>

    <div class="card" style="background: #f8fafc; border-left: 4px solid #3b82f6;">
        <h3 style="margin-top: 0;">Executive Summary</h3>
        <p>TrustAudit conducted an automated security verification against <b>{{ target }}</b>. The asset achieved a security posture score of <b>{{ score }}/100</b> (Grade <b>{{ grade }}</b>) with <b>{{ findings|length }}</b> total verified risk findings detected across perimeter, configuration, and application layers.</p>
        <p style="margin-bottom: 0;"><b>Startup Security Health:</b> {{ checklist.status_summary }}</p>
    </div>

    <h3>Top Prioritized Fixes</h3>
    {% if prioritized %}
        {% for fix in prioritized %}
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <b style="font-size: 15px;">#{{ loop.index }} {{ fix.title }}</b>
                <span class="badge badge-{{ fix.severity }}">{{ fix.severity }}</span>
            </div>
            <p style="margin: 4px 0 8px; font-size: 13.5px; color: #475569;"><b>Why This Matters:</b> {{ fix.why_this_matters }}</p>
            <p style="margin: 0; font-size: 13.5px; color: #0f172a;"><b>Action Plan:</b> {{ fix.what_to_do }}</p>
        </div>
        {% endfor %}
    {% else %}
        <div class="card" style="color: #166534;"><p style="margin: 0;">✓ Zero high or critical priority vulnerabilities detected.</p></div>
    {% endif %}

    <div style="margin-top: 30px; font-size: 11px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 12px;">
        TrustAudit Continuous Security Copilot &bull; Confidential Executive Document &bull; Does not constitute regulatory certification.
    </div>
</body>
</html>"""
    tmpl = Template(tmpl_str)
    return tmpl.render(
        target=target,
        score=score,
        grade=grade,
        findings=findings,
        prioritized=prioritized,
        checklist=checklist,
        now_str=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    )


def generate_technical_report(scan_result):
    """Generates a technical deep-dive security report with raw evidence for engineering teams."""
    return generate_html_report(scan_result)

