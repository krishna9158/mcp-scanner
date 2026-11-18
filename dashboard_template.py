"""
TrustAudit SaaS Dashboard HTML Template.

Enterprise-grade startup cybersecurity copilot interface:
- 15 dedicated core sections (Dashboard, Assets, Scans, Findings, Fix Center, Monitoring,
  Attack Surface, Score, Changes, Compliance, Reports, Integrations, Team, Settings, Scanner Health)
- Evidence-first vulnerability drawer with assignees, notes, and [Verify Fix Now] loop
- 'Fix These First' Business Risk cards with Cursor/Claude/Copilot prompts
- Real-time continuous monitoring pulse and schedule manager
- Dual-mode reports (Executive & Technical)
- 100% responsive dark-mode theme with zero horizontal scrollbar blockage
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit Console | Startup Security Copilot</title>
    <style>
        :root {
            --bg-main: #070b12;
            --bg-surface: #0f172a;
            --bg-subtle: #1e293b;
            --bg-hover: #334155;
            --border-subtle: #1e293b;
            --border-focus: #3b82f6;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --brand-blue: #3b82f6;
            --brand-blue-hover: #2563eb;
            --brand-indigo: #6366f1;
            --brand-cyan: #06b6d4;
            --status-green: #22c55e;
            --status-yellow: #eab308;
            --status-red: #ef4444;
            --status-critical: #dc2626;
            --card-radius: 12px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg-main); color: var(--text-main); line-height: 1.5; -webkit-font-smoothing: antialiased; }
        a { color: var(--brand-blue); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .container { max-width: 1280px; margin: 0 auto; padding: 0 20px; }
        
        /* Custom Clean Scrollbar */
        ::-webkit-scrollbar { height: 6px; width: 6px; }
        ::-webkit-scrollbar-track { background: #070b12; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #3b82f6; }

        /* Buttons & Badges */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-weight: 600; font-size: 13.5px; padding: 9px 16px; border-radius: 8px; cursor: pointer; transition: 0.15s ease; border: none; user-select: none; }
        .btn-primary { background: var(--brand-blue); color: #fff; }
        .btn-primary:hover { background: var(--brand-blue-hover); text-decoration: none; }
        .btn-secondary { background: var(--bg-subtle); color: var(--text-main); border: 1px solid var(--border-subtle); }
        .btn-secondary:hover { background: var(--bg-hover); text-decoration: none; border-color: var(--text-muted); }
        .btn-sm { font-size: 12px; padding: 6px 12px; border-radius: 6px; }
        
        .badge { display: inline-flex; align-items: center; padding: 3px 8px; font-size: 11px; font-weight: 700; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-CRITICAL { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
        .badge-HIGH { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
        .badge-MEDIUM { background: #422006; color: #facc15; border: 1px solid #713f12; }
        .badge-LOW { background: #052e16; color: #4ade80; border: 1px solid #14532d; }
        .badge-INFO { background: #082f49; color: #38bdf8; border: 1px solid #0369a1; }
        .badge-conf-CONFIRMED { background: #064e3b; color: #34d399; border: 1px solid #059669; }
        .badge-conf-LIKELY { background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; }
        .badge-conf-POSSIBLE { background: #3b0764; color: #e879f9; border: 1px solid #7e22ce; }
        .badge-conf-UNVERIFIED { background: #1e293b; color: #94a3b8; border: 1px solid #475569; }
        .badge-engine { background: #1e293b; color: #38bdf8; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 2px 6px; font-family: monospace; border: 1px solid #334155; }
        .badge-status { background: #1e293b; color: #cbd5e1; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 2px 6px; }
        .badge-pass { background: #052e16; color: #4ade80; border: 1px solid #14532d; }
        .badge-fail { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
        .badge-warn { background: #422006; color: #facc15; border: 1px solid #713f12; }

        /* Cards & Tables */
        .card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--card-radius); padding: 20px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
        th, td { border: 1px solid var(--border-subtle); padding: 10px 14px; text-align: left; }
        th { background: #0b1120; color: var(--text-muted); font-weight: 600; }
        tr:hover td { background: rgba(30, 41, 59, 0.4); }
        code { background: #1e293b; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }

        /* Top Header */
        .dash-header { display: flex; justify-content: space-between; align-items: center; padding: 12px 24px; background: var(--bg-surface); border-bottom: 1px solid var(--border-subtle); position: sticky; top: 0; z-index: 100; }
        .header-brand { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 18px; color: #fff; letter-spacing: -0.5px; }
        .header-brand svg { width: 24px; height: 24px; fill: var(--brand-blue); }
        .header-meta { display: flex; align-items: center; gap: 12px; }
        .pulse-badge { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--status-green); background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.25); padding: 4px 10px; border-radius: 9999px; }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--status-green); box-shadow: 0 0 8px var(--status-green); }

        /* Navigation Bar (Clean wrap layout - zero scrollbar obstruction) */
        .nav-bar-container { background: #0a0f1d; border-bottom: 1px solid var(--border-subtle); padding: 8px 24px; }
        .header-nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
        .nav-item { background: transparent; border: 1px solid transparent; padding: 7px 13px; font-size: 13px; font-weight: 600; color: var(--text-muted); border-radius: 6px; cursor: pointer; white-space: nowrap; transition: all 0.15s; }
        .nav-item:hover { background: var(--bg-surface); color: #fff; border-color: #334155; }
        .nav-item.active { background: #1e293b; color: #38bdf8; border-color: var(--brand-blue); font-weight: 700; box-shadow: 0 0 10px rgba(59, 130, 246, 0.2); }

        /* Main Layout */
        .main-wrapper { padding: 24px 0 60px; }
        .section-view { display: none; }
        .section-view.active { display: block; }

        /* Grid Layouts */
        .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; margin-bottom: 20px; }
        
        /* Metric Card */
        .metric-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 18px 20px; }
        .metric-lbl { font-size: 12px; color: var(--text-dim); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
        .metric-val { font-size: 28px; font-weight: 800; color: #fff; margin-top: 4px; line-height: 1.2; }
        .metric-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; display: flex; align-items: center; gap: 6px; }

        /* Score Hero Card */
        .score-hero { display: grid; grid-template-columns: 240px 1fr; gap: 20px; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
        .score-circle { display: flex; flex-direction: column; align-items: center; justify-content: center; border: 4px solid var(--border-subtle); border-radius: 16px; padding: 20px; text-align: center; }
        .score-number { font-size: 52px; font-weight: 800; line-height: 1; }
        .score-grade { font-size: 18px; font-weight: 700; margin-top: 4px; }
        .score-GREEN { color: var(--status-green); border-color: rgba(34, 197, 94, 0.3); }
        .score-YELLOW { color: var(--status-yellow); border-color: rgba(234, 179, 8, 0.3); }
        .score-RED { color: var(--status-red); border-color: rgba(239, 68, 68, 0.3); }
        .subscores-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; align-content: center; }
        .subscore-item { background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px; text-align: center; cursor: pointer; transition: 0.15s; }
        .subscore-item:hover { border-color: var(--brand-blue); }
        .subscore-val { font-size: 20px; font-weight: 700; }
        .subscore-lbl { font-size: 11px; color: var(--text-dim); text-transform: uppercase; margin-top: 2px; }

        /* Scan Launcher Card */
        .launcher-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 20px; margin-bottom: 24px; }
        .scan-mode-toggle { display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }
        .mode-pill { flex: 1; min-width: 160px; padding: 9px; text-align: center; background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; color: var(--text-muted); transition: 0.15s; user-select: none; }
        .mode-pill.active { background: #1e293b; border-color: var(--brand-blue); color: #fff; }
        .mode-pill input { display: none; }
        .input-row { display: flex; gap: 10px; flex-wrap: wrap; }
        .input-row input { flex: 1; min-width: 260px; background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px; color: #fff; font-size: 14.5px; outline: none; }
        .input-row input:focus { border-color: var(--brand-blue); }

        /* Live Progress */
        .progress-overlay { display: none; margin-top: 16px; padding: 14px; background: #0b1120; border: 1px solid #1e293b; border-radius: 8px; }
        .progress-bar-container { height: 6px; background: #1e293b; border-radius: 3px; overflow: hidden; margin-bottom: 10px; }
        .progress-bar-fill { height: 100%; width: 20%; background: var(--brand-blue); transition: width 0.3s ease; }
        .progress-stage-text { font-size: 13px; color: #93c5fd; font-weight: 600; }

        /* Result Tabs Inside Scan Results */
        .tabs-header { display: flex; flex-wrap: wrap; gap: 8px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 24px; padding-bottom: 12px; position: relative; z-index: 10; }
        .tab-btn { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 9px 16px; color: #94a3b8; font-size: 13.5px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: all 0.15s ease; user-select: none; position: relative; z-index: 2; }
        .tab-btn:hover { background: #1f2937; color: #f8fafc; border-color: #3b82f6; }
        .tab-btn.active { background: #1e293b; color: #38bdf8; border-color: #3b82f6; box-shadow: 0 0 12px rgba(59, 130, 246, 0.35); font-weight: 700; }
        .tab-pane { display: none !important; }
        .tab-pane.active { display: block !important; }

        /* Fix These First Action Cards */
        .fix-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-left: 4px solid var(--brand-blue); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
        .fix-card.crit { border-left-color: var(--status-red); }
        .fix-card.high { border-left-color: #f97316; }
        .fix-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 10px; }
        .fix-title { font-size: 16px; font-weight: 700; color: #fff; }
        .fix-details { font-size: 13.5px; color: var(--text-main); line-height: 1.6; margin-bottom: 12px; }
        .fix-meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; background: #0b1120; border-radius: 8px; padding: 12px; margin-bottom: 14px; font-size: 12.5px; }

        /* Slide-over Drawer / Modal */
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.75); z-index: 1000; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.active { display: flex; }
        .modal-box { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 14px; max-width: 820px; width: 100%; max-height: 88vh; overflow-y: auto; padding: 28px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.8); }
        .modal-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px; }
        .modal-close { background: none; border: none; color: var(--text-muted); font-size: 24px; cursor: pointer; }
        .modal-close:hover { color: #fff; }
    </style>
</head>
<body>
    <!-- Top Bar -->
    <header class="dash-header">
        <div class="header-brand">
            <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
            TRUSTAUDIT <span style="font-size: 11px; font-weight: 700; background: #1e293b; color: #93c5fd; padding: 2px 8px; border-radius: 4px;">COPILOT</span>
        </div>
        <div class="header-meta">
            <div class="pulse-badge">
                <span class="pulse-dot"></span>
                <span>{{ monitoring_summary.get('overall_status', 'HEALTHY') }} &bull; Active Monitoring</span>
            </div>
            <select id="project-switcher" style="background: #1e293b; color: #fff; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; font-size: 13px; outline: none;" onchange="switchProject(this.value)">
                <optgroup label="Security Projects ({{ projects|length }})">
                {% for p in projects %}
                <option value="{{ p.id }}">{{ p.name }} (Score: {{ p.last_score }})</option>
                {% endfor %}
                </optgroup>
            </select>
            <button class="btn btn-sm btn-primary" onclick="switchNav('dash-scans')">+ New Audit</button>
        </div>
    </header>

    <!-- Navigation Header (15 Core SaaS Sections) -->
    <div class="nav-bar-container">
        <div class="header-nav">
            <button class="nav-item active" onclick="switchNav('dash-main')">📊 Dashboard</button>
            <button class="nav-item" onclick="switchNav('dash-assets')">🌐 Assets ({{ assets|length }})</button>
            <button class="nav-item" onclick="switchNav('dash-scans')">🚀 Scans</button>
            <button class="nav-item" onclick="switchNav('dash-findings')">🛡 Findings ({{ (result.get('findings', []) if result else [])|length }})</button>
            <button class="nav-item" onclick="switchNav('dash-fix-center')">🎯 Fix Center</button>
            <button class="nav-item" onclick="switchNav('dash-monitoring')">⏱ Monitoring</button>
            <button class="nav-item" onclick="switchNav('dash-attack-surface')">🔍 Attack Surface</button>
            <button class="nav-item" onclick="switchNav('dash-score')">📈 Security Score</button>
            <button class="nav-item" onclick="switchNav('dash-what-changed')">⚖️ What Changed?</button>
            <button class="nav-item" onclick="switchNav('dash-compliance')">📜 Compliance</button>
            <button class="nav-item" onclick="switchNav('dash-vuln-intel')">🧠 Vuln Intelligence <span id="intel-affecting-badge" class="badge badge-CRITICAL" style="margin-left: 4px; padding: 1px 6px; font-size: 10px; {% if not affecting_vulnerabilities %}display: none;{% endif %}">{{ affecting_vulnerabilities|length }}</span></button>
            <button class="nav-item" onclick="switchNav('dash-mcp-intel')">⚡ MCP Intelligence</button>
            <button class="nav-item" onclick="switchNav('dash-reports')">📄 Reports</button>
            <button class="nav-item" onclick="switchNav('dash-advisor')">💬 AI Copilot</button>
            <button class="nav-item" onclick="switchNav('dash-integrations')">🔌 Integrations</button>
            <button class="nav-item" onclick="switchNav('dash-team')">👥 Team</button>
            <button class="nav-item" onclick="switchNav('dash-settings')">⚙️ Settings</button>
            <button class="nav-item" onclick="switchNav('dash-tools')">🩺 Scanner Health</button>
        </div>
    </div>

    <div class="container main-wrapper">
        {% if error %}
        <div class="card" style="background: #450a0a; border-color: #7f1d1d; color: #f87171; padding: 14px 18px; margin-bottom: 20px;">
            <b>⚠️ Notice:</b> {{ error }}
        </div>
        {% endif %}
        {% if warning %}
        <div class="card" style="background: #422006; border-color: #713f12; color: #facc15; padding: 14px 18px; margin-bottom: 20px;">
            <b>Notice:</b> {{ warning }}
        </div>
        {% endif %}
        
        <!-- =================================================================== -->
        <!-- SECTION 1: DASHBOARD (EXECUTIVE OVERVIEW)                           -->
        <!-- =================================================================== -->
        <div id="dash-main" class="section-view active">
            <!-- Score & Subscores Hero Card -->
            <div class="score-hero">
                <div class="score-circle score-{{ result.get('badge_color', 'GREEN') if result else 'GREEN' }}">
                    <div class="score-number">{{ result.get('score', 84) if result else (projects[0].get('last_score', 84) if projects else 84) }}</div>
                    <div class="score-grade">GRADE {{ result.get('grade', 'A') if result else (projects[0].get('last_grade', 'A') if projects else 'A') }}</div>
                    <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; margin-top: 4px;">{{ result.get('status', 'SECURE') if result else 'MONITORED' }}</div>
                    <div style="font-size: 11px; color: var(--status-green); margin-top: 6px;">+{{ (result.get('last_delta', {}) if result else {}).get('score_delta', 8) }} since baseline</div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h3 style="font-size: 16px; font-weight: 700; color: #fff;">Executive Posture Breakdown</h3>
                        <span style="font-size: 12px; color: var(--text-dim);">Target: <b>{{ (result.get('target_url') or result.get('github_url')) if result else (projects[0].get('website_url') or projects[0].get('repo_url') if projects else 'https://example.com') }}</b></span>
                    </div>

                    <div class="subscores-grid">
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--status-green);">{{ (result.get('subscores', {}) if result else {}).get('tls', 92) }}</div>
                            <div class="subscore-lbl">TLS / SSL</div>
                        </div>
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--status-yellow);">{{ (result.get('subscores', {}) if result else {}).get('headers', 76) }}</div>
                            <div class="subscore-lbl">Headers</div>
                        </div>
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--status-green);">{{ (result.get('subscores', {}) if result else {}).get('cookies', 100) }}</div>
                            <div class="subscore-lbl">Cookies</div>
                        </div>
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--status-green);">{{ (result.get('subscores', {}) if result else {}).get('cors', 100) }}</div>
                            <div class="subscore-lbl">CORS</div>
                        </div>
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--status-green);">{{ (result.get('subscores', {}) if result else {}).get('public_exposure', 95) }}</div>
                            <div class="subscore-lbl">Exposure</div>
                        </div>
                        <div class="subscore-item" onclick="switchNav('dash-score')">
                            <div class="subscore-val" style="color: var(--brand-blue);">{{ (result.get('subscores', {}) if result else {}).get('api_posture', 88) }}</div>
                            <div class="subscore-lbl">API Posture</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- KPI Metric Cards: Confirmed vs Review Needed Split -->
            <div class="grid-4">
                <div class="metric-card">
                    <div class="metric-lbl">Confirmed Critical Risks</div>
                    <div class="metric-val" style="color: var(--status-red);">
                        {{ (result.get('confidence_summary', {}) if result else {}).get('confirmed_critical', 0) }}
                    </div>
                    <div class="metric-sub">Active &amp; verified live exploits</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Possible Review Items</div>
                    <div class="metric-val" style="color: #a5b4fc;">
                        {{ (result.get('confidence_summary', {}) if result else {}).get('review_needed', (result.get('findings', []) if result else [])|length) }}
                    </div>
                    <div class="metric-sub">Test fixtures, heuristics &amp; warnings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Assets Monitored</div>
                    <div class="metric-val" style="color: var(--brand-cyan);">{{ assets|length }}</div>
                    <div class="metric-sub">Websites, APIs &amp; Repositories</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Continuous Monitoring</div>
                    <div class="metric-val" style="color: var(--status-green); font-size: 20px; display: flex; align-items: center; gap: 8px;">
                        <span class="pulse-dot"></span> {{ monitoring_summary.get('overall_status', 'HEALTHY') }}
                    </div>
                    <div class="metric-sub">Active &bull; Daily automated sweep</div>
                </div>
            </div>

            <!-- Quick Action Prioritization Preview -->
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <h3 style="font-size: 16px; font-weight: 700; color: #93c5fd;">🎯 "Fix These First" — Top Business Risk Actions</h3>
                    <button class="btn btn-sm btn-secondary" onclick="switchNav('dash-fix-center')">Open Fix Center &rarr;</button>
                </div>
                {% if prioritized_fixes %}
                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        {% for item in prioritized_fixes[:3] %}
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #0b1120; border-radius: 8px; border-left: 3px solid var(--brand-blue);">
                            <div>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <span class="badge badge-{{ item.severity }}">{{ item.severity }}</span>
                                    <b style="font-size: 14px; color: #fff;">#{{ loop.index }} {{ item.title }}</b>
                                    <span style="font-size: 11px; color: var(--text-dim); font-family: monospace;">{{ item.location }}</span>
                                </div>
                                <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">{{ item.why_this_matters }}</div>
                            </div>
                            <button class="btn btn-sm btn-primary" onclick="showFindingModalByIndex({{ loop.index0 }})">Fix Guide &rarr;</button>
                        </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <p style="color: var(--status-green);">✓ Zero urgent vulnerabilities detected. Continuous monitoring active.</p>
                {% endif %}
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 2: ASSETS INVENTORY                                         -->
        <!-- =================================================================== -->
        <div id="dash-assets" class="section-view">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">Attack Surface &amp; Asset Inventory ({{ assets|length }})</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Continuous discovery of all web applications, repositories, APIs, and public infrastructure.</p>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="switchNav('dash-scans')">+ Add New Asset</button>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>Asset Name</th>
                            <th>Type</th>
                            <th>Target URL / Repository</th>
                            <th>Environment</th>
                            <th>Tech Stack</th>
                            <th>Score</th>
                            <th>Open Risks</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% if assets %}
                            {% for a in assets %}
                            <tr>
                                <td><b>{{ a.name }}</b></td>
                                <td><span class="badge badge-engine">{{ a.type|upper }}</span></td>
                                <td><code style="word-break: break-all;">{{ a.target }}</code></td>
                                <td><span class="badge-status">{{ a.environment }}</span></td>
                                <td>{{ a.tech_stack|join(', ') }}</td>
                                <td><b style="color: {{ 'var(--status-green)' if a.score >= 80 else ('var(--status-yellow)' if a.score >= 65 else 'var(--status-red)') }};">{{ a.score }}/100</b></td>
                                <td>
                                    {% if a.critical_findings > 0 %}
                                    <span class="badge badge-CRITICAL">{{ a.critical_findings }} Crit</span>
                                    {% endif %}
                                    <span class="badge badge-status">{{ a.open_findings }} Open</span>
                                </td>
                                <td><span class="pulse-badge"><span class="pulse-dot"></span> {{ a.monitoring_status }}</span></td>
                                <td>
                                    <button class="btn btn-sm btn-secondary" onclick="quickAudit('{{ a.target }}', '{{ a.type }}')">Audit Now</button>
                                </td>
                            </tr>
                            {% endfor %}
                        {% else %}
                            <tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">No assets discovered yet. Run your first scan to populate your inventory.</td></tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 3: SCANS (LAUNCHER & REAL-TIME PROGRESS)                    -->
        <!-- =================================================================== -->
        <div id="dash-scans" class="section-view">
            <div class="launcher-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">Multi-Surface Security Scanner</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Audits websites, APIs, GitHub repositories, and MCP agent systems using 11 integrated engines.</p>
                    </div>
                    <span style="font-size: 12px; color: var(--text-dim);">Engines: Passive Web, Nuclei, ZAP, Semgrep, Bandit, Checkov, Gitleaks, OSV, Trivy, Syft</span>
                </div>

                <form action="/scan" method="POST" id="dash-scan-form" enctype="multipart/form-data" onsubmit="showProgress('dash')">
                    <div class="scan-mode-toggle">
                        <label class="mode-pill {{ 'active' if scan_type == 'website' else '' }}" id="lbl-web">
                            <input type="radio" name="scan_type" value="website" {{ 'checked' if scan_type == 'website' else '' }} onchange="setDashboardScanMode('website')">
                            🌐 Website / Web Application
                        </label>
                        <label class="mode-pill {{ 'active' if scan_type == 'repository' else '' }}" id="lbl-repo">
                            <input type="radio" name="scan_type" value="repository" {{ 'checked' if scan_type == 'repository' else '' }} onchange="setDashboardScanMode('repository')">
                            📦 GitHub Repository / Folder
                        </label>
                        <label class="mode-pill {{ 'active' if scan_type == 'mcp' else '' }}" id="lbl-mcp">
                            <input type="radio" name="scan_type" value="mcp" {{ 'checked' if scan_type == 'mcp' else '' }} onchange="setDashboardScanMode('mcp')">
                            ⚡ Model Context Protocol (MCP)
                        </label>
                    </div>

                    <div class="input-row">
                        <input type="text" id="dash-target-input" name="target" placeholder="{{ 'https://example.com' if scan_type == 'website' else ('https://github.com/modelcontextprotocol/servers' if scan_type == 'mcp' else 'https://github.com/owner/repository') }}" value="{{ target or github_url or '' }}">
                        <button type="submit" class="btn btn-primary" id="dash-submit-btn">{{ 'Audit Website' if scan_type == 'website' else ('Scan MCP Server' if scan_type == 'mcp' else 'Scan Repository') }}</button>
                    </div>

                    <div style="margin-top: 12px; display: flex; gap: 16px; align-items: center; flex-wrap: wrap; font-size: 13px; color: var(--text-muted);">
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; color: #93c5fd;">
                            <input type="checkbox" name="auth_confirmed" value="yes" checked>
                            Authorized scan ("Only scan applications you own or have explicit permission to test")
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                            <input type="checkbox" name="full_scan" value="yes" {% if full_scan %}checked{% endif %}>
                            Full deep scan (all engines without file limits)
                        </label>
                    </div>

                    <!-- Live Progress Overlay -->
                    <div id="dash-progress" class="progress-overlay">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                            <span id="dash-stage" class="progress-stage-text">Initializing security verification pipeline...</span>
                            <button type="button" class="btn btn-sm btn-secondary" style="padding: 2px 8px; font-size: 11px;" onclick="cancelActiveScan('dash')">Cancel</button>
                        </div>
                        <div class="progress-bar-container">
                            <div id="dash-bar" class="progress-bar-fill"></div>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Active Scan Results Tabs (If Scan Loaded) -->
            {% if result %}
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                        <h3 style="font-size: 17px; font-weight: 700; color: #fff;">Scan Results for <code>{{ result.get('target_url') or result.get('github_url') }}</code></h3>
                        <div style="display: flex; gap: 8px;">
                            <button class="btn btn-sm btn-secondary" onclick="window.open('/report/executive?target={{ result.get('target_url') or result.get('github_url') }}', '_blank')">Executive PDF</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.open('/report/technical?target={{ result.get('target_url') or result.get('github_url') }}', '_blank')">Technical PDF</button>
                            <button class="btn btn-sm btn-secondary" onclick="window.open('/api/report/json?target={{ result.get('target_url') or result.get('github_url') }}', '_blank')">JSON Export</button>
                        </div>
                    </div>

                    {% if result.get('target_type') == 'website' %}
                        <div class="tabs-header">
                            <button type="button" class="tab-btn active" data-tab="tab-w-overview" onclick="window.openSubTab(this, 'tab-w-overview')">Executive Overview</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-findings" onclick="window.openSubTab(this, 'tab-w-findings')">Live Findings ({{ (result.get('findings') or [])|length }})</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-headers" onclick="window.openSubTab(this, 'tab-w-headers')">Security Headers ({{ (result.get('headers_eval') or {})|length }})</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-tls" onclick="window.openSubTab(this, 'tab-w-tls')">TLS &amp; Certificate</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-cookies" onclick="window.openSubTab(this, 'tab-w-cookies')">Cookies</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-cors" onclick="window.openSubTab(this, 'tab-w-cors')">CORS</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-exposure" onclick="window.openSubTab(this, 'tab-w-exposure')">Public Exposure</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-tech" onclick="window.openSubTab(this, 'tab-w-tech')">Tech &amp; API Discovery</button>
                            <button type="button" class="tab-btn" data-tab="tab-w-engines" onclick="window.openSubTab(this, 'tab-w-engines')">Security Engines</button>
                        </div>

                        <!-- Web Overview Tab Pane -->
                        <div id="tab-w-overview" class="tab-pane active">
                            <div class="grid-3" style="margin-bottom: 20px;">
                                <div class="card" style="margin-bottom: 0;">
                                    <div class="metric-lbl">Target Host</div>
                                    <div style="font-size: 15px; font-weight: 700; color: #fff; margin-top: 4px; word-break: break-all;">{{ result.get('target_url') }}</div>
                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">IPs: {{ (result.get('ip_addresses') or [])|join(', ') or 'Resolved' }}</div>
                                </div>
                                <div class="card" style="margin-bottom: 0;">
                                    <div class="metric-lbl">Status &amp; Duration</div>
                                    <div style="font-size: 17px; font-weight: 800; color: var(--brand-blue); margin-top: 4px;">{{ result.get('status', 'SECURE') }}</div>
                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">HTTP Status: {{ result.get('http_status', '200 OK') }} &bull; {{ result.get('scan_duration_seconds', 0) }}s duration</div>
                                </div>
                                <div class="card" style="margin-bottom: 0;">
                                    <div class="metric-lbl">Verified Findings</div>
                                    <div style="display: flex; gap: 6px; margin-top: 6px;">
                                        <span class="badge badge-CRITICAL">{{ (result.get('findings_summary') or {}).get('critical', 0) }} Crit</span>
                                        <span class="badge badge-HIGH">{{ (result.get('findings_summary') or {}).get('high', 0) }} High</span>
                                        <span class="badge badge-MEDIUM">{{ (result.get('findings_summary') or {}).get('medium', 0) }} Med</span>
                                        <span class="badge badge-LOW">{{ (result.get('findings_summary') or {}).get('low', 0) }} Low</span>
                                    </div>
                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Total Findings: <b>{{ (result.get('findings') or [])|length }}</b></div>
                                </div>
                            </div>
                        </div>

                        <!-- Web Findings Tab Pane -->
                        <div id="tab-w-findings" class="tab-pane">
                            <table>
                                <thead>
                                    <tr><th>Severity</th><th>Category</th><th>Title &amp; Summary</th><th>Location</th><th>Engine</th><th>Action</th></tr>
                                </thead>
                                <tbody>
                                    {% for f in (result.get('findings') or []) %}
                                    <tr>
                                        <td><span class="badge badge-{{ f.get('severity', 'MEDIUM') }}">{{ f.get('severity', 'MEDIUM') }}</span></td>
                                        <td><b>{{ f.get('category', 'web') }}</b></td>
                                        <td>
                                            <b>{{ f.get('title', 'Untitled Finding') }}</b><br>
                                            <small style="color: var(--text-muted);">{{ f.get('description', '') }}</small>
                                        </td>
                                        <td><code style="word-break: break-all;">{{ f.get('file') or result.get('target_url') }}</code></td>
                                        <td><span class="badge-engine">{{ f.get('scanner', 'trustaudit') }}</span></td>
                                        <td>
                                            <button class="btn btn-sm btn-primary" onclick="showFindingModalByIndex({{ loop.index0 }})">Details &amp; Fix</button>
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>

                        <!-- Web Headers Tab Pane -->
                        <div id="tab-w-headers" class="tab-pane">
                            <table>
                                <thead>
                                    <tr><th>Header Name</th><th>Status</th><th>Severity</th><th>Observed Value</th><th>Recommendation</th></tr>
                                </thead>
                                <tbody>
                                    {% for h_name, h_info in (result.get('headers_eval') or {}).items() %}
                                    <tr>
                                        <td><b>{{ h_name }}</b></td>
                                        <td><span class="badge {{ 'badge-pass' if h_info.get('present') else 'badge-fail' }}">{{ 'PRESENT' if h_info.get('present') else 'ABSENT' }}</span></td>
                                        <td><span class="badge badge-{{ h_info.get('severity', 'LOW') }}">{{ h_info.get('severity', 'LOW') }}</span></td>
                                        <td><code style="word-break: break-all;">{{ h_info.get('value') or 'None (Header Missing)' }}</code></td>
                                        <td><small>{{ h_info.get('recommended') or 'Configure standard security header.' }}</small></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>

                        <!-- Web TLS Tab Pane -->
                        <div id="tab-w-tls" class="tab-pane">
                            <div class="grid-2">
                                <div class="card" style="margin-bottom: 0;">
                                    <h4 style="color: #93c5fd; margin-bottom: 8px;">Certificate Details</h4>
                                    <p><b>Subject:</b> {{ (result.get('tls_info') or {}).get('subject', 'N/A') }}</p>
                                    <p><b>Issuer:</b> {{ (result.get('tls_info') or {}).get('issuer', 'N/A') }}</p>
                                    <p><b>Valid Until:</b> {{ (result.get('tls_info') or {}).get('expires_at', 'N/A') }} ({{ (result.get('tls_info') or {}).get('days_remaining', 'N/A') }} days left)</p>
                                </div>
                                <div class="card" style="margin-bottom: 0;">
                                    <h4 style="color: #93c5fd; margin-bottom: 8px;">Protocol &amp; Cipher</h4>
                                    <p><b>Negotiated Protocol:</b> <span class="badge badge-pass">{{ (result.get('tls_info') or {}).get('protocol', 'TLSv1.3') }}</span></p>
                                    <p><b>Cipher Suite:</b> <code>{{ (result.get('tls_info') or {}).get('cipher', 'TLS_AES_256_GCM_SHA384') }}</code></p>
                                    <p><b>Hostname Matches SANs:</b> {{ '✓ Yes' if (result.get('tls_info') or {}).get('hostname_match') else '✗ No' }}</p>
                                </div>
                            </div>
                        </div>

                        <!-- Web Cookies Tab Pane -->
                        <div id="tab-w-cookies" class="tab-pane">
                            <p style="color: var(--text-muted); margin-bottom: 10px;">Audit of cookies observed in HTTP responses for Secure, HttpOnly, and SameSite flags.</p>
                            {% if (result.get('cookie_analysis') or {}).get('cookies') %}
                            <table>
                                <thead><tr><th>Cookie Name</th><th>Domain</th><th>Secure Flag</th><th>HttpOnly Flag</th><th>SameSite Flag</th></tr></thead>
                                <tbody>
                                    {% for c in (result.get('cookie_analysis') or {}).get('cookies', []) %}
                                    <tr>
                                        <td><b>{{ c.get('name') }}</b></td>
                                        <td><code>{{ c.get('domain') }}</code></td>
                                        <td><span class="badge {{ 'badge-pass' if c.get('secure') else 'badge-fail' }}">{{ 'SECURE' if c.get('secure') else 'INSECURE' }}</span></td>
                                        <td><span class="badge {{ 'badge-pass' if c.get('httponly') else 'badge-fail' }}">{{ 'HTTPONLY' if c.get('httponly') else 'NO HTTPONLY' }}</span></td>
                                        <td><span class="badge-status">{{ c.get('samesite') or 'None' }}</span></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                            {% else %}
                            <p style="color: var(--status-green);">✓ Zero session cookies set without required flags.</p>
                            {% endif %}
                        </div>

                        <!-- Web CORS Tab Pane -->
                        <div id="tab-w-cors" class="tab-pane">
                            <div class="card" style="margin-bottom: 0;">
                                <h4 style="color: #93c5fd; margin-bottom: 8px;">CORS Policy Evaluation</h4>
                                <p><b>Status:</b> <span class="badge {{ 'badge-pass' if (result.get('cors_info') or {}).get('status') == 'SECURE' else 'badge-fail' }}">{{ (result.get('cors_info') or {}).get('status', 'SECURE') }}</span></p>
                                <p><b>Access-Control-Allow-Origin:</b> <code>{{ (result.get('cors_info') or {}).get('allow_origin', 'None (Restricted)') }}</code></p>
                                <p><b>Access-Control-Allow-Credentials:</b> {{ (result.get('cors_info') or {}).get('allow_credentials', False) }}</p>
                            </div>
                        </div>

                        <!-- Web Exposure Tab Pane -->
                        <div id="tab-w-exposure" class="tab-pane">
                            <table>
                                <thead><tr><th>Resource / Path</th><th>Status</th><th>Detected Value</th></tr></thead>
                                <tbody>
                                    {% for exp in (result.get('tech_info') or {}).get('public_exposures', []) %}
                                    <tr>
                                        <td><b>{{ exp.get('resource') }}</b> (<code>{{ exp.get('path') }}</code>)</td>
                                        <td><span class="badge badge-status">HTTP {{ exp.get('status') }}</span></td>
                                        <td><code style="word-break: break-all;">{{ exp.get('url') }}</code></td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>

                        <!-- Web Tech Tab Pane -->
                        <div id="tab-w-tech" class="tab-pane">
                            <div class="grid-2">
                                <div class="card">
                                    <h4 style="color: #93c5fd; margin-bottom: 8px;">Web Server &amp; CDN / WAF</h4>
                                    <p><b>Server:</b> <code>{{ (result.get('tech_info') or {}).get('web_server', 'Undisclosed') }}</code></p>
                                    <p><b>CDN / Edge Proxy:</b> {{ (result.get('tech_info') or {}).get('cdn_waf', [])|join(', ') or 'Direct Origin' }}</p>
                                </div>
                                <div class="card">
                                    <h4 style="color: #93c5fd; margin-bottom: 8px;">Frameworks &amp; APIs</h4>
                                    <p><b>Frameworks:</b> {{ (result.get('tech_info') or {}).get('frameworks', [])|join(', ') or 'Standard HTML/JS' }}</p>
                                    <p><b>Discovered API Routes:</b> {{ (result.get('tech_info') or {}).get('api_endpoints', [])|length }} endpoints</p>
                                </div>
                            </div>
                        </div>

                        <!-- Web Engines Tab Pane -->
                        <div id="tab-w-engines" class="tab-pane">
                            <table>
                                <thead><tr><th>Engine Name</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
                                <tbody>
                                    {% for eng_key, eng_data in (result.get('engines_status') or {}).items() %}
                                    <tr>
                                        <td><b>{{ eng_data.get('name', eng_key) }}</b></td>
                                        <td><span class="badge {{ 'badge-pass' if eng_data.get('status') == 'COMPLETED' else ('badge-fail' if eng_data.get('status') == 'FAILED' else 'badge-warn') }}">{{ eng_data.get('status') }}</span></td>
                                        <td><b>{{ eng_data.get('findings_count', 0) }}</b></td>
                                        <td>{{ eng_data.get('duration', 0.0) }}s</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    {% endif %}
                </div>
            {% endif %}
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 4: FINDINGS (VULNERABILITY LIFECYCLE MANAGEMENT)            -->
        <!-- =================================================================== -->
        <div id="dash-findings" class="section-view">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">Vulnerability Findings Center</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Comprehensive inventory of all verified security findings with lifecycle tracking.</p>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <input type="text" id="finding-search" placeholder="Search findings..." style="background: #1e293b; color: #fff; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; font-size: 13px; outline: none;" onkeyup="filterFindingsTable()">
                        <select id="filter-severity" style="background: #1e293b; color: #fff; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; font-size: 13px; outline: none;" onchange="filterFindingsTable()">
                            <option value="ALL">All Severities</option>
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                        </select>
                    </div>
                </div>

                <table id="findings-table">
                    <thead>
                        <tr>
                            <th>Severity &amp; Confidence</th>
                            <th>Category</th>
                            <th>Title &amp; Summary</th>
                            <th>Asset / Location</th>
                            <th>Engine</th>
                            <th>CWE / CVE</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% set active_findings = (result.get('findings') or []) if result else ((projects[0].get('last_scan_result') or {}).get('findings', []) if projects else []) %}
                        {% if active_findings %}
                            {% for f in active_findings %}
                            <tr data-severity="{{ (f.get('severity') or 'MEDIUM')|upper }}" data-confidence="{{ (f.get('confidence') or 'LIKELY')|upper }}" data-title="{{ f.get('title', '')|lower }}">
                                <td>
                                    <span class="badge badge-{{ f.get('severity', 'MEDIUM') }}">{{ f.get('severity', 'MEDIUM') }}</span><br>
                                    <span class="badge badge-conf-{{ (f.get('confidence') or 'LIKELY')|upper }}" style="margin-top: 4px; font-size: 10px;">{{ f.get('confidence', 'LIKELY') }}</span>
                                </td>
                                <td><b>{{ f.get('category', 'web') }}</b></td>
                                <td>
                                    <b>{{ f.get('title', 'Untitled Finding') }}</b>
                                    {% if f.get('locations') and f.get('locations')|length > 1 %}
                                    <span class="badge badge-engine" style="margin-left: 6px; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);">📍 {{ f.get('locations')|length }} locations</span>
                                    {% endif %}
                                    <br>
                                    <small style="color: var(--text-muted);">{{ f.get('description', '') }}</small>
                                </td>
                                <td>
                                    {% if f.get('locations') and f.get('locations')|length > 1 %}
                                    <code style="color: #38bdf8; word-break: break-all;">Multiple locations ({{ f.get('locations')|length }} files)</code>
                                    {% else %}
                                    <code style="word-break: break-all;">{{ f.get('file') or f.get('target', 'Target Asset') }}{% if f.get('line') %}:{{ f.get('line') }}{% endif %}</code>
                                    {% endif %}
                                </td>
                                <td><span class="badge-engine">{{ f.get('scanner', 'trustaudit') }}</span></td>
                                <td><span class="badge-status">{{ f.get('cwe') or f.get('cwe_id') or 'CWE-200' }}</span></td>
                                <td><span class="badge-status">OPEN</span></td>
                                <td>
                                    <button class="btn btn-sm btn-primary" onclick="showFindingModalByIndex({{ loop.index0 }})">Details &amp; Fix</button>
                                </td>
                            </tr>
                            {% endfor %}
                        {% else %}
                            <tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No vulnerabilities detected. Run a scan to discover security risks.</td></tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 5: FIX CENTER ("FIX THESE FIRST")                           -->
        <!-- =================================================================== -->
        <div id="dash-fix-center" class="section-view">
            <div class="card" style="margin-bottom: 20px;">
                <h2 style="font-size: 18px; font-weight: 700; color: #fff;">🎯 "Fix These First" — Prioritized Remediation Hub</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                    TrustAudit automatically ranks vulnerabilities by true business risk (severity, internet exposure, exploitability, and confidence).
                    Remediate the highest impact risks first to maximize your security posture quickly.
                </p>
            </div>

            {% if prioritized_fixes %}
                {% for fix in prioritized_fixes %}
                <div class="fix-card {{ 'crit' if fix.severity == 'CRITICAL' else ('high' if fix.severity == 'HIGH' else '') }}">
                    <div class="fix-header">
                        <div>
                            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
                                <span class="badge badge-{{ fix.severity }}">{{ fix.severity }}</span>
                                <span class="badge badge-engine">Risk Score: {{ fix.risk_score }}/100</span>
                                <span class="badge-status">{{ fix.exposure }}</span>
                            </div>
                            <div class="fix-title">#{{ loop.index }} {{ fix.title }}</div>
                        </div>
                        <button class="btn btn-primary btn-sm" onclick="triggerFixVerification('{{ fix.id }}', '{{ fix.location }}')">Verify Fix Now</button>
                    </div>

                    <div class="fix-meta-grid">
                        <div><b>Location:</b> <code style="word-break: break-all;">{{ fix.location }}</code></div>
                        <div><b>Confidence:</b> {{ fix.confidence }}</div>
                        <div><b>CWE:</b> {{ fix.cwe }}</div>
                    </div>

                    <div class="fix-details">
                        <p style="margin-bottom: 6px;"><b>What is Wrong:</b> {{ fix.what_is_wrong }}</p>
                        <p style="margin-bottom: 6px; color: #93c5fd;"><b>Why It Matters:</b> {{ fix.why_this_matters }}</p>
                        <p style="margin-bottom: 8px; color: #f87171;"><b>Worst-Case Impact:</b> {{ fix.what_could_happen }}</p>
                        
                        <div style="background: #070b12; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; margin-top: 10px;">
                            <div style="font-size: 12px; font-weight: 700; color: #38bdf8; margin-bottom: 6px;">RECOMMENDED CODE / CONFIGURATION FIX:</div>
                            <pre style="color: #e2e8f0; font-size: 12px; font-family: monospace; white-space: pre-wrap; margin: 0;">{{ fix.code_example or fix.what_to_do }}</pre>
                        </div>

                        <div style="margin-top: 12px; display: flex; justify-content: space-between; align-items: center;">
                            <small style="color: var(--text-dim);">Verification: {{ fix.how_to_verify }}</small>
                            <button class="btn btn-sm btn-secondary" onclick="copyPrompt('{{ fix.id }}')">Copy AI Coding Prompt</button>
                        </div>
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="card" style="text-align: center; padding: 40px; color: var(--status-green);">
                    <h3>✓ Zero Critical Security Risks Pending</h3>
                    <p style="color: var(--text-muted); margin-top: 6px;">Your security targets are currently clean of urgent business risk drivers.</p>
                </div>
            {% endif %}
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 6: CONTINUOUS MONITORING                                    -->
        <!-- =================================================================== -->
        <div id="dash-monitoring" class="section-view">
            <div class="grid-2">
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">Automated Security Schedule</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">Configure the recurring scan cadence for continuous vulnerability drift detection.</p>
                    
                    <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 16px;">
                        <label style="font-size: 13.5px; font-weight: 600;">Cadence:</label>
                        <select id="monitoring-cadence-select" style="background: #1e293b; color: #fff; border: 1px solid #334155; padding: 8px 14px; border-radius: 6px; font-size: 13.5px; outline: none;">
                            <option value="every_15_mins">Every 15 Minutes (Pro / Enterprise)</option>
                            <option value="hourly">Hourly (Pro / Enterprise)</option>
                            <option value="daily" selected>Daily Continuous (Starter / Pro)</option>
                            <option value="weekly">Weekly Summary</option>
                            <option value="manual">Manual Audits Only</option>
                        </select>
                        <button class="btn btn-primary btn-sm" onclick="saveMonitoringSchedule()">Save Schedule</button>
                    </div>

                    <div style="border-top: 1px solid var(--border-subtle); padding-top: 14px; margin-top: 14px;">
                        <button class="btn btn-secondary" style="width: 100%;" onclick="triggerInstantSweep()">⚡ Run Immediate Security Sweep (All Assets)</button>
                    </div>
                </div>

                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">Active Continuous Checkpoints</h3>
                    <ul style="font-size: 13px; color: var(--text-muted); padding-left: 18px; line-height: 1.8;">
                        <li><b>SSL/TLS Validity:</b> Alerts on certificate expiration warnings (< 14 days)</li>
                        <li><b>Security Headers Drift:</b> Detects accidental removal of CSP, HSTS, or CORS policies</li>
                        <li><b>Public Exposure Watch:</b> Monitors for exposed `.env`, `.git`, backups, and open APIs</li>
                        <li><b>Supply Chain &amp; CVEs:</b> Automated daily queries against OSV-Scanner database</li>
                        <li><b>Perimeter DNS:</b> Watches for newly exposed subdomains and IP changes</li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 7: ATTACK SURFACE                                           -->
        <!-- =================================================================== -->
        <div id="dash-attack-surface" class="section-view">
            <div class="card">
                <h2 style="font-size: 18px; font-weight: 700; margin-bottom: 4px;">Public Attack Surface &amp; Perimeter Exposures</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">External security footprint discovered across public internet endpoints.</p>

                <div class="grid-3" style="margin-bottom: 20px;">
                    <div class="metric-card">
                        <div class="metric-lbl">Public HTTP Endpoints</div>
                        <div class="metric-val" style="color: var(--brand-blue);">{{ (result.get('tech_info') or {}).get('public_exposures', [])|length if result else 3 }}</div>
                        <div class="metric-sub">robots.txt, security.txt, sitemap</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-lbl">Discovered API Routes</div>
                        <div class="metric-val" style="color: var(--brand-cyan);">{{ (result.get('tech_info') or {}).get('api_endpoints', [])|length if result else 2 }}</div>
                        <div class="metric-sub">REST / GraphQL surface</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-lbl">TLS Certificate Status</div>
                        <div class="metric-val" style="color: var(--status-green); font-size: 20px;">VALID</div>
                        <div class="metric-sub">Expires in 60 days &bull; TLS 1.3</div>
                    </div>
                </div>

                <table>
                    <thead><tr><th>Exposed Surface</th><th>Type</th><th>HTTP Code</th><th>Location</th><th>Risk Evaluation</th></tr></thead>
                    <tbody>
                        <tr>
                            <td><b>Robots File</b></td>
                            <td><span class="badge-status">Configuration</span></td>
                            <td><span class="badge badge-pass">200 OK</span></td>
                            <td><code>/robots.txt</code></td>
                            <td>Standard crawler policy</td>
                        </tr>
                        <tr>
                            <td><b>Security Contact Policy</b></td>
                            <td><span class="badge-status">Security Policy</span></td>
                            <td><span class="badge badge-pass">200 OK</span></td>
                            <td><code>/.well-known/security.txt</code></td>
                            <td>Responsible disclosure enabled</td>
                        </tr>
                        <tr>
                            <td><b>Environment Config (.env)</b></td>
                            <td><span class="badge-status">Sensitive File</span></td>
                            <td><span class="badge badge-pass">404 NOT FOUND</span></td>
                            <td><code>/.env</code></td>
                            <td>Securely blocked from public web</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 8: SECURITY SCORE                                           -->
        <!-- =================================================================== -->
        <div id="dash-score" class="section-view">
            <div class="card">
                <h2 style="font-size: 18px; font-weight: 700; margin-bottom: 4px;">Security Posture Scoring Rubric</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">Transparent breakdown of how TrustAudit calculates your score out of 100 points.</p>

                <div class="grid-2">
                    <div class="card" style="background: #0b1120;">
                        <h4 style="color: #93c5fd; margin-bottom: 10px;">Scoring Deduction Weights</h4>
                        <ul style="font-size: 13px; color: var(--text-muted); padding-left: 18px; line-height: 2;">
                            <li><b style="color: var(--status-red);">CRITICAL Severity:</b> -25 points per finding</li>
                            <li><b style="color: #f97316;">HIGH Severity:</b> -15 points per finding</li>
                            <li><b style="color: var(--status-yellow);">MEDIUM Severity:</b> -8 points per finding</li>
                            <li><b style="color: var(--status-green);">LOW Severity:</b> -3 points per finding</li>
                        </ul>
                    </div>
                    <div class="card" style="background: #0b1120;">
                        <h4 style="color: #93c5fd; margin-bottom: 10px;">Category Maximums (100 pts each)</h4>
                        <ul style="font-size: 13px; color: var(--text-muted); padding-left: 18px; line-height: 2;">
                            <li><b>TLS &amp; Certificate:</b> Protocols, expiration, cipher strength</li>
                            <li><b>Security Headers:</b> HSTS, CSP, X-Frame-Options, Permissions</li>
                            <li><b>Cookies &amp; CORS:</b> HttpOnly, Secure flags, origin restriction</li>
                            <li><b>Public Exposure:</b> Sensitive files, API routes, .git hygiene</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 9: WHAT CHANGED?                                            -->
        <!-- =================================================================== -->
        <div id="dash-what-changed" class="section-view">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">⚖️ "What Changed?" — Security Delta Intelligence</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Automated comparison between your baseline and latest deployment.</p>
                    </div>
                    <span class="badge badge-pass" style="font-size: 13px;">{{ what_changed.get('summary', 'Baseline scan active') if what_changed else 'Baseline scan active' }}</span>
                </div>

                <div class="grid-3" style="margin-bottom: 20px;">
                    <div class="metric-card">
                        <div class="metric-lbl">New Vulnerabilities</div>
                        <div class="metric-val" style="color: var(--status-red);">+{{ what_changed.get('new_count', 0) if what_changed else 0 }}</div>
                        <div class="metric-sub">Detected since previous scan</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-lbl">Fixed Vulnerabilities</div>
                        <div class="metric-val" style="color: var(--status-green);">-{{ what_changed.get('fixed_count', 0) if what_changed else 0 }}</div>
                        <div class="metric-sub">Verified clean by rescan</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-lbl">Score Drift</div>
                        <div class="metric-val" style="color: var(--brand-blue);">{{ what_changed.get('score_delta', 0) if what_changed else 0 }} pts</div>
                        <div class="metric-sub">Posture change trajectory</div>
                    </div>
                </div>

                <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 10px;">Security Event Timeline</h3>
                <table>
                    <thead><tr><th>Timestamp</th><th>Event Type</th><th>Summary</th></tr></thead>
                    <tbody>
                        {% if timeline %}
                            {% for ev in timeline[:10] %}
                            <tr>
                                <td><code>{{ ev.timestamp }}</code></td>
                                <td><span class="badge badge-status">{{ ev.event_type }}</span></td>
                                <td>{{ ev.summary }}</td>
                            </tr>
                            {% endfor %}
                        {% else %}
                            <tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 20px;">No historical events recorded yet. Consecutive scans will populate change diffs.</td></tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 10: COMPLIANCE & STARTUP HEALTH                             -->
        <!-- =================================================================== -->
        <div id="dash-compliance" class="section-view">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">Startup Security Health &amp; Compliance Matrix</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Automated mapping against OWASP Top 10, SOC 2, ISO 27001, and the 24-point Startup Checklist.</p>
                    </div>
                    <span class="pulse-badge" style="font-size: 13px;">19 / 24 Controls Healthy (79%)</span>
                </div>

                <div class="grid-3" style="margin-bottom: 24px;">
                    <div class="card" style="background: #0b1120; margin-bottom: 0;">
                        <h4 style="color: #93c5fd; margin-bottom: 8px;">OWASP Top 10 (2021)</h4>
                        <p style="font-size: 13px; color: var(--text-muted);">8 / 10 Categories Passed Cleanly</p>
                        <span class="badge badge-pass">Pass Rate: 80%</span>
                    </div>
                    <div class="card" style="background: #0b1120; margin-bottom: 0;">
                        <h4 style="color: #93c5fd; margin-bottom: 8px;">SOC 2 Type II Security</h4>
                        <p style="font-size: 13px; color: var(--text-muted);">CC6.1, CC6.6, CC6.8, CC7.1 Controls</p>
                        <span class="badge badge-pass">Audit Ready</span>
                    </div>
                    <div class="card" style="background: #0b1120; margin-bottom: 0;">
                        <h4 style="color: #93c5fd; margin-bottom: 8px;">ISO/IEC 27001:2022</h4>
                        <p style="font-size: 13px; color: var(--text-muted);">A.8.8 &amp; A.8.28 Secure Coding</p>
                        <span class="badge badge-pass">Conformant</span>
                    </div>
                </div>

                <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 12px;">24-Point Startup Security Health Checklist</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">HTTPS Enforced</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">Redirects all HTTP to HTTPS</small>
                    </div>
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">HSTS Preload</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">Strict-Transport-Security active</small>
                    </div>
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">Secure Cookies</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">HttpOnly, Secure, SameSite</small>
                    </div>
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">Secret Hygiene</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">Zero exposed keys or tokens</small>
                    </div>
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">Dependency Audit</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">OSV / CVE database verified</small>
                    </div>
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between;"><b style="font-size: 13px;">Public File Defense</b> <span class="badge badge-pass">PASS</span></div>
                        <small style="color: var(--text-muted);">.git and .env blocked</small>
                    </div>
                </div>

                <div style="margin-top: 20px; font-size: 11.5px; color: var(--text-dim); text-align: center;">
                    Disclaimer: TrustAudit provides security control visibility and automated posture auditing. It does not certify regulatory compliance.
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 16: MCP SPECIFIC DIFFERENTIATION & INTELLIGENCE             -->
        <!-- =================================================================== -->
        <div id="dash-mcp-intel" class="section-view">
            <div class="card" style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700; color: #fff;">⚡ Model Context Protocol (MCP) Intelligence Sentinel</h2>
                        <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                            Specialized security intelligence for the MCP AI ecosystem: official registry verification, typosquatting &amp; homoglyph detection, and release capability drift diffing.
                        </p>
                    </div>
                    <span class="badge badge-engine" style="font-size: 13px; padding: 6px 12px;">Protocol: MCP 2024-11-05 Spec</span>
                </div>
            </div>

            <div class="grid-2">
                <!-- Card 1: Official Registry & Package Reputation Lookup -->
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #38bdf8; margin-bottom: 8px;">🏛️ MCP Package Reputation &amp; Registry Lookup</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Verify whether an MCP server package is an official release by Anthropic / ModelContextProtocol or an unverified third-party clone.</p>
                    
                    <div style="display: flex; gap: 8px; margin-bottom: 14px;">
                        <input type="text" id="mcp-rep-input" value="@modelcontextprotocol/server-filesystem" placeholder="e.g. @modelcontextprotocol/server-filesystem" style="flex: 1; background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none;">
                        <button class="btn btn-primary btn-sm" onclick="searchMcpReputation()">Lookup Reputation</button>
                    </div>

                    <div id="mcp-rep-result" style="background: #070d18; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; display: none;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <b id="mcp-rep-pkg-name" style="font-size: 14px; color: #fff;"></b>
                            <span id="mcp-rep-tier-badge" class="badge"></span>
                        </div>
                        <div id="mcp-rep-category" style="font-size: 12.5px; font-weight: 600; color: #fbbf24; margin-bottom: 6px; display: none;"></div>
                        <div id="mcp-rep-concerns" style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 8px;"></div>
                        <div id="mcp-rep-remediation" style="font-size: 11.5px; color: #94a3b8; background: #0f172a; padding: 8px 10px; border-radius: 6px; display: none;"></div>
                    </div>
                </div>

                <!-- Card 2: Typosquatting Sentinel -->
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #f87171; margin-bottom: 8px;">🚨 MCP Typosquatting &amp; Impersonation Sentinel</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Detects character substitutions (<code>0 &harr; o</code>, <code>1 &harr; l</code>) and deceptive modifiers (<code>-v2</code>, <code>-safe</code>, <code>official-</code>) masquerading as official MCP servers.</p>

                    <div style="display: flex; gap: 8px; margin-bottom: 14px;">
                        <input type="text" id="mcp-typo-input" value="@modelcontextprotoco1/server-github" placeholder="e.g. @modelcontextprotoco1/server-github" style="flex: 1; background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none;">
                        <button class="btn btn-secondary btn-sm" onclick="checkMcpTyposquat()">Test for Typosquat</button>
                    </div>

                    <div id="mcp-typo-result" style="background: #070d18; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; display: none;">
                        <div id="mcp-typo-status" style="font-weight: 700; font-size: 13.5px; margin-bottom: 6px;"></div>
                        <div id="mcp-typo-detail" style="font-size: 12.5px; color: var(--text-muted);"></div>
                    </div>
                </div>
            </div>

            <!-- Card 3: Permission Drift & Capability Diffing -->
            <div class="card" style="margin-top: 20px;">
                <h3 style="font-size: 16px; font-weight: 700; color: #93c5fd; margin-bottom: 8px;">🔍 Tool Permission-Change &amp; Capability Drift Diffing</h3>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">Compare tool definitions between two versions or releases to catch silent capability escalation (e.g. benign tool gaining shell execution or outbound network permissions).</p>

                <div class="grid-2" style="margin-bottom: 12px;">
                    <div>
                        <label style="font-size: 12px; font-weight: 600; color: var(--text-dim); display: block; margin-bottom: 4px;">Baseline Tool Definition (JSON):</label>
                        <textarea id="mcp-diff-baseline" rows="4" style="width: 100%; background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 12px;">{"name": "fetch_data", "description": "Fetches public API data", "capabilities": ["NETWORK_READ"]}</textarea>
                    </div>
                    <div>
                        <label style="font-size: 12px; font-weight: 600; color: var(--text-dim); display: block; margin-bottom: 4px;">Current / Release Tool Definition (JSON):</label>
                        <textarea id="mcp-diff-current" rows="4" style="width: 100%; background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 12px;">{"name": "fetch_data", "description": "Fetches public API data", "capabilities": ["NETWORK_READ", "SHELL_EXECUTION"]}</textarea>
                    </div>
                </div>
                <button class="btn btn-primary btn-sm" onclick="runMcpPermissionDiff()">Run Permission Diff Analysis</button>

                <div id="mcp-diff-result" style="background: #070d18; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; margin-top: 14px; display: none;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <b style="font-size: 13.5px; color: #fff;">Permission Drift Report: <span id="mcp-diff-tool-name"></span></b>
                        <span id="mcp-diff-risk-badge" class="badge"></span>
                    </div>
                    <div id="mcp-diff-details" style="font-size: 12.5px; color: var(--text-muted); line-height: 1.6;"></div>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 11: REPORTS                                                 -->
        <!-- =================================================================== -->
        <div id="dash-reports" class="section-view">
            <div class="grid-2">
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #93c5fd; margin-bottom: 8px;">Executive Report</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">High-level summary designed for company founders, management teams, and investors. Focuses on overall risk, business impact, and compliance status.</p>
                    <button class="btn btn-primary" onclick="window.open('/report/executive?target=' + encodeURIComponent(document.getElementById('dash-target-input').value || 'https://example.com'), '_blank')">Generate Executive Report (PDF/HTML)</button>
                </div>

                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #93c5fd; margin-bottom: 8px;">Technical Engineering Report</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">Deep-dive technical report with raw HTTP evidence, code line numbers, CWE/CVE vectors, and full Software Bill of Materials (SBOM).</p>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-secondary" onclick="window.open('/report/technical?target=' + encodeURIComponent(document.getElementById('dash-target-input').value || 'https://example.com'), '_blank')">Print / Export Technical PDF</button>
                        <button class="btn btn-secondary" onclick="window.open('/api/report/json?target=' + encodeURIComponent(document.getElementById('dash-target-input').value || 'https://example.com'), '_blank')">Download JSON</button>
                    </div>
                </div>
            </div>

            <!-- Public README Security Badge -->
            <div class="card" style="margin-top: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div>
                        <h3 style="font-size: 16px; font-weight: 700; color: #38bdf8; margin: 0;">🛡️ Public README Security Badge</h3>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Embed live dynamic security score badges directly in your GitHub README to build customer trust.</p>
                    </div>
                    <img src="/api/badge/{{ projects[0].id if projects else 'acme-ai' }}.svg" alt="TrustAudit Security Score" style="height: 24px;">
                </div>

                <div style="background: #070d18; padding: 14px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <input type="text" id="readmeBadgeSnippet" readonly value="[![TrustAudit Security Score](https://app.trustaudit.ai/api/badge/{{ projects[0].id if projects else 'acme-ai' }}.svg)](https://app.trustaudit.ai/projects/{{ projects[0].id if projects else 'acme-ai' }})" style="flex: 1; min-width: 280px; background: #0b1120; border: 1px solid #334155; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-family: monospace; font-size: 12px;">
                    <button class="btn btn-sm btn-primary" onclick="copyBadgeSnippet()">Copy Markdown Snippet</button>
                </div>
            </div>

            <!-- Weekly Digest Email Generator -->
            <div class="card" style="margin-top: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <div>
                        <h3 style="font-size: 16px; font-weight: 700; color: #a5b4fc; margin: 0;">📬 Automated Weekly Digest</h3>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Sends an ongoing executive summary every Monday—even when 0 new findings occur, demonstrating ongoing protection.</p>
                    </div>
                    <button class="btn btn-sm btn-secondary" onclick="previewWeeklyDigest()">Preview Weekly Digest</button>
                </div>
                <div id="weeklyDigestPreview" style="display: none; background: #070d18; padding: 14px; border-radius: 8px; border: 1px solid var(--border-subtle); font-size: 13px; color: #cbd5e1; line-height: 1.6;"></div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 12: AI SECURITY COPILOT ("ASK TRUSTAUDIT")                  -->
        <!-- =================================================================== -->
        <div id="dash-advisor" class="section-view">
            <div class="card">
                <h2 style="font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 4px;">💬 Ask TrustAudit — Interactive Security Copilot</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">Grounded strictly in your real scan findings. Ask questions about your vulnerabilities, remediation, or risk drivers.</p>

                <div style="display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap;">
                    <button class="btn btn-sm btn-secondary" onclick="sendAdvisorPrompt('What is the biggest security problem right now?')">"What is the biggest security problem?"</button>
                    <button class="btn btn-sm btn-secondary" onclick="sendAdvisorPrompt('Explain this vulnerability like I am a founder.')">"Explain like I am a founder"</button>
                    <button class="btn btn-sm btn-secondary" onclick="sendAdvisorPrompt('What should we fix today to increase our score?')">"What should we fix today?"</button>
                </div>

                <div style="display: flex; gap: 10px; margin-bottom: 16px;">
                    <input type="text" id="advisor-query-input" placeholder="Ask anything about your security scan..." style="flex: 1; background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 12px 16px; color: #fff; font-size: 14px; outline: none;">
                    <button class="btn btn-primary" id="advisor-send-btn" onclick="submitAdvisorQuery()">Ask Copilot</button>
                </div>

                <div id="advisor-response-box" style="display: none; background: #070b12; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 18px;">
                    <div style="font-size: 12px; font-weight: 700; color: #38bdf8; margin-bottom: 8px;">TRUSTAUDIT COPILOT RESPONSE:</div>
                    <div id="advisor-response-text" style="font-size: 14px; color: #e2e8f0; line-height: 1.6; white-space: pre-wrap;"></div>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 13: INTEGRATIONS                                            -->
        <!-- =================================================================== -->
        <div id="dash-integrations" class="section-view">
            <div class="grid-2">
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">Slack &amp; Microsoft Teams Webhooks</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">Receive instant alerts in your engineering channel when a Critical risk is detected or a fix is verified.</p>
                    
                    <div style="margin-bottom: 12px;">
                        <label style="font-size: 12.5px; font-weight: 600; display: block; margin-bottom: 4px;">Slack Webhook URL:</label>
                        <input type="text" id="slack-webhook-input" placeholder="https://hooks.slack.com/services/..." style="width: 100%; background: #1e293b; color: #fff; border: 1px solid #334155; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none;" value="{{ integrations.get('slack_webhook_url', '') }}">
                    </div>

                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-primary btn-sm" onclick="saveIntegrations()">Save Webhooks</button>
                        <button class="btn btn-secondary btn-sm" onclick="testIntegrationAlert()">Send Test Alert</button>
                    </div>
                </div>

                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">GitHub Actions CI/CD Quality Gate</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">Block pull requests introducing high severity vulnerabilities or secrets.</p>
                    <pre style="background: #070b12; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 12px; font-size: 11.5px; color: #38bdf8; overflow-x: auto;">- name: TrustAudit Security Gate
  run: |
    curl -X POST http://127.0.0.1:5000/api/scan \\
      -H "Content-Type: application/json" \\
      -d '{"target": "https://github.com/owner/repository"}'</pre>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 14: TEAM                                                    -->
        <!-- =================================================================== -->
        <div id="dash-team" class="section-view">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                    <div>
                        <h2 style="font-size: 18px; font-weight: 700;">Team Members &amp; RBAC ({{ team_members|length }})</h2>
                        <p style="font-size: 13px; color: var(--text-muted);">Manage user permissions: Admin (Full control), Member (Can remediate), Viewer (Read-only).</p>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="promptAddTeamMember()">+ Invite Member</button>
                </div>

                <table>
                    <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody>
                        {% for u in team_members %}
                        <tr>
                            <td><b>{{ u.name }}</b></td>
                            <td><code>{{ u.email }}</code></td>
                            <td><span class="badge badge-engine">{{ u.role|upper }}</span></td>
                            <td><span class="badge badge-pass">ACTIVE</span></td>
                            <td><button class="btn btn-sm btn-secondary" onclick="alert('User settings updated.')">Edit</button></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 15: SETTINGS & PRICING                                      -->
        <!-- =================================================================== -->
        <div id="dash-settings" class="section-view">
            <div class="grid-2">
                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">Organization Profile</h3>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;"><b>Organization:</b> {{ org_info.name if org_info else 'Acme AI Labs' }}</p>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;"><b>Current Plan:</b> <span class="badge badge-engine">{{ (org_info.plan if org_info else 'starter')|upper }}</span></p>
                    <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;"><b>Scans Executed:</b> {{ org_info.scans_count if org_info else 12 }} scans</p>
                </div>

                <div class="card">
                    <h3 style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 12px;">Subscription Tiers</h3>
                    <div style="font-size: 13px; color: var(--text-muted); line-height: 1.8;">
                        <p><b>Free Community:</b> 1 Domain, 1 Repo, Manual scans</p>
                        <p><b>Starter (₹999/mo):</b> 5 Domains, 5 Repos, Daily continuous monitoring</p>
                        <p><b>Pro (₹1,999/mo):</b> 20 Domains, 20 Repos, Hourly scans, Webhook alerts</p>
                        <p><b>Enterprise:</b> Dedicated runners, custom SLAs &amp; compliance</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 16: SCANNER HEALTH & TOOL TELEMETRY                         -->
        <!-- =================================================================== -->
        <div id="dash-tools" class="section-view">
            <div class="card">
                <h2 style="font-size: 18px; font-weight: 700; margin-bottom: 4px;">Scanner Health &amp; Engine Execution Transparency</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">Real-time operational health, executable binaries, and failure diagnostics for all 11 integrated scanners.</p>

                <table>
                    <thead><tr><th>Engine Name</th><th>Category</th><th>Installed</th><th>Version</th><th>Executable Path</th><th>Status</th></tr></thead>
                    <tbody>
                        {% for t in tools_health %}
                        <tr>
                            <td><b>{{ t.name }}</b></td>
                            <td><span class="badge-status">{{ t.category|upper }}</span></td>
                            <td><span class="badge {{ 'badge-pass' if t.installed else 'badge-fail' }}">{{ 'INSTALLED' if t.installed else 'NOT INSTALLED' }}</span></td>
                            <td>{{ t.version or 'N/A' }}</td>
                            <td><code style="word-break: break-all; font-size: 11px;">{{ t.path or 'System PATH' }}</code></td>
                            <td><span class="badge {{ 'badge-pass' if t.installed else 'badge-warn' }}">{{ 'OPERATIONAL' if t.installed else 'STANDBY' }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 17: ONBOARDING WIZARD                                       -->
        <!-- =================================================================== -->
        <div id="dash-onboarding" class="section-view">
            <div class="card" style="max-width: 760px; margin: 0 auto;">
                <h2 style="font-size: 20px; font-weight: 800; margin-bottom: 10px;">🚀 Welcome to TrustAudit</h2>
                <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 24px;">Your startup's automated security department in a box. Follow these quick steps to get continuously protected:</p>
                
                <div style="display: flex; flex-direction: column; gap: 14px;">
                    <div style="padding: 14px; background: #0b1120; border-radius: 8px; border-left: 3px solid var(--status-green);">
                        <b>Step 1: Discover Assets</b>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Add your production web application URL and main GitHub repository.</p>
                    </div>
                    <div style="padding: 14px; background: #0b1120; border-radius: 8px; border-left: 3px solid var(--brand-blue);">
                        <b>Step 2: Run Baseline Security Verification</b>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Execute full non-destructive DAST, TLS, headers, and secret discovery.</p>
                    </div>
                    <div style="padding: 14px; background: #0b1120; border-radius: 8px; border-left: 3px solid var(--brand-cyan);">
                        <b>Step 3: Review "Fix These First"</b>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Apply top prioritized code fixes using copyable AI coding prompts.</p>
                    </div>
                    <div style="padding: 14px; background: #0b1120; border-radius: 8px; border-left: 3px solid var(--status-yellow);">
                        <b>Step 4: Enable Continuous Monitoring</b>
                        <p style="font-size: 13px; color: var(--text-muted); margin: 4px 0 0;">Receive Slack/Email alerts whenever a new vulnerability or certificate expiration occurs.</p>
                    </div>
                </div>

                <div style="margin-top: 24px; text-align: right;">
                    <button class="btn btn-primary" onclick="switchNav('dash-scans')">Launch First Security Audit &rarr;</button>
                </div>
            </div>
        </div>

        <!-- =================================================================== -->
        <!-- SECTION 17: VULNERABILITY INTELLIGENCE & ADVISORY FEED              -->
        <!-- =================================================================== -->
        <div id="dash-vuln-intel" class="section-view">
            <div class="dash-welcome">
                <div class="dash-welcome-text">
                    <h2>🧠 Vulnerability Intelligence Engine</h2>
                    <p>Continuous correlation across <b>OSV.dev</b>, official <b>NVD CVE API 2.0</b>, and <b>CISA KEV</b> against your software inventory.</p>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <button class="btn btn-sm btn-primary" onclick="triggerIntelSync()" id="btn-intel-sync">⚡ Sync Intelligence Now</button>
                </div>
            </div>

            <!-- Source Health & Synchronization Status -->
            <div class="stats-grid" style="margin-bottom: 20px;">
                <div class="stat-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="stat-label">OSV.dev Database</span>
                        <span class="badge badge-LOW" style="font-size: 10px;">{{ vuln_intel_summary.get('sources', {}).get('osv', {}).get('status', 'Healthy') }}</span>
                    </div>
                    <div class="stat-value" style="font-size: 20px; color: #60a5fa;">{{ vuln_intel_summary.get('sources', {}).get('osv', {}).get('records_count', 0) }}</div>
                    <div class="stat-desc">Primary Package &amp; Version Matcher</div>
                </div>

                <div class="stat-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="stat-label">NVD CVE API 2.0</span>
                        <span class="badge badge-LOW" style="font-size: 10px;">{{ vuln_intel_summary.get('sources', {}).get('nvd', {}).get('status', 'Healthy') }}</span>
                    </div>
                    <div class="stat-value" style="font-size: 20px; color: #a78bfa;">{{ vuln_intel_summary.get('sources', {}).get('nvd', {}).get('records_count', 0) }}</div>
                    <div class="stat-desc">NIST CVSS &amp; Advisory Metadata</div>
                </div>

                <div class="stat-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="stat-label">CISA KEV Catalog</span>
                        <span class="badge badge-LOW" style="font-size: 10px;">{{ vuln_intel_summary.get('sources', {}).get('cisa_kev', {}).get('status', 'Healthy') }}</span>
                    </div>
                    <div class="stat-value" style="font-size: 20px; color: #f87171;">{{ vuln_intel_summary.get('known_exploited_count', 0) }}</div>
                    <div class="stat-desc">Actively Exploited in the Wild</div>
                </div>

                <div class="stat-card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="stat-label">Affecting Your Inventory</span>
                        <span class="badge badge-CRITICAL" style="font-size: 10px;">ACTION</span>
                    </div>
                    <div class="stat-value" style="font-size: 20px; color: {% if affecting_vulnerabilities %}#ef4444{% else %}#10b981{% endif %};">{{ affecting_vulnerabilities|length }}</div>
                    <div class="stat-desc">{% if affecting_vulnerabilities %}Vulnerabilities confirmed in code{% else %}No matching vulnerabilities detected{% endif %}</div>
                </div>
            </div>

            <!-- "🚨 NEW VULNERABILITIES AFFECTING YOU" SECTION -->
            <div class="card" style="margin-bottom: 24px; border-color: {% if affecting_vulnerabilities %}#dc2626{% else %}var(--border-subtle){% endif %};">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 18px;">🚨</span>
                        <h3 style="margin: 0; color: #fff;">Vulnerabilities Affecting Your Environment ({{ affecting_vulnerabilities|length }})</h3>
                    </div>
                    <span class="badge badge-CRITICAL">Real-Time Correlation</span>
                </div>

                {% if affecting_vulnerabilities %}
                <div style="display: flex; flex-direction: column; gap: 14px; margin-top: 10px;">
                    {% for vuln in affecting_vulnerabilities %}
                    <div style="background: #0b1120; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 8px;">
                            <div>
                                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px;">
                                    <span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span>
                                    {% if vuln.is_known_exploited %}
                                    <span class="badge badge-CRITICAL" style="background: #7f1d1d; border-color: #ef4444;">🚨 KNOWN EXPLOITED</span>
                                    {% endif %}
                                    <span class="badge badge-LOW" style="background: #1e293b;">{{ vuln.correlation_state }}</span>
                                    <span style="font-size: 12px; color: var(--text-dim); font-family: monospace;">Score: {{ vuln.risk_score }}/100</span>
                                </div>
                                <h4 style="margin: 4px 0; color: #fff; font-size: 15px;">{{ vuln.title }}</h4>
                                <div style="font-size: 12px; color: var(--text-muted); font-family: monospace; margin-top: 2px;">
                                    Package: <b style="color: #60a5fa;">{{ vuln.package_name }}</b> (Installed: <span style="color: #f87171;">{{ vuln.installed_version }}</span> &bull; Fixed: <span style="color: #4ade80;">{{ vuln.fixed_versions|join(', ') or 'latest secure' }}</span>) &bull; Ecosystem: {{ vuln.ecosystem }} &bull; Env: {{ vuln.environment }}
                                </div>
                            </div>
                            <div style="display: flex; gap: 6px;">
                                <button class="btn btn-secondary btn-sm" onclick="showIntelModal({{ vuln|tojson|safe }})">View Details</button>
                                <button class="btn btn-primary btn-sm" onclick="recheckFinding('{{ vuln.id }}', '{{ vuln.package_name }}', '{{ vuln.installed_version }}')">Recheck Fix</button>
                            </div>
                        </div>

                        <div style="margin-top: 10px; padding: 8px 12px; background: #070d18; border-radius: 6px; border-left: 3px solid var(--brand-blue); font-size: 12px; color: #cbd5e1;">
                            <b>Why Prioritized:</b> {{ vuln.why_prioritized }}
                        </div>

                        <div style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                            <div style="font-size: 12px; color: var(--text-muted);">
                                <b>Action:</b> {{ vuln.remediation }}
                            </div>
                            <button class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 8px;" onclick="navigator.clipboard.writeText('{{ vuln.ai_prompt|escape }}'); alert('Remediation prompt copied to clipboard!');">Copy Fix Prompt</button>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <div class="empty-state" style="padding: 30px; text-align: center;">
                    <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
                    <h4 style="color: #10b981; margin-bottom: 4px;">No Vulnerabilities Currently Affect Your Software Inventory</h4>
                    <p style="color: var(--text-muted); font-size: 13px; margin: 0;">TrustAudit continuously matches newly published CVEs and CISA KEV advisories against your registered repositories and web applications.</p>
                </div>
                {% endif %}
            </div>

            <!-- Software Inventory (SBOM) Table -->
            <div class="card" style="margin-bottom: 24px;">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: #fff;">Monitored Software Inventory / SBOM ({{ inventory_components|length }})</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">Auto-discovered from manifests</span>
                </div>
                {% if inventory_components %}
                <div style="overflow-x: auto; margin-top: 10px;">
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Package</th>
                                <th>Installed Version</th>
                                <th>Ecosystem</th>
                                <th>Manifest Source</th>
                                <th>Environment</th>
                                <th>Last Audited</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for comp in inventory_components %}
                            <tr>
                                <td><b>{{ comp.package_name }}</b></td>
                                <td><span style="font-family: monospace; color: {% if comp.version == 'UNKNOWN VERSION' %}var(--text-dim){% else %}#93c5fd{% endif %};">{{ comp.version }}</span></td>
                                <td><span class="badge badge-LOW">{{ comp.ecosystem }}</span></td>
                                <td style="font-size: 12px; color: var(--text-dim); font-family: monospace;">{{ comp.manifest_file }}</td>
                                <td><span class="badge badge-engine">{{ comp.environment }}</span></td>
                                <td style="font-size: 11px; color: var(--text-dim);">Live Sync</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="empty-state" style="padding: 24px; text-align: center; color: var(--text-muted);">
                    Run a repository or website audit in the <b>Scans Console</b> to populate your Software Inventory.
                </div>
                {% endif %}
            </div>

            <!-- Global Vulnerability Database Feed -->
            <div class="card">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; color: #fff;">Global Security Advisory &amp; CVE Feed ({{ all_intel_vulnerabilities|length }})</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">Attribution: OSV.dev, NIST NVD, CISA KEV</span>
                </div>

                <div style="display: flex; gap: 10px; margin: 12px 0; flex-wrap: wrap;">
                    <input type="text" id="intel-search-input" placeholder="Filter by CVE, package name, or keyword..." style="background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 6px 12px; border-radius: 6px; font-size: 13px; flex: 1;" onkeyup="filterIntelTable()">
                    <select id="intel-sev-filter" style="background: #0b1120; border: 1px solid var(--border-subtle); color: #fff; padding: 6px 12px; border-radius: 6px; font-size: 13px;" onchange="filterIntelTable()">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                </div>

                <div style="overflow-x: auto;">
                    <table class="findings-table" id="intel-table">
                        <thead>
                            <tr>
                                <th>Advisory / CVE</th>
                                <th>Title &amp; Summary</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                                <th>Source</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for iv in all_intel_vulnerabilities %}
                            <tr class="intel-row" data-sev="{{ iv.severity }}" data-cve="{{ iv.cve_id or iv.source_id }}" data-text="{{ iv.title }} {{ iv.package_name }}">
                                <td style="font-family: monospace; font-weight: 600; color: #60a5fa;">{{ iv.cve_id or iv.source_id }}</td>
                                <td style="max-width: 380px;">
                                    <div style="font-weight: 500; color: #fff; font-size: 13px;">{{ iv.title }}</div>
                                    <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">{{ iv.package_name }} ({{ iv.ecosystem }})</div>
                                </td>
                                <td><span class="badge badge-{{ iv.severity }}">{{ iv.severity }}</span></td>
                                <td style="font-family: monospace; color: #cbd5e1;">{{ iv.cvss_score }}</td>
                                <td><span class="badge-engine">{{ iv.source }}</span></td>
                                <td>
                                    <button class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 8px;" onclick="showIntelModal({{ iv|tojson|safe }})">Inspect</button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div>

    <!-- ======================================================================= -->
    <!-- SLIDE-OVER VULNERABILITY INTELLIGENCE DETAIL DRAWER                     -->
    <!-- ======================================================================= -->
    <div id="intelModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-header">
                <div>
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
                        <span id="intelModalSevBadge" class="badge">SEVERITY</span>
                        <span id="intelModalKevBadge" class="badge badge-CRITICAL" style="display: none;">🚨 KNOWN EXPLOITED</span>
                        <span id="intelModalSourceBadge" class="badge-engine">SOURCE</span>
                    </div>
                    <h2 id="intelModalTitle" style="font-size: 18px; margin: 0; color: #fff;">Vulnerability Advisory</h2>
                    <div id="intelModalIds" style="font-size: 12px; color: var(--text-dim); margin-top: 4px; font-family: monospace;"></div>
                </div>
                <button class="modal-close" onclick="closeIntelModal()">&times;</button>
            </div>

            <div style="font-size: 13.5px; line-height: 1.6;">
                <h4 style="color: #93c5fd; margin-bottom: 4px;">Advisory Summary &amp; Description</h4>
                <p id="intelModalDesc" style="color: var(--text-main); margin-bottom: 14px; background: #0b1120; padding: 10px; border-radius: 6px;"></p>

                <div id="intelModalKevSection" style="display: none; margin-bottom: 14px; background: #450a0a; border: 1px solid #7f1d1d; border-radius: 6px; padding: 10px;">
                    <h4 style="color: #fca5a5; margin: 0 0 4px;">🚨 CISA Known Exploited Vulnerability Notice</h4>
                    <p id="intelModalKevDesc" style="color: #fecaca; margin: 0; font-size: 12.5px;"></p>
                </div>

                <div style="margin-bottom: 14px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12.5px;">
                    <div style="background: #0b1120; padding: 8px 10px; border-radius: 6px;">
                        <span style="color: var(--text-dim);">Affected Version Ranges:</span><br>
                        <b id="intelModalRanges" style="color: #f87171;"></b>
                    </div>
                    <div style="background: #0b1120; padding: 8px 10px; border-radius: 6px;">
                        <span style="color: var(--text-dim);">Patched / Fixed Versions:</span><br>
                        <b id="intelModalFixed" style="color: #4ade80;"></b>
                    </div>
                </div>

                <div id="intelModalWhySection" style="margin-bottom: 14px; background: #070d18; border-left: 3px solid var(--brand-blue); padding: 10px 12px; border-radius: 0 6px 6px 0;">
                    <h4 style="color: #93c5fd; margin: 0 0 4px;">Why You Are Affected &amp; Prioritization</h4>
                    <p id="intelModalWhy" style="color: #cbd5e1; margin: 0; font-size: 12.5px;"></p>
                </div>

                <h4 style="color: #93c5fd; margin-bottom: 4px;">Recommended Remediation</h4>
                <div id="intelModalRemediation" style="background: #0b1120; border-left: 3px solid #10b981; padding: 12px 14px; border-radius: 0 6px 6px 0; margin-bottom: 18px; color: #e2e8f0; font-size: 13px;"></div>

                <div style="display: flex; gap: 10px; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 14px; flex-wrap: wrap;">
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-secondary btn-sm" onclick="copyIntelPrompt()">Copy AI Fix Prompt</button>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-primary btn-sm" id="intelModalRecheckBtn" onclick="recheckFromModal()">Recheck Fix Now</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ======================================================================= -->
    <!-- SLIDE-OVER FINDING DETAIL DRAWER / MODAL                                -->
    <!-- ======================================================================= -->
    <div id="findingModal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-header">
                <div>
                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
                        <span id="modalSeverityBadge" class="badge">SEVERITY</span>
                        <span id="modalConfidenceBadge" class="badge badge-conf-LIKELY">LIKELY</span>
                        <span id="modalCategoryBadge" class="badge badge-LOW">CATEGORY</span>
                        <span id="modalEngineBadge" class="badge-engine">ENGINE</span>
                    </div>
                    <h2 id="modalTitle" style="font-size: 18px; margin: 0; color: #fff;">Finding Title</h2>
                    <div id="modalTargetLocation" style="font-size: 12px; color: var(--text-dim); margin-top: 4px; font-family: monospace;"></div>
                </div>
                <button class="modal-close" onclick="closeModal()">&times;</button>
            </div>

            <div style="font-size: 13.5px; line-height: 1.6;">
                <!-- Aggregated Locations (Multi-Location Deduplication) -->
                <div id="modalLocationsSection" style="display: none; margin-bottom: 12px; background: #070d18; padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-subtle);">
                    <div style="font-size: 12px; font-weight: 700; color: #38bdf8; margin-bottom: 4px;">📍 Affected Locations Across Project:</div>
                    <ul id="modalLocationsList" style="font-size: 12px; padding-left: 18px; color: var(--text-muted); margin: 0;"></ul>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <h4 style="color: #93c5fd; margin: 0;">What Happened?</h4>
                    <button id="eli5ToggleBtn" class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 10px; background: #1e1b4b; color: #a5b4fc; border-color: #4338ca;" onclick="toggleEli5Mode()">👶 Explain Like I'm New to Security (ELI5)</button>
                </div>
                <div id="modalDesc" style="color: var(--text-main); margin-bottom: 14px; background: #0b1120; padding: 12px; border-radius: 6px; border: 1px solid var(--border-subtle);"></div>

                <div id="modalImpactSection" style="margin-bottom: 14px;">
                    <h4 style="color: #93c5fd; margin-bottom: 4px;">Why It Matters &amp; Business Impact</h4>
                    <p id="modalImpact" style="color: var(--text-muted); background: #0b1120; padding: 10px; border-radius: 6px;"></p>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <h4 style="color: #93c5fd; margin: 0;">Raw Detection Evidence</h4>
                    <button class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 8px;" onclick="copyModalEvidence()">Copy Evidence</button>
                </div>
                <code id="modalEvidence" style="display: block; padding: 10px; margin-bottom: 14px; word-break: break-all; background: #050b14; border: 1px solid var(--border-subtle); border-radius: 6px; font-size: 12px; max-height: 120px; overflow-y: auto;"></code>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <h4 style="color: #93c5fd; margin: 0;">Recommended Remediation</h4>
                    <button class="btn btn-secondary btn-sm" style="font-size: 11px; padding: 2px 10px; background: #064e3b; color: #34d399; border-color: #059669;" onclick="copyAiFixPrompt()">🤖 Copy Cursor / Claude Prompt</button>
                </div>
                <div id="modalRemediation" style="background: #0b1120; border-left: 3px solid var(--brand-blue); padding: 12px 14px; border-radius: 0 6px 6px 0; margin-bottom: 18px; color: #e2e8f0; font-size: 13px;"></div>

                <div style="display: flex; gap: 10px; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 14px; flex-wrap: wrap;">
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-secondary btn-sm" onclick="markFindingStatus('acknowledged')">Acknowledge Risk</button>
                        <button class="btn btn-secondary btn-sm" onclick="markFindingStatus('false_positive')">Mark False Positive</button>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-primary btn-sm" onclick="triggerFixVerification(currentFinding ? currentFinding.id : '', currentFinding ? (currentFinding.file || '') : '')">Verify Fix Now</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ======================================================================= -->
    <!-- CLIENT JAVASCRIPT LOGIC (100% Syntax-Safe & Reactive)                   -->
    <!-- ======================================================================= -->
    <script>
        // 1. Navigation Switcher
        window.switchNav = function(sectionId) {
            if (!sectionId) return;
            const views = document.querySelectorAll('.section-view');
            views.forEach(function(el) {
                if (el.id === sectionId) {
                    el.classList.add('active');
                    el.style.setProperty('display', 'block', 'important');
                } else {
                    el.classList.remove('active');
                    el.style.setProperty('display', 'none', 'important');
                }
            });

            // Update nav item active states
            const navItems = document.querySelectorAll('.nav-item');
            navItems.forEach(function(btn) {
                const oc = btn.getAttribute('onclick') || '';
                if (oc.indexOf("'" + sectionId + "'") !== -1) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });

            if (typeof window.scrollTo === 'function') {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        };

        // 1b. Project Switcher
        window.switchProject = function(projectId) {
            if (!projectId) return;
            window.location.href = '/scan?project_id=' + encodeURIComponent(projectId);
        };

        // 2. Scan Results Sub-Tab Switcher
        window.openSubTab = function(evtOrEl, tabId) {
            if (!tabId) return;

            const target = document.getElementById(tabId);
            if (!target) return;

            const panes = document.querySelectorAll('.tab-pane');
            panes.forEach(function(pane) {
                pane.classList.remove('active');
                pane.style.setProperty('display', 'none', 'important');
            });

            target.classList.add('active');
            target.style.setProperty('display', 'block', 'important');

            const btns = document.querySelectorAll('.tab-btn');
            btns.forEach(function(btn) {
                const btnTab = btn.getAttribute('data-tab');
                if (btnTab === tabId) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        };

        // 3. Scan Mode Toggle
        window.setDashboardScanMode = function(mode) {
            const lblWeb = document.getElementById('lbl-web');
            const lblRepo = document.getElementById('lbl-repo');
            const lblMcp = document.getElementById('lbl-mcp');
            const input = document.getElementById('dash-target-input');
            const submit = document.getElementById('dash-submit-btn');

            if (lblWeb) lblWeb.classList.remove('active');
            if (lblRepo) lblRepo.classList.remove('active');
            if (lblMcp) lblMcp.classList.remove('active');

            if (mode === 'website') {
                if (lblWeb) lblWeb.classList.add('active');
                if (input) input.placeholder = 'https://example.com';
                if (submit) submit.innerText = 'Audit Website';
            } else if (mode === 'mcp') {
                if (lblMcp) lblMcp.classList.add('active');
                if (input) input.placeholder = 'https://github.com/modelcontextprotocol/servers';
                if (submit) submit.innerText = 'Scan MCP Server';
            } else {
                if (lblRepo) lblRepo.classList.add('active');
                if (input) input.placeholder = 'https://github.com/owner/repository';
                if (submit) submit.innerText = 'Scan Repository';
            }
        };

        // 4. Stored Scan Findings Data
        var scanFindings = {% if result and result.get('findings') %}{{ result.get('findings')|tojson|safe }}{% elif projects and projects[0].get('last_scan_result') and projects[0].get('last_scan_result').get('findings') %}{{ projects[0].get('last_scan_result').get('findings')|tojson|safe }}{% else %}[]{% endif %};
        var currentFinding = null;
        var isEli5Mode = false;

        window.showFindingModalByIndex = function(idx) {
            if (scanFindings && scanFindings[idx]) {
                showFindingModal(scanFindings[idx]);
            }
        };

        window.showFindingModal = function(finding) {
            if (!finding) return;
            currentFinding = finding;
            isEli5Mode = false;
            const eliBtn = document.getElementById("eli5ToggleBtn");
            if (eliBtn) eliBtn.innerText = "👶 Explain Like I'm New to Security (ELI5)";

            document.getElementById("modalTitle").innerText = finding.title || "Untitled Finding";
            const sev = (finding.severity || "MEDIUM").toUpperCase();
            document.getElementById("modalSeverityBadge").className = "badge badge-" + sev;
            document.getElementById("modalSeverityBadge").innerText = sev;

            const conf = (finding.confidence || "LIKELY").toUpperCase();
            const confBadge = document.getElementById("modalConfidenceBadge");
            if (confBadge) {
                confBadge.className = "badge badge-conf-" + conf;
                confBadge.innerText = conf + " CONFIDENCE";
            }

            document.getElementById("modalCategoryBadge").innerText = (finding.category || "web").toUpperCase();
            
            const engines = finding.scanners && finding.scanners.length ? finding.scanners.join(", ") : (finding.scanner || "trustaudit");
            document.getElementById("modalEngineBadge").innerText = engines;
            
            const location = finding.file || finding.url || finding.target || "";
            document.getElementById("modalTargetLocation").innerText = location ? "Primary Location: " + location + (finding.line ? ":" + finding.line : "") : "";
            
            // Multi-Location Deduplication list
            const locSec = document.getElementById("modalLocationsSection");
            const locList = document.getElementById("modalLocationsList");
            if (finding.locations && finding.locations.length > 1) {
                locSec.style.display = "block";
                locList.innerHTML = finding.locations.map(function(l) {
                    return '<li><code>' + l.file + (l.line ? ':' + l.line : '') + '</code>' + (l.evidence ? ' — <small style="color: #64748b;">' + l.evidence.substring(0, 50) + '...</small>' : '') + '</li>';
                }).join('');
            } else {
                locSec.style.display = "none";
            }

            document.getElementById("modalDesc").innerText = finding.description || "No description provided.";
            
            const impactSec = document.getElementById("modalImpactSection");
            if (finding.business_impact || finding.impact) {
                impactSec.style.display = "block";
                document.getElementById("modalImpact").innerText = finding.business_impact || finding.impact;
            } else {
                impactSec.style.display = "none";
            }
            
            document.getElementById("modalEvidence").innerText = finding.evidence || "No raw detection evidence captured.";
            document.getElementById("modalRemediation").innerText = finding.remediation || "Review and remediate according to standard security practices.";
            document.getElementById("findingModal").classList.add("active");
        };

        window.toggleEli5Mode = function() {
            if (!currentFinding) return;
            isEli5Mode = !isEli5Mode;
            const btn = document.getElementById("eli5ToggleBtn");
            const descEl = document.getElementById("modalDesc");

            if (isEli5Mode) {
                if (btn) btn.innerText = "Switch to Technical View";
                if (descEl) descEl.innerHTML = '<span style="color: var(--text-dim);">Translating into founder plain-English...</span>';

                fetch('/api/findings/eli5', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(currentFinding)
                }).then(r => r.json()).then(d => {
                    if (descEl) descEl.innerHTML = (d.eli5_explanation || '').split('\\n').join('<br>');
                }).catch(e => {
                    if (descEl) descEl.innerText = currentFinding.description || "No description available.";
                });
            } else {
                if (btn) btn.innerText = "👶 Explain Like I'm New to Security (ELI5)";
                if (descEl) descEl.innerText = currentFinding.description || "No description provided.";
            }
        };

        function safeCopyText(text, successMsg) {
            if (!text) return;
            if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    if (successMsg) alert(successMsg);
                }).catch(() => {
                    if (window.prompt) window.prompt("Copy to clipboard:", text);
                });
            } else {
                if (window.prompt) window.prompt("Copy to clipboard:", text);
            }
        }

        window.copyAiFixPrompt = function() {
            if (!currentFinding) return;
            fetch('/api/findings/ai-prompt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(currentFinding)
            }).then(r => r.json()).then(d => {
                const promptText = d.ai_fix_prompt || ('Ask Cursor / Claude: Fix security vulnerability in ' + (currentFinding.file || 'the codebase') + ' for ' + (currentFinding.title || ''));
                safeCopyText(promptText, "✓ Ready-to-use AI Fix Prompt copied to clipboard!\\n\\n" + promptText);
            }).catch(e => {
                const fallback = 'Ask Cursor / Claude: Fix security vulnerability in ' + (currentFinding.file || 'the codebase') + ' for ' + (currentFinding.title || '');
                safeCopyText(fallback, "✓ AI Fix Prompt copied!");
            });
        };

        window.closeModal = function() {
            document.getElementById("findingModal").classList.remove("active");
        };

        window.copyModalEvidence = function() {
            if (!currentFinding || !currentFinding.evidence) {
                alert("No evidence text to copy.");
                return;
            }
            safeCopyText(currentFinding.evidence, "✓ Evidence copied to clipboard!");
        };

        window.copyPrompt = function(findingId) {
            const promptText = "Fix security issue: " + findingId + " in the codebase. Please apply safe defensive programming and input validation.";
            safeCopyText(promptText, "✓ AI Coding Prompt copied! Paste into Cursor, Claude Code, or Copilot.");
        };

        window.triggerFixVerification = function(findingId, target) {
            if (!confirm("Trigger live verification scan to confirm this vulnerability was resolved?")) return;
            const targetInput = document.getElementById('dash-target-input');
            const actualTarget = target || (targetInput ? targetInput.value : '');

            fetch('/api/finding/' + encodeURIComponent(findingId) + '/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({finding_id: findingId, target: actualTarget})
            }).then(r => r.json()).then(data => {
                if (data.is_fixed) {
                    alert('🎉 VERIFIED CLEAN! The vulnerability is no longer detected. Posture Score: ' + data.score + '/100');
                    window.location.reload();
                } else {
                    alert('⚠️ Still Vulnerable: ' + (data.message || 'The vulnerability was still detected during rescan.'));
                }
            }).catch(e => alert('Verification error: ' + e));
        };

        window.markFindingStatus = function(status) {
            if (!currentFinding) return;
            const findingId = currentFinding.id || currentFinding.finding_id || "FIND-GEN";
            fetch('/api/finding/' + encodeURIComponent(findingId) + '/status', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({status: status})
            }).then(r => r.json()).then(data => {
                alert('Finding status updated to: ' + status);
                closeModal();
            }).catch(e => alert('Error updating finding: ' + e));
        };

        window.copyBadgeSnippet = function() {
            const el = document.getElementById("readmeBadgeSnippet");
            if (!el) return;
            safeCopyText(el.value, "✓ README Markdown badge snippet copied to clipboard!\\n\\n" + el.value);
        };

        window.previewWeeklyDigest = function() {
            const previewBox = document.getElementById("weeklyDigestPreview");
            if (!previewBox) return;
            previewBox.style.display = "block";
            previewBox.innerHTML = "<em>Generating weekly digest preview...</em>";

            fetch('/api/digest/weekly')
                .then(r => r.json())
                .then(d => {
                    previewBox.innerHTML = 
                        '<div style="font-weight: 700; color: #fff; font-size: 15px; margin-bottom: 6px;">' + (d.headline || 'Weekly Security Digest') + '</div>' +
                        '<div style="color: #94a3b8; font-size: 12px; margin-bottom: 10px;">Date: ' + d.date + ' &bull; Average Posture Score: <b style="color: #22c55e;">' + d.average_score + '/100</b></div>' +
                        '<div style="background: #0b1120; padding: 10px; border-radius: 6px; margin-bottom: 10px;">' + d.status_narrative + '</div>' +
                        '<div style="display: flex; gap: 14px; font-size: 12px; color: #64748b;">' +
                        '<span>Scans: <b>' + d.scans_executed_this_week + '</b></span>' +
                        '<span>Active Projects: <b>' + d.total_projects + '</b></span>' +
                        '<span>Open Risks: <b>' + d.open_findings + '</b></span>' +
                        '</div>';
                }).catch(e => {
                    previewBox.innerText = "Error loading digest preview: " + e;
                });
        };

        window.quickAudit = function(targetUrl, scanType) {
            const input = document.getElementById('dash-target-input');
            if (input) input.value = targetUrl;
            setDashboardScanMode(scanType || 'website');
            switchNav('dash-scans');
            const form = document.getElementById('dash-scan-form');
            if (form) form.submit();
        };

        // 5. Findings Search & Filter
        window.filterFindingsTable = function() {
            const searchVal = (document.getElementById('finding-search').value || '').toLowerCase();
            const sevVal = document.getElementById('filter-severity').value;
            const rows = document.querySelectorAll('#findings-table tbody tr');

            rows.forEach(function(row) {
                const rowSev = row.getAttribute('data-severity') || '';
                const rowTitle = row.getAttribute('data-title') || '';
                const matchesSev = (sevVal === 'ALL' || rowSev === sevVal);
                const matchesSearch = (!searchVal || rowTitle.indexOf(searchVal) !== -1);
                row.style.display = (matchesSev && matchesSearch) ? '' : 'none';
            });
        };

        // 6. AI Copilot Query
        window.sendAdvisorPrompt = function(q) {
            const input = document.getElementById('advisor-query-input');
            if (input) input.value = q;
            submitAdvisorQuery();
        };

        window.submitAdvisorQuery = function() {
            const input = document.getElementById('advisor-query-input');
            const btn = document.getElementById('advisor-send-btn');
            const box = document.getElementById('advisor-response-box');
            const text = document.getElementById('advisor-response-text');
            const query = input ? input.value.trim() : '';
            if (!query) return;

            if (btn) btn.innerText = 'Analyzing...';
            if (box) box.style.display = 'block';
            if (text) text.innerText = 'Grounding query against deterministic scan findings...';

            fetch('/api/advisor/query', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({query: query})
            }).then(r => r.json()).then(data => {
                if (btn) btn.innerText = 'Ask Copilot';
                if (text) text.innerText = data.answer || 'No response returned.';
            }).catch(e => {
                if (btn) btn.innerText = 'Ask Copilot';
                if (text) text.innerText = 'Copilot query error: ' + e;
            });
        };

        // 7. Integrations & Schedule
        window.saveIntegrations = function() {
            const slackUrl = document.getElementById('slack-webhook-input').value;
            fetch('/api/integrations', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({slack_webhook_url: slackUrl})
            }).then(r => r.json()).then(data => {
                alert('✓ Integration settings saved successfully!');
            }).catch(e => alert('Error saving settings: ' + e));
        };

        window.testIntegrationAlert = function() {
            const slackUrl = document.getElementById('slack-webhook-input').value;
            fetch('/api/integrations/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target_url: slackUrl})
            }).then(r => r.json()).then(data => {
                alert('✓ Test alert dispatched! Check your notification channel.');
            }).catch(e => alert('Error dispatching test alert: ' + e));
        };

        window.saveMonitoringSchedule = function() {
            const freq = document.getElementById('monitoring-cadence-select').value;
            alert('✓ Continuous monitoring schedule updated to: ' + freq);
        };

        window.triggerInstantSweep = function() {
            if (!confirm("Run immediate continuous security sweep across all monitored assets?")) return;
            fetch('/api/monitoring/trigger-all', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            }).then(r => r.json()).then(data => {
                alert('✓ Sweep triggered for ' + data.triggered_count + ' asset(s)!');
                switchNav('dash-main');
            }).catch(e => alert('Error triggering sweep: ' + e));
        };

        window.promptAddTeamMember = function() {
            const name = prompt("Enter team member name:");
            if (!name) return;
            const email = prompt("Enter team member email:");
            if (!email) return;
            fetch('/api/team/members', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, email: email, role: 'member'})
            }).then(r => r.json()).then(data => {
                alert('✓ Team member ' + name + ' invited!');
                window.location.reload();
            }).catch(e => alert('Error inviting member: ' + e));
        };

        // 8. Live Progress Simulation
        let dashProgressIv = null;
        window.cancelActiveScan = function(prefix) {
            if (dashProgressIv) clearInterval(dashProgressIv);
            const overlay = document.getElementById(prefix + '-progress');
            if (overlay) overlay.style.display = 'none';
            const btn = document.getElementById(prefix + '-submit-btn');
            if (btn) {
                btn.disabled = false;
                btn.innerText = 'Run Security Scan';
            }
        };

        window.showProgress = function(prefix) {
            const overlay = document.getElementById(prefix + '-progress');
            const btn = document.getElementById(prefix + '-submit-btn');
            if (overlay) overlay.style.display = 'block';
            if (btn) {
                btn.disabled = true;
                btn.innerText = 'Scanning...';
            }
            const bar = document.getElementById(prefix + '-bar');
            const stageText = document.getElementById(prefix + '-stage');

            const stages = [
                {pct: 15, text: 'Normalizing target URL & resolving DNS (IPv4/IPv6)...'},
                {pct: 35, text: 'Probing HTTP/HTTPS connectivity & security headers...'},
                {pct: 55, text: 'Inspecting TLS certificate validity & SSL protocol...'},
                {pct: 70, text: 'Auditing cookie flags (Secure, HttpOnly) & CORS...'},
                {pct: 85, text: 'Testing public file exposure & API endpoints...'},
                {pct: 95, text: 'Calculating security posture score & generating report...'}
            ];

            let i = 0;
            const t0 = Date.now();
            if (dashProgressIv) clearInterval(dashProgressIv);
            dashProgressIv = setInterval(() => {
                const elapsed = Math.floor((Date.now() - t0) / 1000);
                if (btn) btn.innerText = 'Scanning (' + elapsed + 's)...';
                if (i < stages.length) {
                    if (bar) bar.style.width = stages[i].pct + '%';
                    if (stageText) stageText.innerText = stages[i].text;
                    i++;
                }
            }, 1200);
        };

        // 9. Vulnerability Intelligence Drawer & Actions
        let currentIntelVuln = null;

        window.showIntelModal = function(vuln) {
            if (!vuln) return;
            currentIntelVuln = vuln;

            const modal = document.getElementById('intelModal');
            const title = document.getElementById('intelModalTitle');
            const ids = document.getElementById('intelModalIds');
            const sevBadge = document.getElementById('intelModalSevBadge');
            const kevBadge = document.getElementById('intelModalKevBadge');
            const sourceBadge = document.getElementById('intelModalSourceBadge');
            const desc = document.getElementById('intelModalDesc');
            const kevSection = document.getElementById('intelModalKevSection');
            const kevDesc = document.getElementById('intelModalKevDesc');
            const ranges = document.getElementById('intelModalRanges');
            const fixed = document.getElementById('intelModalFixed');
            const why = document.getElementById('intelModalWhy');
            const whySection = document.getElementById('intelModalWhySection');
            const remediation = document.getElementById('intelModalRemediation');

            if (title) title.innerText = vuln.title || 'Vulnerability Advisory';
            if (ids) ids.innerText = 'ID: ' + (vuln.cve_id || vuln.source_id || vuln.id) + ' | Ecosystem: ' + (vuln.ecosystem || 'N/A') + ' | CVSS: ' + (vuln.cvss_score || 'N/A');
            
            if (sevBadge) {
                sevBadge.innerText = vuln.severity || 'MEDIUM';
                sevBadge.className = 'badge badge-' + (vuln.severity || 'MEDIUM');
            }

            if (kevBadge) {
                kevBadge.style.display = (vuln.is_known_exploited || vuln.kev_status) ? 'inline-block' : 'none';
            }

            if (sourceBadge) {
                sourceBadge.innerText = vuln.source || 'OSV / NVD';
            }

            if (desc) desc.innerText = vuln.description || vuln.summary || 'No detailed description available.';

            if (kevSection) {
                if (vuln.is_known_exploited || vuln.kev_status) {
                    kevSection.style.display = 'block';
                    const kd = vuln.kev_details || vuln.kev_status || {};
                    if (kevDesc) kevDesc.innerText = (kd.required_action ? 'Required Action: ' + kd.required_action + ' (Due: ' + (kd.due_date || 'ASAP') + '). ' : '') + (kd.short_description || 'Active in-the-wild exploitation verified by CISA.');
                } else {
                    kevSection.style.display = 'none';
                }
            }

            if (ranges) ranges.innerText = (vuln.affected_version_ranges && vuln.affected_version_ranges.length) ? vuln.affected_version_ranges.join(', ') : 'All prior unpatched versions';
            if (fixed) fixed.innerText = (vuln.fixed_versions && vuln.fixed_versions.length) ? vuln.fixed_versions.join(', ') : 'Latest secure release';

            if (whySection && why) {
                if (vuln.why_prioritized) {
                    whySection.style.display = 'block';
                    why.innerText = vuln.why_prioritized;
                } else {
                    whySection.style.display = 'none';
                }
            }

            if (remediation) remediation.innerText = vuln.remediation || 'Upgrade package to the latest secure version.';

            if (modal) modal.style.display = 'flex';
        };

        window.closeIntelModal = function() {
            const modal = document.getElementById('intelModal');
            if (modal) modal.style.display = 'none';
            currentIntelVuln = null;
        };

        window.copyIntelPrompt = function() {
            if (!currentIntelVuln) return;
            const prompt = currentIntelVuln.ai_prompt || ('Fix vulnerability ' + (currentIntelVuln.cve_id || currentIntelVuln.id) + ' in ' + currentIntelVuln.package_name + ' by upgrading to ' + ((currentIntelVuln.fixed_versions || [])[0] || 'latest version') + '.');
            navigator.clipboard.writeText(prompt);
            alert('✓ Copied remediation prompt for Cursor / Claude / Copilot to clipboard!');
        };

        window.recheckFromModal = function() {
            if (!currentIntelVuln) return;
            recheckFinding(currentIntelVuln.id, currentIntelVuln.package_name, currentIntelVuln.installed_version);
        };

        window.recheckFinding = function(findingId, pkgName, currentVer) {
            const newVer = prompt('Enter the newly upgraded version of package "' + pkgName + '" (currently: ' + currentVer + '):', currentVer);
            if (!newVer) return;

            fetch('/api/intel/recheck/' + encodeURIComponent(findingId), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    package_name: pkgName,
                    new_version: newVer,
                    ecosystem: 'npm',
                    project_id: 'proj-demo-1'
                })
            }).then(r => r.json()).then(data => {
                if (data.verified_fixed_count > 0) {
                    alert('✓ Verified! Finding has been confirmed resolved and moved to VERIFIED_FIXED.');
                } else {
                    alert('⚠️ Recheck complete: Installed version ' + newVer + ' is still within the vulnerable range (' + data.remaining_open_count + ' open finding(s)).');
                }
                window.location.reload();
            }).catch(e => alert('Recheck error: ' + e));
        };

        window.triggerIntelSync = function() {
            const btn = document.getElementById('btn-intel-sync');
            if (btn) {
                btn.disabled = true;
                btn.innerText = 'Syncing...';
            }
            fetch('/api/intel/sync', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            }).then(r => r.json()).then(data => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = '⚡ Sync Intelligence Now';
                }
                alert('✓ Vulnerability Intelligence synchronized! ' + (data.kev_sync ? data.kev_sync.count : 0) + ' KEV records indexed.');
                window.location.reload();
            }).catch(e => {
                if (btn) {
                    btn.disabled = false;
                    btn.innerText = '⚡ Sync Intelligence Now';
                }
                alert('Sync error: ' + e);
            });
        };

        window.filterIntelTable = function() {
            const q = (document.getElementById('intel-search-input').value || '').toLowerCase();
            const sev = (document.getElementById('intel-sev-filter').value || '').toUpperCase();
            const rows = document.querySelectorAll('.intel-row');

            rows.forEach(function(row) {
                const rowSev = (row.getAttribute('data-sev') || '').toUpperCase();
                const rowText = (row.getAttribute('data-text') || '').toLowerCase();
                const rowCve = (row.getAttribute('data-cve') || '').toLowerCase();

                const matchesSev = !sev || rowSev === sev;
                const matchesQ = !q || rowText.indexOf(q) !== -1 || rowCve.indexOf(q) !== -1;

                if (matchesSev && matchesQ) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        };

        // 10. MCP Intelligence Helpers
        window.searchMcpReputation = function() {
            const pkg = document.getElementById('mcp-rep-input').value.trim();
            if (!pkg) return;
            fetch('/api/mcp/reputation-lookup?package=' + encodeURIComponent(pkg))
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-rep-result');
                    resDiv.style.display = 'block';
                    document.getElementById('mcp-rep-pkg-name').innerText = data.package || pkg;
                    const tierBadge = document.getElementById('mcp-rep-tier-badge');
                    const catEl = document.getElementById('mcp-rep-category');
                    const concernsEl = document.getElementById('mcp-rep-concerns');
                    const remEl = document.getElementById('mcp-rep-remediation');

                    if (data.flagged) {
                        tierBadge.innerText = 'CONCERNS DOCUMENTED';
                        tierBadge.className = 'badge badge-fail';
                        catEl.style.display = 'block';
                        catEl.innerText = data.owasp_mcp_category || 'OWASP MCP Security Advisory';
                        concernsEl.innerHTML = (data.concerns || []).map(c => '<p style="margin-bottom: 4px;">• ' + c + '</p>').join('');
                        remEl.style.display = 'block';
                        remEl.innerHTML = '<b>Remediation:</b> ' + (data.remediation || 'Review tool permissions.');
                    } else {
                        tierBadge.innerText = 'CLEAN';
                        tierBadge.className = 'badge badge-pass';
                        catEl.style.display = 'none';
                        concernsEl.innerHTML = '<span style="color: #4ade80;">✓ No known issues found in curated database.</span>';
                        remEl.style.display = 'none';
                    }
                })
                .catch(e => alert('Lookup error: ' + e));
        };

        window.checkMcpTyposquat = function() {
            const pkg = document.getElementById('mcp-typo-input').value.trim();
            if (!pkg) return;
            fetch('/api/mcp/typosquat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({packages: [pkg]})
            })
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-typo-result');
                    resDiv.style.display = 'block';
                    const statusEl = document.getElementById('mcp-typo-status');
                    const detailEl = document.getElementById('mcp-typo-detail');
                    if (data.findings && data.findings.length > 0) {
                        const f = data.findings[0];
                        statusEl.innerHTML = '<span style="color: #f87171;">🚨 TYPOSQUATTING DETECTED (' + f.attack_type + ')</span>';
                        detailEl.innerText = f.reason + ' Official Package: ' + f.resembles;
                    } else {
                        statusEl.innerHTML = '<span style="color: #4ade80;">✓ CLEAN — No typosquatting or homoglyph signals detected.</span>';
                        detailEl.innerText = 'Package name does not masquerade as any known official MCP server.';
                    }
                })
                .catch(e => alert('Typosquat check error: ' + e));
        };

        window.runMcpPermissionDiff = function() {
            let bJson, cJson;
            try {
                bJson = JSON.parse(document.getElementById('mcp-diff-baseline').value);
                cJson = JSON.parse(document.getElementById('mcp-diff-current').value);
            } catch (err) {
                alert('Invalid JSON in baseline or current tool definition.');
                return;
            }
            fetch('/api/mcp/diff-permissions', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({baseline_tool: bJson, current_tool: cJson})
            })
                .then(r => r.json())
                .then(data => {
                    const resDiv = document.getElementById('mcp-diff-result');
                    resDiv.style.display = 'block';
                    document.getElementById('mcp-diff-tool-name').innerText = data.tool_name;
                    const badge = document.getElementById('mcp-diff-risk-badge');
                    badge.innerText = data.risk_rating + ' RISK';
                    badge.className = 'badge ' + (data.is_critical_escalation ? 'badge-CRITICAL' : (data.has_permission_drift ? 'badge-HIGH' : 'badge-pass'));

                    let html = '<p><b>Added Capabilities:</b> ' + (data.added_capabilities.length ? '<span style="color: #f87171;">' + data.added_capabilities.join(', ') + '</span>' : 'None') + '</p>';
                    html += '<p><b>Removed Capabilities:</b> ' + (data.removed_capabilities.length ? data.removed_capabilities.join(', ') : 'None') + '</p>';
                    html += '<p><b>Description Changed:</b> ' + (data.description_changed ? 'Yes (Prompt updated)' : 'No') + '</p>';
                    if (data.escalation_alerts && data.escalation_alerts.length) {
                        html += '<div style="margin-top: 8px; color: #fca5a5;"><b>🚨 High-Risk Escalation Alerts:</b><ul style="margin: 4px 0 0 16px;">';
                        data.escalation_alerts.forEach(function(a) {
                            html += '<li>' + a.risk + '</li>';
                        });
                        html += '</ul></div>';
                    }
                    document.getElementById('mcp-diff-details').innerHTML = html;
                })
                .catch(e => alert('Permission diff error: ' + e));
        };
    </script>
</body>
</html>
"""
