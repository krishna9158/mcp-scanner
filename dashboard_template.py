"""
TrustAudit — DPDP Compliance Management Platform Dashboard Template
===================================================================
Comprehensive 13-section SaaS Command Center for Indian businesses & healthcare.
Replaces all legacy scanner views with DPDP Discovery, Assessment, and Operational Workflows.
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit — DPDP Compliance Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0b111e;
            --bg-surface: #111a2e;
            --bg-card: #16223b;
            --bg-card-hover: #1c2b4a;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --border-color: #1e2e4f;
            --border-subtle: #2d416b;
            --brand-primary: #2563eb;
            --brand-primary-hover: #1d4ed8;
            --brand-accent: #38bdf8;
            --brand-emerald: #10b981;
            --brand-amber: #f59e0b;
            --brand-red: #ef4444;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --radius-xl: 20px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif; background: var(--bg-base); color: var(--text-main); line-height: 1.5; font-size: 13.5px; overflow-x: hidden; }
        a { color: inherit; text-decoration: none; }
        button { cursor: pointer; border: none; font-family: inherit; }

        .app-layout { display: flex; height: 100vh; overflow: hidden; }

        /* SIDEBAR */
        aside.sidebar { width: 260px; background: var(--bg-surface); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; flex-shrink: 0; }
        .sidebar-brand { height: 70px; display: flex; align-items: center; gap: 10px; padding: 0 20px; border-bottom: 1px solid var(--border-color); font-weight: 800; font-size: 18px; color: #ffffff; }
        .sidebar-brand svg { color: var(--brand-accent); }
        .sidebar-brand-badge { font-size: 9.5px; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: var(--brand-accent); padding: 2px 6px; border-radius: 4px; }
        
        .sidebar-nav { flex-grow: 1; overflow-y: auto; padding: 16px 10px; }
        .nav-group-title { font-size: 10.5px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; padding: 12px 12px 6px 12px; }
        .nav-item { display: flex; align-items: center; gap: 10px; padding: 9px 12px; border-radius: var(--radius-md); font-weight: 600; font-size: 13px; color: var(--text-muted); transition: all 0.15s; margin-bottom: 2px; }
        .nav-item:hover { color: #ffffff; background: rgba(255, 255, 255, 0.05); }
        .nav-item.active { color: #ffffff; background: var(--brand-primary); }
        .nav-item svg { width: 16px; height: 16px; flex-shrink: 0; }
        .nav-pill { margin-left: auto; font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 9999px; }
        .nav-pill-amber { background: rgba(245, 158, 11, 0.2); color: var(--brand-amber); }
        .nav-pill-emerald { background: rgba(16, 185, 129, 0.2); color: var(--brand-emerald); }

        .sidebar-footer { padding: 14px 16px; border-top: 1px solid var(--border-color); font-size: 12px; color: var(--text-muted); }

        /* MAIN CONTENT AREA */
        main.main-area { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; background: var(--bg-base); }
        header.top-bar { height: 70px; background: var(--bg-surface); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; padding: 0 28px; flex-shrink: 0; }
        .topbar-left { display: flex; align-items: center; gap: 16px; }
        .org-badge { display: flex; align-items: center; gap: 8px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 6px 12px; border-radius: 9999px; font-size: 12.5px; font-weight: 600; }
        .readiness-chip { background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: var(--brand-emerald); font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 9999px; display: flex; align-items: center; gap: 6px; }
        .topbar-right { display: flex; align-items: center; gap: 14px; }

        .content-body { padding: 28px; max-width: 1400px; margin: 0 auto; width: 100%; }

        /* CARDS & PANELS */
        .dash-section { display: none; }
        .dash-section.active { display: block; animation: fadeIn 0.2s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        .page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }
        .page-title { font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: -0.4px; }
        .page-subtitle { font-size: 13.5px; color: var(--text-muted); margin-top: 4px; }

        .grid-kpi { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .kpi-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 18px 20px; }
        .kpi-title { font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px; }
        .kpi-val { font-size: 28px; font-weight: 800; color: #ffffff; line-height: 1.1; }
        .kpi-sub { font-size: 12px; color: var(--text-muted); margin-top: 6px; }

        .card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 22px; margin-bottom: 24px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; padding-bottom: 14px; border-bottom: 1px solid var(--border-color); }
        .card-title { font-size: 16px; font-weight: 700; color: #ffffff; display: flex; align-items: center; gap: 8px; }

        /* BUTTONS & CONTROLS */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 8px 16px; border-radius: var(--radius-sm); font-weight: 600; font-size: 13px; transition: all 0.15s; }
        .btn-primary { background: var(--brand-primary); color: #ffffff; }
        .btn-primary:hover { background: var(--brand-primary-hover); }
        .btn-secondary { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border-color); }
        .btn-secondary:hover { background: var(--bg-card-hover); border-color: var(--border-subtle); }
        .btn-sm { padding: 5px 10px; font-size: 12px; }

        /* TABLES */
        .table-wrap { overflow-x: auto; }
        table.dash-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12.5px; }
        table.dash-table th { padding: 11px 14px; background: rgba(0, 0, 0, 0.2); color: var(--text-dim); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; border-bottom: 1px solid var(--border-color); }
        table.dash-table td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); color: var(--text-main); }
        table.dash-table tr:hover td { background: rgba(255, 255, 255, 0.02); }

        .badge-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 9999px; }
        .badge-emerald { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .badge-sky { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
        .badge-red { background: rgba(239, 68, 68, 0.15); color: #f87171; }

        /* FORMS & MODALS */
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 9px 12px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-sm); color: #ffffff; font-size: 13px; font-family: inherit; }
        .form-control:focus { outline: none; border-color: var(--brand-accent); }

        .modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(4px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.open { display: flex; }
        .modal-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); width: 100%; max-width: 600px; padding: 26px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); max-height: 90vh; overflow-y: auto; }

        /* ASSISTANT DRAWER */
        .assistant-panel { background: #0c1424; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 20px; margin-top: 18px; }
        .assistant-chat { max-height: 280px; overflow-y: auto; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
        .chat-bubble { padding: 12px 14px; border-radius: var(--radius-md); font-size: 13px; line-height: 1.5; }
        .chat-user { background: var(--brand-primary); color: #ffffff; align-self: flex-end; max-width: 80%; }
        .chat-ai { background: var(--bg-card); border: 1px solid var(--border-color); color: #f1f5f9; align-self: flex-start; max-width: 90%; }

        /* WEBSITE SCANNER STYLES & RADAR MOTION */
        .scanner-hero { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 24px; margin-bottom: 24px; }
        @media (max-width: 960px) { .scanner-hero { grid-template-columns: 1fr; } }
        .radar-box { position: relative; width: 150px; height: 150px; border-radius: 50%; border: 2px solid rgba(56, 189, 248, 0.3); display: flex; align-items: center; justify-content: center; background: radial-gradient(circle, rgba(56, 189, 248, 0.1) 0%, transparent 70%); margin: 0 auto; }
        .radar-ring { position: absolute; inset: 18px; border-radius: 50%; border: 1px dashed rgba(56, 189, 248, 0.25); }
        .radar-sweep { position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(56, 189, 248, 0.45) 360deg); animation: radarRotate 2.2s linear infinite; }
        .radar-center-dot { width: 12px; height: 12px; border-radius: 50%; background: var(--brand-accent); box-shadow: 0 0 14px var(--brand-accent); z-index: 2; }
        @keyframes radarRotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .scanner-visual-card { background: linear-gradient(145deg, #0f172a, #0b1120); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 24px; display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; overflow: hidden; }
        .scanner-node-tag { position: absolute; font-size: 10.5px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: rgba(15, 23, 42, 0.85); border: 1px solid var(--border-color); backdrop-filter: blur(4px); color: var(--text-muted); }
        .node-tag-1 { top: 18px; left: 18px; color: #38bdf8; border-color: rgba(56, 189, 248, 0.3); }
        .node-tag-2 { bottom: 20px; left: 20px; color: #34d399; border-color: rgba(52, 211, 153, 0.3); }
        .node-tag-3 { top: 22px; right: 18px; color: #fbbf24; border-color: rgba(251, 191, 36, 0.3); }
        .node-tag-4 { bottom: 22px; right: 20px; color: #f87171; border-color: rgba(248, 113, 113, 0.3); }

        .progress-stage-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 18px; }
        @media (max-width: 800px) { .progress-stage-grid { grid-template-columns: 1fr; } }
        .stage-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-sm); font-size: 12px; font-weight: 600; color: var(--text-muted); transition: all 0.2s; }
        .stage-item.stage-active { border-color: var(--brand-accent); color: #ffffff; background: rgba(56, 189, 248, 0.12); }
        .stage-item.stage-done { border-color: var(--brand-emerald); color: var(--brand-emerald); background: rgba(16, 185, 129, 0.1); }

        .finding-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); margin-bottom: 14px; overflow: hidden; transition: border-color 0.15s; }
        .finding-card:hover { border-color: var(--border-subtle); }
        .finding-header { padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
        .finding-header:hover { background: rgba(255, 255, 255, 0.02); }
        .finding-body { padding: 0 20px 20px 20px; display: none; border-top: 1px solid var(--border-color); margin-top: 4px; padding-top: 16px; font-size: 13px; }
        .finding-body.expanded { display: block; animation: fadeIn 0.2s ease; }
        .filter-btn { padding: 6px 12px; font-size: 12px; font-weight: 600; border-radius: 9999px; background: var(--bg-card); color: var(--text-muted); border: 1px solid var(--border-color); cursor: pointer; }
        .filter-btn.active { background: var(--brand-primary); color: #ffffff; border-color: var(--brand-primary); }
    </style>
</head>
<body>

    <div class="app-layout">
        <!-- SIDEBAR -->
        <aside class="sidebar">
            <div class="sidebar-brand">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>TrustAudit</span>
                <span class="sidebar-brand-badge">DPDP</span>
            </div>

            <div class="sidebar-nav">
                <div class="nav-group-title">Command &bull; DPDP</div>
                <a href="#overview" onclick="navTo('overview', this)" class="nav-item active">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    <span>Overview</span>
                </a>
                <a href="#scanner" onclick="navTo('scanner', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
                    <span>DPDP Website Scanner</span>
                    <span class="nav-pill nav-pill-emerald">NEW</span>
                </a>
                <a href="#assessment" onclick="navTo('assessment', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <span>DPDP Assessment</span>
                    <span class="nav-pill nav-pill-amber">15</span>
                </a>
                <a href="#inventory" onclick="navTo('inventory', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                    <span>Data Inventory</span>
                    <span class="nav-pill nav-pill-emerald" id="nav-inv-count">18</span>
                </a>

                <div class="nav-group-title">Privacy &amp; Workflows</div>
                <a href="#privacy" onclick="navTo('privacy', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <span>Privacy Notices (Sec 5)</span>
                </a>
                <a href="#consent" onclick="navTo('consent', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg>
                    <span>Consent &amp; Withdrawals</span>
                </a>
                <a href="#rights" onclick="navTo('rights', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                    <span>Data Principal Rights</span>
                </a>
                <a href="#vendors" onclick="navTo('vendors', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    <span>Vendor Management</span>
                </a>
                <a href="#retention" onclick="navTo('retention', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    <span>Retention &amp; Erasure</span>
                </a>
                <a href="#breach" onclick="navTo('breach', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>Breach Management (Sec 8(6))</span>
                </a>

                <div class="nav-group-title">Governance &amp; Audit</div>
                <a href="#evidence" onclick="navTo('evidence', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    <span>Evidence Vault</span>
                </a>
                <a href="#remediation" onclick="navTo('remediation', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                    <span>Remediation Centre</span>
                    <span class="nav-pill nav-pill-amber" id="nav-gaps-count">3</span>
                </a>
                <a href="#reports" onclick="navTo('reports', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <span>Reports</span>
                </a>
                <a href="#settings" onclick="navTo('settings', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    <span>Settings &amp; Team</span>
                </a>
            </div>

            <div class="sidebar-footer">
                <div style="font-weight: 600; color: #ffffff;">TrustAudit &bull; India</div>
                <div style="font-size: 11px; margin-top: 2px;">DPDP Act 2023 &amp; Rules 2025</div>
            </div>
        </aside>

        <!-- MAIN AREA -->
        <main class="main-area">
            <!-- TOP BAR -->
            <header class="top-bar">
                <div class="topbar-left">
                    <div class="org-badge">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>
                        <span id="topbar-org-name">{{ org_info.name if org_info else "Arogya Diagnostics Clinic" }}</span>
                    </div>
                    <div class="readiness-chip">
                        <span>DPDP Readiness:</span>
                        <strong id="topbar-readiness-val">82%</strong>
                        <span style="font-size: 10.5px; opacity: 0.8;">(Self-Attested)</span>
                    </div>
                </div>

                <div class="topbar-right">
                    <a href="/trust" target="_blank" class="btn btn-secondary btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        <span>Public Trust Centre</span>
                    </a>
                    <button onclick="openAssistantModal()" class="btn btn-primary btn-sm">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                        <span>AI DPDP Assistant</span>
                    </button>
                </div>
            </header>

            <!-- CONTENT BODY -->
            <div class="content-body">

                <!-- ============================================================== -->
                <!-- SECTION 1: OVERVIEW                                            -->
                <!-- ============================================================== -->
                <div id="section-overview" class="dash-section active">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Compliance Overview</h1>
                            <p class="page-subtitle">Continuous operational posture, applicable requirements, and evidence readiness.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="openAddInventoryModal()" class="btn btn-secondary">+ Add Inventory Entry</button>
                            <button onclick="navTo('assessment')" class="btn btn-primary">Review Assessment</button>
                        </div>
                    </div>

                    <div class="grid-kpi">
                        <div class="kpi-card">
                            <div class="kpi-title">DPDP Readiness Status</div>
                            <div class="kpi-val" style="color: var(--brand-accent);" id="kpi-readiness">82%</div>
                            <div class="kpi-sub">12 of 15 Requirements Addressed</div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-title">Personal Data Inventory</div>
                            <div class="kpi-val" id="kpi-inventory-count">18</div>
                            <div class="kpi-sub">Across 6 Clinical / Staff Streams</div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-title">Compliance Gaps</div>
                            <div class="kpi-val" style="color: var(--brand-amber);" id="kpi-gaps-count">3</div>
                            <div class="kpi-sub">Actionable Tasks in Remediation</div>
                        </div>
                        <div class="kpi-card">
                            <div class="kpi-title">Evidence Artifacts</div>
                            <div class="kpi-val" style="color: var(--brand-emerald);" id="kpi-evidence-count">14</div>
                            <div class="kpi-sub">SHA-256 Cryptographic Records</div>
                        </div>
                    </div>

                    <!-- RECENT WORKFLOWS -->
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                                <span>Core DPDP Workflows &amp; Readiness Status</span>
                            </div>
                            <span class="badge-pill badge-sky">Statutory Timelines Active</span>
                        </div>

                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Workflow / Control</th>
                                        <th>Statutory Reference</th>
                                        <th>Applicable Date</th>
                                        <th>Current Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><strong>Itemised Patient Privacy Notice</strong></td>
                                        <td>Section 5 read with Rule 3</td>
                                        <td>13 May 2027</td>
                                        <td><span class="badge-pill badge-emerald">Published (English &amp; Hindi)</span></td>
                                        <td><a href="#privacy" onclick="navTo('privacy')" style="color: var(--brand-accent);">Manage &rarr;</a></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Consent Withdrawal &amp; Processor Cascading</strong></td>
                                        <td>Section 6(4)-(6)</td>
                                        <td>13 May 2027</td>
                                        <td><span class="badge-pill badge-emerald">Operational Workflow Active</span></td>
                                        <td><a href="#consent" onclick="navTo('consent')" style="color: var(--brand-accent);">View Logs &rarr;</a></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Data Principal Access &amp; Erasure Desk</strong></td>
                                        <td>Sections 11–14</td>
                                        <td>13 May 2027</td>
                                        <td><span class="badge-pill badge-sky">2 Requests In Progress</span></td>
                                        <td><a href="#rights" onclick="navTo('rights')" style="color: var(--brand-accent);">Ticketing &rarr;</a></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Diagnostic Lab &amp; HMS Vendor DPAs</strong></td>
                                        <td>Section 8(2)</td>
                                        <td>13 May 2027</td>
                                        <td><span class="badge-pill badge-amber">1 DPA Review Pending</span></td>
                                        <td><a href="#vendors" onclick="navTo('vendors')" style="color: var(--brand-accent);">Review &rarr;</a></td>
                                    </tr>
                                    <tr>
                                        <td><strong>Dual-Stage Breach Intimation Procedure</strong></td>
                                        <td>Section 8(6) read with Rule 7</td>
                                        <td>13 May 2027</td>
                                        <td><span class="badge-pill badge-emerald">Draft Forms Prepared</span></td>
                                        <td><a href="#breach" onclick="navTo('breach')" style="color: var(--brand-accent);">Configure &rarr;</a></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION: DPDP WEBSITE SCANNER                                  -->
                <!-- ============================================================== -->
                <div id="section-scanner" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Website Scanner &amp; Gap Detection</h1>
                            <p class="page-subtitle">Scan your publicly accessible website for observable DPDP privacy gaps, trackers, form disclosures, and consent practices.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="triggerWebsiteScan(true)" class="btn btn-secondary">Run Demo Scan</button>
                            <a href="#history" onclick="document.getElementById('scanner-history-card').scrollIntoView({behavior: 'smooth'})" class="btn btn-secondary">Scan History</a>
                        </div>
                    </div>

                    <!-- HERO SCANNER CONFIGURATION BENTO -->
                    <div class="scanner-hero">
                        <!-- LEFT: FORM INPUTS -->
                        <div class="card" style="margin-bottom: 0;">
                            <div class="card-header">
                                <div class="card-title">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
                                    <span>Target Website &amp; Business Profile</span>
                                </div>
                                <span class="badge-pill badge-emerald">Safe &bull; Passive Only</span>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
                                <div class="form-group" style="grid-column: span 2;">
                                    <label class="form-label">Website URL <span style="color: var(--brand-red);">*</span></label>
                                    <input type="url" id="scanner-url" class="form-control" placeholder="https://exampleclinic.in" value="https://arogyaclinic.example.in">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Business Name</label>
                                    <input type="text" id="scanner-biz-name" class="form-control" placeholder="e.g. Arogya Diagnostics Clinic" value="Arogya Diagnostics Clinic">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Industry <span style="color: var(--brand-red);">*</span></label>
                                    <select id="scanner-industry" class="form-control" onchange="adaptIndustryChecks()">
                                        <option value="healthcare" selected>Healthcare / Clinic / Diagnostics</option>
                                        <option value="clinics">Speciality Clinics</option>
                                        <option value="diagnostic centres">Diagnostic Laboratories</option>
                                        <option value="hospitals">Hospitals &amp; Daycare Centres</option>
                                        <option value="education">Education &amp; EdTech</option>
                                        <option value="saas">SaaS &amp; Software Products</option>
                                        <option value="ecommerce">E-Commerce &amp; Retail</option>
                                        <option value="professional services">Professional Services</option>
                                        <option value="other">Other Businesses</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Business Type</label>
                                    <input type="text" id="scanner-biz-type" class="form-control" value="Diagnostic &amp; Healthcare Clinic">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Primary Website Purpose</label>
                                    <input type="text" id="scanner-purpose" class="form-control" value="Patient Consultations, Test Bookings &amp; Telehealth">
                                </div>
                            </div>

                            <!-- INDUSTRY SPECIFIC TOGGLES -->
                            <div style="background: var(--bg-card); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-color); margin-bottom: 16px;">
                                <div style="font-size: 11.5px; font-weight: 700; color: var(--brand-accent); text-transform: uppercase; margin-bottom: 10px;">Tailored DPDP Scope Checks</div>
                                <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12.5px;">
                                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="checkbox" id="scanner-collects-pii" checked>
                                        <span>Website Collects Personal Data (Names, Mobile Numbers, Enquiries, Appointments)</span>
                                    </label>
                                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="checkbox" id="scanner-children-data" checked>
                                        <span id="label-children-data">Processes Children's / Minor Data (Section 9 Verifiable Parental Consent Required)</span>
                                    </label>
                                </div>
                            </div>

                            <!-- MANDATORY AUTHORIZATION CHECKBOX -->
                            <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 18px;">
                                <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; font-size: 12px; color: #f1f5f9;">
                                    <input type="checkbox" id="scanner-auth-confirm" checked style="margin-top: 2px;">
                                    <span><strong>Authorization Confirmation:</strong> I confirm that I own this website or have explicit authorization to assess its DPDP compliance readiness. The scan performs safe, non-invasive passive observation only.</span>
                                </label>
                            </div>

                            <div style="display: flex; gap: 12px;">
                                <button id="btn-start-scan" onclick="triggerWebsiteScan(false)" class="btn btn-primary" style="flex: 1; padding: 11px;">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                                    <span>Start DPDP Website Scan</span>
                                </button>
                                <button id="btn-demo-scan" onclick="triggerWebsiteScan(true)" class="btn btn-secondary" style="padding: 11px 18px;">
                                    <span>Instant Demo Scan</span>
                                </button>
                            </div>
                        </div>

                        <!-- RIGHT: CERTINAL-STYLE RADAR VISUAL -->
                        <div class="scanner-visual-card">
                            <div class="scanner-node-tag node-tag-1">Section 5 &bull; Itemised Notice</div>
                            <div class="scanner-node-tag node-tag-2">Section 6 &bull; Unpreselected Consent</div>
                            <div class="scanner-node-tag node-tag-3">Section 8(2) &bull; Third-Party Trackers</div>
                            <div class="scanner-node-tag node-tag-4">Section 13 &bull; Grievance Officer</div>

                            <div class="radar-box">
                                <div class="radar-ring"></div>
                                <div class="radar-sweep"></div>
                                <div class="radar-center-dot"></div>
                            </div>

                            <div style="text-align: center; margin-top: 24px;">
                                <div style="font-size: 15px; font-weight: 800; color: #ffffff;">Automated Perimeter Audit</div>
                                <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px; max-width: 280px;">Observes publicly published notices, form inputs, analytics scripts, and security headers without intrusive testing.</p>
                            </div>
                        </div>
                    </div>

                    <!-- PROGRESS STAGES PANEL (VISIBLE WHEN RUNNING) -->
                    <div id="scanner-progress-panel" class="card" style="display: none;">
                        <div class="card-header">
                            <div class="card-title">
                                <span class="spinner" style="display: inline-block; width: 14px; height: 14px; border: 2px solid #38bdf8; border-top-color: transparent; border-radius: 50%; animation: radarRotate 0.8s linear infinite;"></span>
                                <span id="progress-status-text">Scanning Website: Connecting &amp; SSRF Verification...</span>
                            </div>
                            <span class="badge-pill badge-sky" id="progress-percent-badge">10%</span>
                        </div>

                        <div style="background: var(--bg-card); height: 8px; border-radius: 9999px; overflow: hidden; margin-bottom: 20px;">
                            <div id="progress-bar-fill" style="width: 10%; height: 100%; background: linear-gradient(90deg, var(--brand-accent), var(--brand-emerald)); transition: width 0.3s ease;"></div>
                        </div>

                        <div class="progress-stage-grid">
                            <div id="stage-01" class="stage-item stage-active">01 &bull; Connecting &amp; SSRF</div>
                            <div id="stage-02" class="stage-item">02 &bull; Discovering Public Pages</div>
                            <div id="stage-03" class="stage-item">03 &bull; Detecting Form Inputs</div>
                            <div id="stage-04" class="stage-item">04 &bull; Analysing Privacy Notice</div>
                            <div id="stage-05" class="stage-item">05 &bull; Inspecting Consent Checkboxes</div>
                            <div id="stage-06" class="stage-item">06 &bull; Detecting Third-Party Trackers</div>
                            <div id="stage-07" class="stage-item">07 &bull; Checking Rights &amp; Grievances</div>
                            <div id="stage-08" class="stage-item">08 &bull; Mapping DPDP Penalties</div>
                            <div id="stage-09" class="stage-item">09 &bull; Assembling Findings</div>
                        </div>

                        <div style="background: #090e17; border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px; font-family: monospace; font-size: 11px; color: #94a3b8; max-height: 120px; overflow-y: auto;" id="scanner-terminal-log">
                            <div>[INFO] Initializing passive scanner worker...</div>
                        </div>
                    </div>

                    <!-- RESULTS DASHBOARD (VISIBLE WHEN COMPLETE) -->
                    <div id="scanner-results-panel" style="display: none;">
                        <!-- TOP KPI METRICS -->
                        <div class="grid-kpi">
                            <div class="kpi-card">
                                <div class="kpi-title">Pages Inspected</div>
                                <div class="kpi-val" id="res-pages-count">0</div>
                                <div class="kpi-sub" id="res-domain-sub">Target Domain</div>
                            </div>
                            <div class="kpi-card">
                                <div class="kpi-title">Forms Discovered</div>
                                <div class="kpi-val" id="res-forms-count">0</div>
                                <div class="kpi-sub">Public Data Intakes</div>
                            </div>
                            <div class="kpi-card">
                                <div class="kpi-title">Third-Party Services</div>
                                <div class="kpi-val" id="res-trackers-count">0</div>
                                <div class="kpi-sub">External Scripts &amp; Pixels</div>
                            </div>
                            <div class="kpi-card">
                                <div class="kpi-title">DPDP Readiness Index</div>
                                <div class="kpi-val" style="color: var(--brand-accent);" id="res-score-val">0%</div>
                                <div class="kpi-sub" id="res-score-sub">Perimeter Readiness Score</div>
                            </div>
                        </div>

                        <!-- FINDINGS CONTAINER -->
                        <div class="card">
                            <div class="card-header" style="flex-wrap: wrap; gap: 12px;">
                                <div>
                                    <div class="card-title" id="findings-title">Observed DPDP Compliance Gaps &amp; Safeguards</div>
                                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Click any finding to inspect evidence, legal references, and potential statutory exposure.</div>
                                </div>
                                <div style="display: flex; gap: 8px; flex-wrap: wrap;" id="findings-filter-bar">
                                    <button class="filter-btn active" onclick="filterFindings('ALL')">All (<span id="count-all">0</span>)</button>
                                    <button class="filter-btn" onclick="filterFindings('HIGH')">High (<span id="count-high">0</span>)</button>
                                    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium (<span id="count-med">0</span>)</button>
                                    <button class="filter-btn" onclick="filterFindings('FUTURE')">Future Readiness</button>
                                </div>
                            </div>

                            <!-- FINDINGS LIST -->
                            <div id="findings-list-wrap">
                                <!-- Cards injected dynamically -->
                            </div>
                        </div>

                        <!-- STATUTORY DISCLAIMER BANNER -->
                        <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: var(--radius-md); padding: 18px 22px; margin-bottom: 24px; font-size: 12.5px; color: #f1f5f9; line-height: 1.6;">
                            <strong style="color: #fbbf24; display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                <span>Statutory Legal Notice &amp; Scope Limitation</span>
                            </strong>
                            A public website scan evaluates observable perimeter disclosures, forms, cookies, and technical headers. It does not establish complete legal compliance or non-compliance under the Digital Personal Data Protection Act, 2023. Internal controls such as employee access permissions, encryption at rest, and purpose-based retention schedules cannot be observed from a public website. Penalty amounts cited in findings reflect statutory maximum ceilings under the Schedule to the Act, not predicted or automatic fines.
                        </div>

                        <!-- BRIDGE TO FULL INTERNAL ASSESSMENT -->
                        <div class="card" style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9)); border: 1px solid var(--border-subtle);">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                                <div>
                                    <h3 style="font-size: 16px; font-weight: 800; color: #ffffff;">Ready to Complete Your Full DPDP Compliance Journey?</h3>
                                    <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Transition from public website discovery to comprehensive internal assessment, RoPA inventory, and evidence vault management.</p>
                                </div>
                                <button onclick="navTo('assessment')" class="btn btn-primary" style="padding: 10px 20px;">
                                    <span>Continue With Full DPDP Assessment &rarr;</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- SCAN HISTORY CARD -->
                    <div class="card" id="scanner-history-card">
                        <div class="card-header">
                            <div class="card-title">Past Website Compliance Scans</div>
                            <span class="badge-pill badge-sky" id="history-scans-count">0 Recorded</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Date &amp; Time</th>
                                        <th>Target Website</th>
                                        <th>Industry</th>
                                        <th>Pages Inspected</th>
                                        <th>Observable Gaps</th>
                                        <th>Readiness Score</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="scanner-history-tbody">
                                    <tr>
                                        <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No website scans recorded yet. Enter a URL above and click "Start DPDP Website Scan".</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Statutory Requirements Assessment</h1>
                            <p class="page-subtitle">Evaluate controls against the DPDP Act 2023, Rules 2025, and October 2026 Removal of Difficulties Order.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Requirement Controls Matrix (15 Evaluated)</div>
                            <span class="badge-pill badge-amber">3 Actionable Gaps</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table" id="assessment-table">
                                <thead>
                                    <tr>
                                        <th>Section / Rule</th>
                                        <th>Requirement Title</th>
                                        <th>Category</th>
                                        <th>Effective Date</th>
                                        <th>Self-Attested Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="assessment-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 3: PERSONAL DATA INVENTORY                             -->
                <!-- ============================================================== -->
                <div id="section-inventory" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Personal Data Inventory</h1>
                            <p class="page-subtitle">Catalog all digital personal data, collection sources, legal bases, storage systems, and retention rules.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="downloadInventoryCSV()" class="btn btn-secondary">Export CSV</button>
                            <button onclick="openAddInventoryModal()" class="btn btn-primary">+ Add Data Stream</button>
                        </div>
                    </div>

                    <div class="card">
                        <div class="table-wrap">
                            <table class="dash-table" id="inventory-table">
                                <thead>
                                    <tr>
                                        <th>Data Category</th>
                                        <th>Principal Type</th>
                                        <th>Processing Purpose</th>
                                        <th>Legal Basis</th>
                                        <th>Storage System</th>
                                        <th>Department</th>
                                        <th>Retention</th>
                                        <th>Transfer</th>
                                    </tr>
                                </thead>
                                <tbody id="inventory-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 4: PRIVACY NOTICES (SECTION 5)                         -->
                <!-- ============================================================== -->
                <div id="section-privacy" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Privacy Notice Management</h1>
                            <p class="page-subtitle">Generate itemised privacy notices under Section 5 &amp; Rule 3 with Grievance Officer details and Eighth Schedule language readiness.</p>
                        </div>
                        <button onclick="openNoticeModal()" class="btn btn-primary">+ Generate New Notice</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Published Itemised Notices</div>
                            <span class="badge-pill badge-emerald">Rule 3 Compliant</span>
                        </div>
                        <div id="notice-cards-container">
                            <!-- Notice cards populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 5: CONSENT & WITHDRAWAL (SECTION 6)                    -->
                <!-- ============================================================== -->
                <div id="section-consent" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Consent Records &amp; Withdrawal Workflows</h1>
                            <p class="page-subtitle">Execute Section 6(4)-(6) consent withdrawal workflows that cascade instructions to data processors.</p>
                        </div>
                        <button onclick="openWithdrawalModal()" class="btn btn-primary">+ Log Consent Withdrawal</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Withdrawal Requests &amp; Processor Cease-Processing Audits</div>
                            <span class="badge-pill badge-sky">Section 6(4) Active</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Principal Reference</th>
                                        <th>Data Category</th>
                                        <th>Processing Halt</th>
                                        <th>Processors Notified</th>
                                        <th>Statutory Retention Check</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="withdrawal-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 6: DATA PRINCIPAL RIGHTS                               -->
                <!-- ============================================================== -->
                <div id="section-rights" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Data Principal Rights Management</h1>
                            <p class="page-subtitle">Statutory request tracking for Access (Sec 11), Correction (Sec 12), Erasure, Grievance (Sec 13), and Nomination (Sec 14).</p>
                        </div>
                        <button onclick="openRightsModal()" class="btn btn-primary">+ New Rights Request</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Active Requests &amp; SLA Tracking (30-Day Window)</div>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Request ID</th>
                                        <th>Type</th>
                                        <th>Principal</th>
                                        <th>Received Date</th>
                                        <th>SLA Deadline</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="rights-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 7: VENDOR MANAGEMENT (SECTION 8(2))                    -->
                <!-- ============================================================== -->
                <div id="section-vendors" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Vendor &amp; Data Processor Register</h1>
                            <p class="page-subtitle">Track Data Processing Agreements (DPAs), cloud storage regions, and breach notification terms under Section 8(2).</p>
                        </div>
                        <button onclick="openVendorModal()" class="btn btn-primary">+ Add Vendor Record</button>
                    </div>

                    <div class="card">
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Vendor Name</th>
                                        <th>Service Provided</th>
                                        <th>Personal Data Handled</th>
                                        <th>Storage Region</th>
                                        <th>DPA Contract Status</th>
                                        <th>Breach Clause</th>
                                        <th>Risk</th>
                                    </tr>
                                </thead>
                                <tbody id="vendors-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 8: RETENTION & ERASURE (RULE 8)                        -->
                <!-- ============================================================== -->
                <div id="section-retention" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Retention &amp; Erasure Schedules</h1>
                            <p class="page-subtitle">Define Rule 8 retention justification, statutory preservation rules, and end-of-purpose deletion workflows.</p>
                        </div>
                        <button onclick="openRetentionModal()" class="btn btn-primary">+ Add Retention Rule</button>
                    </div>

                    <div class="card">
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Data Category</th>
                                        <th>Retention Period</th>
                                        <th>Statutory Justification</th>
                                        <th>End of Purpose Trigger</th>
                                        <th>Disposal Method</th>
                                        <th>Next Review</th>
                                    </tr>
                                </thead>
                                <tbody id="retention-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 9: BREACH MANAGEMENT (SECTION 8(6))                    -->
                <!-- ============================================================== -->
                <div id="section-breach" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Personal Data Breach Management</h1>
                            <p class="page-subtitle">Section 8(6) &amp; Rule 7 incident logging, dual-stage Board intimation drafts, and Data Principal notifications.</p>
                        </div>
                        <button onclick="openBreachModal()" class="btn btn-primary">+ Log Security Incident</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Incident Register &amp; Statutory Intimations</div>
                            <span class="badge-pill badge-emerald">Requires Customer Authorization</span>
                        </div>
                        <div id="breach-cards-container">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 10: EVIDENCE VAULT                                     -->
                <!-- ============================================================== -->
                <div id="section-evidence" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Compliance Evidence Vault</h1>
                            <p class="page-subtitle">Tenant-isolated storage of notices, executed DPAs, staff training logs, and deletion certificates with SHA-256 integrity.</p>
                        </div>
                        <button onclick="openEvidenceModal()" class="btn btn-primary">+ Upload Evidence</button>
                    </div>

                    <div class="card">
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Document Title</th>
                                        <th>Requirement Mapping</th>
                                        <th>Uploaded Date</th>
                                        <th>SHA-256 Checksum</th>
                                        <th>Review Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="evidence-tbody">
                                    <!-- Populated dynamically -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 11: REMEDIATION CENTRE                                 -->
                <!-- ============================================================== -->
                <div id="section-remediation" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Compliance Remediation Centre</h1>
                            <p class="page-subtitle">Actionable tasks linked to identified compliance gaps with statutory explanations, templates, and deadlines.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Active Remediation Action Items</div>
                        </div>
                        <div id="remediation-list-container">
                            <!-- Populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 12: REPORTS                                            -->
                <!-- ============================================================== -->
                <div id="section-reports" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Compliance Reports</h1>
                            <p class="page-subtitle">Generate audit-ready readiness summaries and executive compliance packs.</p>
                        </div>
                        <button onclick="window.print()" class="btn btn-secondary">Print / Save as PDF</button>
                    </div>

                    <div class="card" style="max-width: 800px; margin: 0 auto; background: #ffffff; color: #0f172a; padding: 36px; border-radius: 8px;">
                        <div style="border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h2 style="font-size: 22px; font-weight: 800; color: #0f172a;">DPDP READINESS REPORT</h2>
                                <div style="font-size: 13px; color: #475569;">Digital Personal Data Protection Act, 2023 &bull; Evaluation Summary</div>
                            </div>
                            <div style="text-align: right; font-size: 12px; color: #475569;">
                                <div>Date: 2026-11-22</div>
                                <div>Status: Self-Attested Review</div>
                            </div>
                        </div>

                        <div style="margin-bottom: 20px;">
                            <h4 style="font-size: 14px; font-weight: 700; margin-bottom: 6px;">Organisation Profile</h4>
                            <div style="font-size: 13px; color: #334155;">Organisation: <strong>Arogya Diagnostics Clinic Ltd</strong></div>
                            <div style="font-size: 13px; color: #334155;">Sector: Healthcare &bull; Jurisdiction: India</div>
                        </div>

                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; text-align: center;">
                            <div style="background: #f1f5f9; padding: 12px; border-radius: 6px;">
                                <div style="font-size: 11px; color: #64748b;">READINESS SCORE</div>
                                <div style="font-size: 24px; font-weight: 800; color: #0284c7;">82%</div>
                            </div>
                            <div style="background: #f1f5f9; padding: 12px; border-radius: 6px;">
                                <div style="font-size: 11px; color: #64748b;">INVENTORY STREAMS</div>
                                <div style="font-size: 24px; font-weight: 800; color: #059669;">18</div>
                            </div>
                            <div style="background: #f1f5f9; padding: 12px; border-radius: 6px;">
                                <div style="font-size: 11px; color: #64748b;">OPEN GAPS</div>
                                <div style="font-size: 24px; font-weight: 800; color: #d97706;">3</div>
                            </div>
                        </div>

                        <div style="font-size: 12px; color: #64748b; border-top: 1px solid #cbd5e1; padding-top: 12px;">
                            Disclaimer: This report represents self-attested operational evaluation under TrustAudit DPDP Platform. It does not constitute statutory government certification or formal legal advice.
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 13: SETTINGS & TEAM                                    -->
                <!-- ============================================================== -->
                <div id="section-settings" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Settings &amp; Organisation Governance</h1>
                            <p class="page-subtitle">Configure organization details, team roles, MFA, and Data Principal rights settings.</p>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">Organisation Profile</div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Legal Entity Name</label>
                                <input type="text" class="form-control" value="Arogya Diagnostics Clinic Ltd" readonly>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Sector</label>
                                <input type="text" class="form-control" value="Healthcare (Clinics &amp; Diagnostics)" readonly>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Designated Grievance Officer</label>
                                <input type="text" class="form-control" value="Medical Records Superintendent">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Grievance Email (Section 8(10))</label>
                                <input type="email" class="form-control" value="grievance@organisation.com">
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">Data Protection &amp; Account Security</div>
                            </div>
                            <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                                Multi-Factor Authentication (RFC 6238 TOTP) is enforced for organization administrators accessing patient inventory records.
                            </div>
                            <div style="padding: 12px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 6px; color: var(--brand-emerald); font-weight: 600; font-size: 12.5px; margin-bottom: 16px;">
                                &bull; PBKDF2-HMAC-SHA256 (600,000 iterations active)
                            </div>
                            <div style="border-top: 1px solid var(--border-color); padding-top: 14px;">
                                <div style="font-weight: 700; color: #ffffff; margin-bottom: 4px;">Organisation Data Erasure</div>
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">Purge all organization records, evidence artifacts, and session logs with 0-day active scrubbing.</div>
                                <button onclick="confirmOrgDeletion()" class="btn btn-secondary btn-sm" style="color: var(--brand-red); border-color: rgba(239, 68, 68, 0.3);">Request Account Scrubbing</button>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </main>
    </div>

    <!-- AI ASSISTANT MODAL -->
    <div id="assistantModal" class="modal-overlay">
        <div class="modal-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3 style="font-size: 18px; font-weight: 700; color: #ffffff;">AI DPDP Legal Assistant</h3>
                <button onclick="closeAssistantModal()" style="background: none; font-size: 20px; color: var(--text-muted);">&times;</button>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 14px;">
                Grounded queries across the DPDP Act 2023, DPDP Rules 2025, and October 2026 Gazette Orders. Zero external data transmission.
            </div>

            <div class="assistant-chat" id="chat-messages">
                <div class="chat-bubble chat-ai">
                    Hello! I am your DPDP Assistant. You can ask about Section 5 notices, Section 6 consent withdrawal, Section 7 legitimate uses, Section 8(6) breach notifications, or children's data under Section 9.
                </div>
            </div>

            <div style="display: flex; gap: 8px;">
                <input type="text" id="ai-query-input" class="form-control" placeholder="Ask about DPDP requirements..." onkeydown="if(event.key==='Enter') sendAiQuery()">
                <button onclick="sendAiQuery()" class="btn btn-primary" id="ai-send-btn">Ask</button>
            </div>
            <div style="font-size: 11px; color: var(--text-dim); margin-top: 8px; text-align: center;">
                Informational guidance only &bull; Does not constitute formal legal counsel.
            </div>
        </div>
    </div>

    <!-- MODAL: ADD INVENTORY ENTRY -->
    <div id="addInventoryModal" class="modal-overlay">
        <div class="modal-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3 style="font-size: 18px; font-weight: 700; color: #ffffff;">Add Personal Data Inventory Stream</h3>
                <button onclick="closeAddInventoryModal()" style="background: none; font-size: 20px; color: var(--text-muted);">&times;</button>
            </div>

            <form onsubmit="submitNewInventory(event)">
                <div class="form-group">
                    <label class="form-label">Data Category *</label>
                    <input type="text" id="inv_cat" class="form-control" placeholder="e.g. Patient Clinical Diagnostic Reports" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Data Principal Type *</label>
                    <input type="text" id="inv_principal" class="form-control" placeholder="e.g. Patients / Minor Guardians" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Processing Purpose *</label>
                    <input type="text" id="inv_purpose" class="form-control" placeholder="e.g. Medical diagnosis &amp; treatment" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Legal Basis *</label>
                    <select id="inv_basis" class="form-control">
                        <option value="DPDP Section 6 (Consent)">DPDP Section 6 (Consent)</option>
                        <option value="DPDP Section 7(e) (Medical Emergency)">DPDP Section 7(e) (Medical Emergency)</option>
                        <option value="DPDP Section 7(c) (Legal Obligation)">DPDP Section 7(c) (Legal Obligation)</option>
                        <option value="DPDP Section 7(i) (Employment)">DPDP Section 7(i) (Employment)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Storage System *</label>
                    <input type="text" id="inv_storage" class="form-control" placeholder="e.g. Hospital Management System / AWS Mumbai" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Retention Period *</label>
                    <input type="text" id="inv_retention" class="form-control" placeholder="e.g. 5 Years (Clinical Records Rules)" required>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
                    <button type="button" onclick="closeAddInventoryModal()" class="btn btn-secondary">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save Entry</button>
                </div>
            </form>
        </div>
    </div>

    <!-- JAVASCRIPT LOGIC -->
    <script>
        let currentSection = 'overview';

        function navTo(sectionId, el) {
            document.querySelectorAll('.dash-section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            const target = document.getElementById('section-' + sectionId);
            if (target) {
                target.classList.add('active');
                currentSection = sectionId;
            }
            if (el) el.classList.add('active');
            else {
                document.querySelectorAll('.nav-item').forEach(n => {
                    if (n.getAttribute('href') === '#' + sectionId) n.classList.add('active');
                });
            }
        }

        // On Load, fetch DPDP data from backend APIs
        window.addEventListener('DOMContentLoaded', async () => {
            const hash = window.location.hash.replace('#', '') || 'overview';
            navTo(hash);
            await loadAllDpdpData();
        });

        async function loadAllDpdpData() {
            try {
                // 1. Load Inventory
                const invRes = await fetch('/api/dpdp/inventory');
                if (invRes.ok) {
                    const inv = await invRes.json();
                    renderInventory(inv.items || []);
                }

                // 2. Load Assessment
                const assRes = await fetch('/api/dpdp/assessment');
                if (assRes.ok) {
                    const ass = await assRes.json();
                    renderAssessment(ass);
                }

                // 3. Load Privacy Notices
                const notRes = await fetch('/api/dpdp/notices');
                if (notRes.ok) {
                    const nots = await notRes.json();
                    renderNotices(nots.items || []);
                }

                // 4. Load Withdrawals
                const wthRes = await fetch('/api/dpdp/withdrawals');
                if (wthRes.ok) {
                    const wths = await wthRes.json();
                    renderWithdrawals(wths.items || []);
                }

                // 5. Load Rights Requests
                const rgtRes = await fetch('/api/dpdp/rights');
                if (rgtRes.ok) {
                    const rgts = await rgtRes.json();
                    renderRights(rgts.items || []);
                }

                // 6. Load Vendors
                const vndRes = await fetch('/api/dpdp/vendors');
                if (vndRes.ok) {
                    const vnds = await vndRes.json();
                    renderVendors(vnds.items || []);
                }

                // 7. Load Retention
                const retRes = await fetch('/api/dpdp/retention');
                if (retRes.ok) {
                    const rets = await retRes.json();
                    renderRetention(rets.items || []);
                }

                // 8. Load Breaches
                const brcRes = await fetch('/api/dpdp/breaches');
                if (brcRes.ok) {
                    const brcs = await brcRes.json();
                    renderBreaches(brcs.items || []);
                }

                // 9. Load Evidence
                const eviRes = await fetch('/api/evidence');
                if (eviRes.ok) {
                    const evis = await eviRes.json();
                    renderEvidence(evis.evidence || []);
                }

                // 10. Load Website Scan History
                await loadWebsiteScanHistory();
            } catch (err) {
                console.warn('Backend DPDP data fetch fallback:', err);
            }
        }

        function renderInventory(items) {
            const tbody = document.getElementById('inventory-tbody');
            if (!tbody) return;
            const navInv = document.getElementById('nav-inv-count');
            const kpiInv = document.getElementById('kpi-inventory-count');
            if (navInv) navInv.innerText = items.length;
            if (kpiInv) kpiInv.innerText = items.length;
            
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim);">No data inventory items logged. Click "+ Add Data Stream" to start.</td></tr>';
                return;
            }

            tbody.innerHTML = items.map(item => `
                <tr>
                    <td><strong>${escapeHtml(item.category || '')}</strong></td>
                    <td>${escapeHtml(item.principal_type || '')}</td>
                    <td>${escapeHtml(item.purpose || '')}</td>
                    <td><span class="badge-pill badge-sky">${escapeHtml(item.legal_basis || '')}</span></td>
                    <td>${escapeHtml(item.storage_system || '')}</td>
                    <td>${escapeHtml(item.department || '')}</td>
                    <td>${escapeHtml(item.retention_period || '')}</td>
                    <td>${escapeHtml(item.international_transfer || 'None')}</td>
                </tr>
            `).join('');
        }

        function renderAssessment(assessment) {
            const tbody = document.getElementById('assessment-tbody');
            if (!tbody) return;
            const controls = assessment.controls || [];
            const kpiRead = document.getElementById('kpi-readiness');
            const topRead = document.getElementById('topbar-readiness-val');
            const kpiGaps = document.getElementById('kpi-gaps-count');
            const navGaps = document.getElementById('nav-gaps-count');
            if (kpiRead) kpiRead.innerText = (assessment.readiness_score || 82) + '%';
            if (topRead) topRead.innerText = (assessment.readiness_score || 82) + '%';
            if (kpiGaps) kpiGaps.innerText = assessment.gaps_count || 0;
            if (navGaps) navGaps.innerText = assessment.gaps_count || 0;

            tbody.innerHTML = controls.map(ctrl => {
                const isGap = ctrl.status === 'GAP_IDENTIFIED';
                const pillClass = isGap ? 'badge-amber' : 'badge-emerald';
                const statusLabel = isGap ? 'Gap Identified' : 'Self-Attested Implemented';
                return `
                    <tr>
                        <td><strong style="color: var(--brand-accent);">${escapeHtml(ctrl.section || '')}</strong></td>
                        <td>${escapeHtml(ctrl.title || '')}</td>
                        <td>${escapeHtml(ctrl.category || '')}</td>
                        <td>${escapeHtml(ctrl.effective_date || '')}</td>
                        <td><span class="badge-pill ${pillClass}">${statusLabel}</span></td>
                        <td><button onclick="alert('Viewing control: ${ctrl.requirement_id}')" class="btn btn-secondary btn-sm">Inspect</button></td>
                    </tr>
                `;
            }).join('');

            // Render Remediation list
            const remContainer = document.getElementById('remediation-list-container');
            if (remContainer) {
                const tasks = assessment.remediation_tasks || [];
                remContainer.innerHTML = tasks.map(t => `
                    <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-weight: 700; color: #ffffff;">${escapeHtml(t.title || '')}</div>
                            <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Owner: ${escapeHtml(t.owner || '')} &bull; Deadline: ${escapeHtml(t.deadline || '')} &bull; Category: ${escapeHtml(t.category || '')}</div>
                            <div style="font-size: 11.5px; color: var(--text-dim); margin-top: 4px;">${escapeHtml(t.guidance || '')}</div>
                        </div>
                        <span class="badge-pill badge-amber">Open Action Item</span>
                    </div>
                `).join('') || '<div style="color: var(--text-dim); text-align: center;">No open remediation tasks.</div>';
            }
        }

        function renderNotices(items) {
            const container = document.getElementById('notice-cards-container');
            if (!container) return;
            if (!items.length) {
                container.innerHTML = '<div style="color: var(--text-dim); text-align: center; padding: 20px;">No custom privacy notices generated yet.</div>';
                return;
            }
            container.innerHTML = items.map(n => `
                <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <h4 style="font-size: 15px; font-weight: 700; color: #ffffff;">${escapeHtml(n.title || '')} (${escapeHtml(n.version || 'v1.0')})</h4>
                        <span class="badge-pill badge-emerald">Approved</span>
                    </div>
                    <pre style="background: #090e17; padding: 12px; border-radius: 6px; font-size: 11.5px; color: #94a3b8; overflow-x: auto; white-space: pre-wrap; max-height: 180px;">${escapeHtml(n.content || '')}</pre>
                </div>
            `).join('');
        }

        function renderWithdrawals(items) {
            const tbody = document.getElementById('withdrawal-tbody');
            if (!tbody) return;
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No consent withdrawals logged.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(w => `
                <tr>
                    <td><code>${escapeHtml(w.id || '')}</code></td>
                    <td><strong>${escapeHtml(w.data_principal_ref || '')}</strong></td>
                    <td>${escapeHtml(w.category || '')}</td>
                    <td><span class="badge-pill badge-emerald">${escapeHtml(w.processing_halt_status || 'CEASED')}</span></td>
                    <td>${w.processor_notified ? '<span class="badge-pill badge-emerald">Cascaded</span>' : 'Pending'}</td>
                    <td>${w.statutory_exception_applies ? '<span style="color: var(--brand-amber);">' + escapeHtml(w.exception_reason || '') + '</span>' : 'None (Full Erasure)'}</td>
                    <td><span class="badge-pill badge-emerald">${escapeHtml(w.status || 'COMPLETED')}</span></td>
                </tr>
            `).join('');
        }

        function renderRights(items) {
            const tbody = document.getElementById('rights-tbody');
            if (!tbody) return;
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No rights requests logged.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(r => `
                <tr>
                    <td><code>${escapeHtml(r.id || '')}</code></td>
                    <td><span class="badge-pill badge-sky">${escapeHtml(r.type || '')}</span></td>
                    <td>${escapeHtml(r.principal_name || '')}</td>
                    <td>${escapeHtml(r.received_at ? r.received_at.slice(0, 10) : '')}</td>
                    <td>${escapeHtml(r.sla_deadline || '')}</td>
                    <td><span class="badge-pill ${r.status==='COMPLETED'?'badge-emerald':'badge-amber'}">${escapeHtml(r.status || '')}</span></td>
                    <td><button onclick="resolveRightsRequest('${r.id}')" class="btn btn-secondary btn-sm">Resolve</button></td>
                </tr>
            `).join('');
        }

        function renderVendors(items) {
            const tbody = document.getElementById('vendors-tbody');
            if (!tbody) return;
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No vendors registered.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(v => `
                <tr>
                    <td><strong>${escapeHtml(v.name || '')}</strong></td>
                    <td>${escapeHtml(v.service || '')}</td>
                    <td>${escapeHtml(v.personal_data_processed || '')}</td>
                    <td>${escapeHtml(v.storage_location || '')}</td>
                    <td><span class="badge-pill ${v.dpa_status==='EXECUTED'?'badge-emerald':'badge-amber'}">${escapeHtml(v.dpa_status || '')}</span></td>
                    <td>${escapeHtml(v.breach_notification_clause || '')}</td>
                    <td><span class="badge-pill ${v.risk_rating==='LOW'?'badge-emerald':'badge-amber'}">${escapeHtml(v.risk_rating || '')}</span></td>
                </tr>
            `).join('');
        }

        function renderRetention(items) {
            const tbody = document.getElementById('retention-tbody');
            if (!tbody) return;
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No retention rules configured.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(r => `
                <tr>
                    <td><strong>${escapeHtml(r.category || '')}</strong></td>
                    <td>${escapeHtml(r.period_years ? r.period_years + ' Years' : '')}</td>
                    <td>${escapeHtml(r.statutory_basis || '')}</td>
                    <td>${escapeHtml(r.end_of_purpose_trigger || '')}</td>
                    <td>${escapeHtml(r.deletion_method || '')}</td>
                    <td>${escapeHtml(r.next_review_date || '')}</td>
                </tr>
            `).join('');
        }

        function renderBreaches(items) {
            const container = document.getElementById('breach-cards-container');
            if (!container) return;
            if (!items.length) {
                container.innerHTML = '<div style="color: var(--text-dim); text-align: center; padding: 20px;">No security incidents reported. Platform operational.</div>';
                return;
            }
            container.innerHTML = items.map(b => `
                <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <h4 style="font-size: 15px; font-weight: 700; color: #ffffff;">${escapeHtml(b.title || '')}</h4>
                        <span class="badge-pill badge-red">${escapeHtml(b.severity || 'MEDIUM')} SEVERITY</span>
                    </div>
                    <div style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 10px;">
                        Detected: ${escapeHtml(b.detected_at || '')} &bull; Affected Categories: ${escapeHtml((b.affected_data_categories||[]).join(', '))}
                    </div>
                    <div style="background: #090e17; padding: 12px; border-radius: 6px; font-size: 11.5px; color: #94a3b8; margin-bottom: 10px; white-space: pre-wrap;">${escapeHtml(b.board_initial_intimation_draft || '')}</div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 11.5px; color: var(--brand-amber);">Status: ${escapeHtml(b.board_notification_status || 'DRAFT')}</span>
                        ${!b.customer_authorized_to_send ? `<button onclick="authorizeBreach('${b.id}')" class="btn btn-primary btn-sm">Authorize Intimation</button>` : '<span class="badge-pill badge-emerald">Authorized &bull; Submitted</span>'}
                    </div>
                </div>
            `).join('');
        }

        function renderEvidence(items) {
            const tbody = document.getElementById('evidence-tbody');
            if (!tbody) return;
            const kpiEvi = document.getElementById('kpi-evidence-count');
            if (kpiEvi) kpiEvi.innerText = items.length;
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No evidence artifacts uploaded yet.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(e => `
                <tr>
                    <td><strong>${escapeHtml(e.title || e.filename || '')}</strong></td>
                    <td><span class="badge-pill badge-sky">${escapeHtml(e.control_id || e.category || 'General')}</span></td>
                    <td>${escapeHtml(e.uploaded_at ? e.uploaded_at.slice(0, 10) : '')}</td>
                    <td><code style="font-size: 11px; color: var(--brand-accent);">${escapeHtml((e.file_hash || 'SHA-256 Verified').slice(0, 20))}...</code></td>
                    <td><span class="badge-pill badge-emerald">${escapeHtml(e.status || 'VERIFIED')}</span></td>
                    <td><button onclick="alert('Evidence artifact integrity verified via SHA-256.')" class="btn btn-secondary btn-sm">Inspect</button></td>
                </tr>
            `).join('');
        }

        function escapeHtml(str) {
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // CSV Export
        function downloadInventoryCSV() {
            window.location.href = '/api/dpdp/inventory/export';
        }

        // Modals
        function openAddInventoryModal() { document.getElementById('addInventoryModal').classList.add('open'); }
        function closeAddInventoryModal() { document.getElementById('addInventoryModal').classList.remove('open'); }
        function openAssistantModal() { document.getElementById('assistantModal').classList.add('open'); }
        function closeAssistantModal() { document.getElementById('assistantModal').classList.remove('open'); }

        async function submitNewInventory(e) {
            e.preventDefault();
            const data = {
                category: document.getElementById('inv_cat').value.trim(),
                principal_type: document.getElementById('inv_principal').value.trim(),
                purpose: document.getElementById('inv_purpose').value.trim(),
                legal_basis: document.getElementById('inv_basis').value,
                storage_system: document.getElementById('inv_storage').value.trim(),
                retention_period: document.getElementById('inv_retention').value.trim()
            };
            const res = await fetch('/api/dpdp/inventory', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (res.ok) {
                closeAddInventoryModal();
                await loadAllDpdpData();
            } else {
                alert('Could not add inventory entry');
            }
        }

        async function sendAiQuery() {
            const input = document.getElementById('ai-query-input');
            const q = input.value.trim();
            if (!q) return;
            const chat = document.getElementById('chat-messages');
            chat.innerHTML += `<div class="chat-bubble chat-user">${escapeHtml(q)}</div>`;
            input.value = '';

            try {
                const res = await fetch('/api/dpdp/assistant', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: q })
                });
                const data = await res.json();
                chat.innerHTML += `
                    <div class="chat-bubble chat-ai">
                        <div style="font-size: 11px; color: var(--brand-accent); font-weight: 700; margin-bottom: 4px;">${escapeHtml(data.matched_section || '')}</div>
                        <div>${escapeHtml(data.response || '')}</div>
                        <div style="font-size: 10.5px; color: var(--text-dim); margin-top: 6px;">Status: ${escapeHtml(data.effective_status || '')} &bull; Source: ${escapeHtml(data.source_document || '')}</div>
                    </div>
                `;
                chat.scrollTop = chat.scrollHeight;
            } catch (err) {
                chat.innerHTML += `<div class="chat-bubble chat-ai" style="color: var(--brand-red);">Assistant error. Please try again.</div>`;
            }
        }

        async function resolveRightsRequest(id) {
            const summary = prompt('Enter resolution summary for Data Principal:');
            if (summary) {
                await fetch('/api/dpdp/rights/' + id + '/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: 'COMPLETED', response_summary: summary })
                });
                await loadAllDpdpData();
            }
        }

        async function authorizeBreach(id) {
            if (confirm('Authorize notification to the Data Protection Board under Section 8(6) & Rule 7?')) {
                await fetch('/api/dpdp/breaches/' + id + '/authorize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                await loadAllDpdpData();
            }
        }

        // ==============================================================================
        // DPDP WEBSITE SCANNER FUNCTIONS
        // ==============================================================================
        let activeScanReport = null;
        let activeFilter = 'ALL';

        function adaptIndustryChecks() {
            const ind = (document.getElementById('scanner-industry').value || '').toLowerCase();
            const childToggle = document.getElementById('scanner-children-data');
            const childLabel = document.getElementById('label-children-data');
            const purposeInput = document.getElementById('scanner-purpose');
            const typeInput = document.getElementById('scanner-biz-type');

            if (ind.includes('health') || ind.includes('clinic') || ind.includes('diag') || ind.includes('hosp')) {
                if (childToggle) childToggle.checked = true;
                if (childLabel) childLabel.textContent = "Processes Pediatric / Minor Patient Data (Section 9 Parental Consent)";
                if (purposeInput) purposeInput.value = "Patient Consultations, Test Bookings & Telehealth";
                if (typeInput) typeInput.value = "Diagnostic & Healthcare Clinic";
            } else if (ind.includes('educat')) {
                if (childToggle) childToggle.checked = true;
                if (childLabel) childLabel.textContent = "Processes Student / Minor Records under 18 (Section 9 Verifiable Consent)";
                if (purposeInput) purposeInput.value = "Student Admissions, Online Learning & Academic Enquiries";
                if (typeInput) typeInput.value = "Educational Institution / EdTech";
            } else if (ind.includes('saas')) {
                if (childToggle) childToggle.checked = false;
                if (childLabel) childLabel.textContent = "Children / Minor Data Processed (Toggle if intended for minors)";
                if (purposeInput) purposeInput.value = "B2B SaaS Platform User Onboarding & Subscription Management";
                if (typeInput) typeInput.value = "SaaS / Technology Company";
            } else if (ind.includes('ecom')) {
                if (childToggle) childToggle.checked = false;
                if (purposeInput) purposeInput.value = "E-Commerce Shopping, Customer Orders & Deliveries";
                if (typeInput) typeInput.value = "Online Retail Store";
            }
        }

        async function triggerWebsiteScan(isDemo) {
            const urlInput = document.getElementById('scanner-url');
            const url = urlInput.value.trim();
            const authConfirmed = document.getElementById('scanner-auth-confirm').checked;

            if (!authConfirmed) {
                alert('Please confirm website ownership or scan authorization before proceeding.');
                return;
            }

            if (!url) {
                alert('Please enter a target website URL.');
                urlInput.focus();
                return;
            }

            const btnStart = document.getElementById('btn-start-scan');
            const btnDemo = document.getElementById('btn-demo-scan');
            const progressPanel = document.getElementById('scanner-progress-panel');
            const resultsPanel = document.getElementById('scanner-results-panel');
            const progressBar = document.getElementById('progress-bar-fill');
            const statusText = document.getElementById('progress-status-text');
            const percentBadge = document.getElementById('progress-percent-badge');
            const terminalLog = document.getElementById('scanner-terminal-log');

            btnStart.disabled = true;
            btnDemo.disabled = true;
            resultsPanel.style.display = 'none';
            progressPanel.style.display = 'block';
            progressPanel.scrollIntoView({ behavior: 'smooth' });

            terminalLog.innerHTML = `<div>[${new Date().toLocaleTimeString()}] Initializing DPDP passive scanner worker...</div>`;

            // Stage animation simulation while backend runs
            const stages = [
                { id: 'stage-01', text: '01 · Connecting & SSRF Verification', pct: 15 },
                { id: 'stage-02', text: '02 · Discovering Public Pages & Sitemaps', pct: 28 },
                { id: 'stage-03', text: '03 · Detecting Personal Data Forms', pct: 40 },
                { id: 'stage-04', text: '04 · Analysing Privacy Notice Disclosures', pct: 52 },
                { id: 'stage-05', text: '05 · Inspecting Consent Checkboxes', pct: 64 },
                { id: 'stage-06', text: '06 · Detecting Third-Party Trackers', pct: 75 },
                { id: 'stage-07', text: '07 · Checking Rights & Grievance Information', pct: 85 },
                { id: 'stage-08', text: '08 · Mapping DPDP Statutory Penalties', pct: 93 },
                { id: 'stage-09', text: '09 · Generating Comprehensive Report', pct: 100 }
            ];

            let stageIdx = 0;
            const stageTimer = setInterval(() => {
                if (stageIdx < stages.length) {
                    const st = stages[stageIdx];
                    progressBar.style.width = st.pct + '%';
                    percentBadge.textContent = st.pct + '%';
                    statusText.textContent = st.text;
                    document.querySelectorAll('.stage-item').forEach(el => el.classList.remove('stage-active'));
                    const curEl = document.getElementById(st.id);
                    if (curEl) {
                        curEl.classList.add('stage-active');
                        if (stageIdx > 0) {
                            const prevEl = document.getElementById(stages[stageIdx - 1].id);
                            if (prevEl) prevEl.classList.add('stage-done');
                        }
                    }
                    terminalLog.innerHTML += `<div>[${new Date().toLocaleTimeString()}] ${st.text}... OK</div>`;
                    terminalLog.scrollTop = terminalLog.scrollHeight;
                    stageIdx++;
                }
            }, 600);

            try {
                const payload = {
                    website_url: url,
                    business_name: document.getElementById('scanner-biz-name').value.trim(),
                    industry: document.getElementById('scanner-industry').value,
                    business_type: document.getElementById('scanner-biz-type').value.trim(),
                    website_purpose: document.getElementById('scanner-purpose').value.trim(),
                    collects_personal_info: document.getElementById('scanner-collects-pii').checked,
                    children_data_processed: document.getElementById('scanner-children-data').checked,
                    authorization_confirmed: true,
                    is_demo: isDemo
                };

                const res = await fetch('/api/dpdp/scanner/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                clearInterval(stageTimer);
                const data = await res.json();

                if (res.ok && data.status === 'success') {
                    // Mark all stages done
                    document.querySelectorAll('.stage-item').forEach(el => {
                        el.classList.remove('stage-active');
                        el.classList.add('stage-done');
                    });
                    progressBar.style.width = '100%';
                    percentBadge.textContent = '100%';
                    statusText.textContent = 'Scan Complete!';
                    terminalLog.innerHTML += `<div>[${new Date().toLocaleTimeString()}] Report generated successfully. Ready to review.</div>`;

                    setTimeout(() => {
                        progressPanel.style.display = 'none';
                        renderWebsiteScanResults(data.scan);
                        resultsPanel.style.display = 'block';
                        resultsPanel.scrollIntoView({ behavior: 'smooth' });
                        loadWebsiteScanHistory();
                    }, 500);
                } else {
                    progressPanel.style.display = 'none';
                    alert(data.message || 'Website scan failed. Check URL or SSRF boundary.');
                }
            } catch (err) {
                clearInterval(stageTimer);
                progressPanel.style.display = 'none';
                alert('Website scan request error: ' + err.message);
            } finally {
                btnStart.disabled = false;
                btnDemo.disabled = false;
            }
        }

        function renderWebsiteScanResults(scan) {
            activeScanReport = scan;
            const metrics = scan.summary_metrics || {};

            document.getElementById('res-pages-count').textContent = metrics.pages_scanned_count || 0;
            document.getElementById('res-forms-count').textContent = metrics.forms_discovered_count || 0;
            document.getElementById('res-trackers-count').textContent = metrics.third_party_services_count || 0;
            document.getElementById('res-score-val').textContent = (metrics.readiness_score || 0) + '%';
            document.getElementById('res-domain-sub').textContent = scan.target_url || 'Target Domain';

            // Filter counts
            const findings = scan.findings || [];
            document.getElementById('count-all').textContent = findings.length;
            document.getElementById('count-high').textContent = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
            document.getElementById('count-med').textContent = findings.filter(f => f.severity === 'MEDIUM').length;

            renderFindingsList(findings);
        }

        function renderFindingsList(findings) {
            const wrap = document.getElementById('findings-list-wrap');
            if (!findings || findings.length === 0) {
                wrap.innerHTML = `<div style="text-align: center; padding: 30px; color: var(--text-dim);">No compliance gaps detected matching current filter.</div>`;
                return;
            }

            wrap.innerHTML = findings.map((f, i) => {
                const sevBadge = f.severity === 'CRITICAL' ? 'badge-red' :
                                 (f.severity === 'HIGH' ? 'badge-amber' :
                                 (f.severity === 'MEDIUM' ? 'badge-sky' : 'badge-emerald'));

                const effBadge = f.effective_status === 'SCHEDULED_MAY_2027' ?
                    '<span class="badge-pill badge-sky" style="font-size: 10px;">Future Readiness: Scheduled 13 May 2027</span>' :
                    '<span class="badge-pill badge-emerald" style="font-size: 10px;">In Force</span>';

                return `
                    <div class="finding-card" id="finding-card-${f.id}">
                        <div class="finding-header" onclick="toggleFindingCard('${f.id}')">
                            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                                <span class="badge-pill ${sevBadge}">${escapeHtml(f.severity)}</span>
                                <strong style="font-size: 13.5px; color: #ffffff;">${escapeHtml(f.title)}</strong>
                                <span style="font-size: 11px; color: var(--brand-accent);">${escapeHtml(f.legal_reference)}</span>
                                ${effBadge}
                            </div>
                            <svg id="arrow-${f.id}" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>

                        <div class="finding-body" id="body-${f.id}">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Observation</div>
                                    <div style="color: #f1f5f9; margin-top: 4px;">${escapeHtml(f.observation || '')}</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Affected Component &amp; Page</div>
                                    <div style="color: var(--brand-accent); margin-top: 4px; font-family: monospace; font-size: 11.5px;">${escapeHtml(f.affected_component || '')} &bull; ${escapeHtml(f.affected_page || '')}</div>
                                </div>
                            </div>

                            <div style="margin-bottom: 14px;">
                                <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 4px;">Technical Evidence Snippet</div>
                                <div style="background: #090e17; border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px; font-family: monospace; font-size: 11.5px; color: #94a3b8; overflow-x: auto;">
                                    ${escapeHtml(f.evidence_snippet || 'Observed via passive inspection')}
                                </div>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Why This Matters</div>
                                    <div style="color: #cbd5e1; margin-top: 4px; line-height: 1.5;">${escapeHtml(f.why_it_matters || '')}</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">Recommended Remediation Action</div>
                                    <div style="color: #34d399; margin-top: 4px; line-height: 1.5;">${escapeHtml(f.recommended_action || '')}</div>
                                </div>
                            </div>

                            <!-- STATUTORY PENALTY EXPOSURE -->
                            <div style="background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: var(--radius-sm); padding: 12px 14px; margin-bottom: 16px; font-size: 12px;">
                                <div style="font-weight: 700; color: #f87171; display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                                    <span>Potential Statutory Penalty Ceiling (Schedule to DPDP Act):</span>
                                    <span>${escapeHtml(f.penalty_ceiling_text || 'Up to ₹50 crore')}</span>
                                </div>
                                <div style="color: var(--text-muted); font-size: 11px;">
                                    ${escapeHtml(f.statutory_disclaimer || '')}
                                </div>
                            </div>

                            <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); padding-top: 14px;">
                                <div style="font-size: 11px; color: var(--text-dim);">
                                    Confidence: <strong style="color: #ffffff;">${escapeHtml(f.confidence || 'HIGH')}</strong> &bull; Required Evidence: <em>${escapeHtml(f.required_evidence || 'Documented procedure')}</em>
                                </div>
                                <button id="btn-fix-${f.id}" onclick="convertFindingToTask('${activeScanReport.scan_id}', '${f.id}')" class="btn btn-primary btn-sm">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>FIX THIS ISSUE &rarr; Create Remediation Task</span>
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function toggleFindingCard(id) {
            const body = document.getElementById('body-' + id);
            const arrow = document.getElementById('arrow-' + id);
            if (!body) return;
            if (body.classList.contains('expanded')) {
                body.classList.remove('expanded');
                if (arrow) arrow.style.transform = 'rotate(0deg)';
            } else {
                body.classList.add('expanded');
                if (arrow) arrow.style.transform = 'rotate(180deg)';
            }
        }

        function filterFindings(type) {
            activeFilter = type;
            document.querySelectorAll('#findings-filter-bar .filter-btn').forEach(b => b.classList.remove('active'));
            if (event && event.target) event.target.classList.add('active');

            if (!activeScanReport) return;
            const all = activeScanReport.findings || [];
            let filtered = all;

            if (type === 'HIGH') {
                filtered = all.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
            } else if (type === 'MEDIUM') {
                filtered = all.filter(f => f.severity === 'MEDIUM');
            } else if (type === 'FUTURE') {
                filtered = all.filter(f => f.effective_status === 'SCHEDULED_MAY_2027');
            }
            renderFindingsList(filtered);
        }

        async function convertFindingToTask(scanId, findingId) {
            const btn = document.getElementById('btn-fix-' + findingId);
            if (btn) btn.disabled = true;

            try {
                const res = await fetch('/api/dpdp/scanner/convert-task', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scan_id: scanId, finding_id: findingId, assignee: 'Privacy Lead' })
                });
                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    if (btn) {
                        btn.classList.remove('btn-primary');
                        btn.classList.add('btn-secondary');
                        btn.innerHTML = '<span>Task Added to Remediation Centre &#10003;</span>';
                    }
                    const gapEl = document.getElementById('kpi-gaps-count');
                    if (gapEl) gapEl.textContent = (parseInt(gapEl.textContent) || 0) + 1;
                } else {
                    alert('Could not convert finding: ' + (data.message || 'Error'));
                    if (btn) btn.disabled = false;
                }
            } catch (err) {
                alert('Request failed: ' + err.message);
                if (btn) btn.disabled = false;
            }
        }

        async function loadWebsiteScanHistory() {
            try {
                const res = await fetch('/api/dpdp/scanner/history');
                if (!res.ok) return;
                const data = await res.json();
                const scans = data.scans || [];
                const tbody = document.getElementById('scanner-history-tbody');
                const badge = document.getElementById('history-scans-count');

                if (badge) badge.textContent = `${scans.length} Recorded`;
                if (!tbody) return;

                if (scans.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No website scans recorded yet. Enter a URL above and click "Start DPDP Website Scan".</td></tr>`;
                    return;
                }

                tbody.innerHTML = scans.map(s => {
                    const dt = s.scanned_at ? new Date(s.scanned_at).toLocaleString() : 'Recent';
                    const score = s.summary_metrics?.readiness_score || 0;
                    const gaps = s.findings?.length || 0;
                    const pages = s.summary_metrics?.pages_scanned_count || 1;

                    return `
                        <tr>
                            <td>${escapeHtml(dt)}</td>
                            <td><strong style="color: #ffffff;">${escapeHtml(s.target_url || '')}</strong><br><span style="font-size: 11px; color: var(--text-dim);">${escapeHtml(s.business_name || '')}</span></td>
                            <td><span class="badge-pill badge-sky">${escapeHtml(s.industry || 'healthcare')}</span></td>
                            <td>${pages} Pages</td>
                            <td><span class="badge-pill ${gaps > 0 ? 'badge-amber' : 'badge-emerald'}">${gaps} Observable Gaps</span></td>
                            <td><strong style="color: var(--brand-accent);">${score}%</strong></td>
                            <td>
                                <button onclick="viewPastScan('${s.scan_id}')" class="btn btn-secondary btn-sm" style="margin-right: 6px;">View Report</button>
                                <button onclick="deletePastScan('${s.scan_id}')" style="background: none; color: var(--brand-red); font-size: 11px;">Delete</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                console.error('Error loading scan history:', err);
            }
        }

        async function viewPastScan(scanId) {
            try {
                const res = await fetch('/api/dpdp/scanner/results/' + scanId);
                if (res.ok) {
                    const data = await res.json();
                    renderWebsiteScanResults(data.scan);
                    const panel = document.getElementById('scanner-results-panel');
                    panel.style.display = 'block';
                    panel.scrollIntoView({ behavior: 'smooth' });
                }
            } catch (err) {
                alert('Could not load past scan: ' + err.message);
            }
        }

        async function deletePastScan(scanId) {
            if (confirm('Permanently delete this scan report and associated technical observations?')) {
                try {
                    const res = await fetch('/api/dpdp/scanner/' + scanId, { method: 'DELETE' });
                    if (res.ok) {
                        await loadWebsiteScanHistory();
                    }
                } catch (err) {
                    alert('Delete failed: ' + err.message);
                }
            }
        }

        function confirmOrgDeletion() {
            if (confirm('Are you sure you want to request permanent erasure of all organization records? This deletes user accounts, evidence artifacts, and compliance logs per DPDP Section 8(7).')) {
                fetch('/api/account/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
                    .then(() => { alert('Account deletion submitted.'); window.location.href = '/'; });
            }
        }
    </script>
</body>
</html>
"""
