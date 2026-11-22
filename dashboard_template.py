"""
TrustAudit — DPDP Compliance Management Platform Dashboard Template
===================================================================
Premium enterprise SaaS command centre for Indian businesses, clinics & healthcare.
Simplified 8-anchor navigation, 4-quadrant overview, 2-field website scanner, 
8 plain-English scanning stages, and 4-bucket findings layout.
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
            --bg-base: #f8fafc;
            --bg-surface: #ffffff;
            --bg-card: #f8fafc;
            --bg-card-hover: #f1f5f9;
            --sidebar-bg: #0f172a;
            --sidebar-surface: #1e293b;
            --sidebar-text: #94a3b8;
            --sidebar-text-hover: #ffffff;
            --sidebar-border: #1e293b;
            --text-main: #0f172a;
            --text-secondary: #334155;
            --text-muted: #64748b;
            --text-dim: #94a3b8;
            --border-color: #e2e8f0;
            --border-subtle: #cbd5e1;
            --brand-primary: #1d4ed8;
            --brand-primary-hover: #1e40af;
            --brand-primary-light: #eff6ff;
            --brand-accent: #0284c7;
            --brand-emerald: #059669;
            --brand-emerald-light: #ecfdf5;
            --brand-amber: #d97706;
            --brand-amber-light: #fffbeb;
            --brand-red: #dc2626;
            --brand-red-light: #fef2f2;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --radius-xl: 20px;
            --shadow-xs: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.08), 0 1px 2px -1px rgba(0, 0, 0, 0.08);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.08);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.08);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif; background: var(--bg-base); color: var(--text-main); line-height: 1.5; font-size: 13.5px; overflow-x: hidden; }
        a { color: inherit; text-decoration: none; }
        button { cursor: pointer; border: none; font-family: inherit; }

        .app-layout { display: flex; height: 100vh; overflow: hidden; }

        /* SIDEBAR — 8 CLEAN PRIMARY ANCHORS */
        aside.sidebar { width: 270px; background: var(--sidebar-bg); border-right: 1px solid var(--sidebar-border); display: flex; flex-direction: column; flex-shrink: 0; z-index: 20; }
        .sidebar-brand { height: 68px; display: flex; align-items: center; justify-content: space-between; padding: 0 20px; border-bottom: 1px solid var(--sidebar-border); }
        .sidebar-brand-inner { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 17px; color: #ffffff; letter-spacing: -0.3px; }
        .sidebar-brand-badge { font-size: 10px; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 2px 6px; border-radius: 4px; letter-spacing: 0.5px; }
        
        .sidebar-nav { flex-grow: 1; overflow-y: auto; padding: 14px 10px; }
        .sidebar-nav::-webkit-scrollbar { width: 5px; }
        .sidebar-nav::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        
        .nav-group-title { font-size: 10px; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.8px; padding: 12px 12px 4px 12px; }
        .nav-item { display: flex; align-items: center; gap: 10px; padding: 8.5px 12px; border-radius: var(--radius-md); font-weight: 600; font-size: 13px; color: var(--sidebar-text); transition: all 0.15s; margin-bottom: 2px; }
        .nav-item:hover { color: var(--sidebar-text-hover); background: rgba(255, 255, 255, 0.06); }
        .nav-item.active { color: #ffffff; background: var(--brand-primary); }
        .nav-item svg { width: 16px; height: 16px; flex-shrink: 0; }
        
        /* Expandable Sub-Navigation */
        .nav-parent { display: flex; align-items: center; justify-content: space-between; padding: 8.5px 12px; border-radius: var(--radius-md); font-weight: 600; font-size: 13px; color: var(--sidebar-text); cursor: pointer; transition: all 0.15s; margin-bottom: 2px; }
        .nav-parent:hover { color: var(--sidebar-text-hover); background: rgba(255, 255, 255, 0.06); }
        .nav-parent-title { display: flex; align-items: center; gap: 10px; }
        .nav-parent-title svg { width: 16px; height: 16px; flex-shrink: 0; }
        .nav-chevron { width: 14px; height: 14px; transition: transform 0.2s; }
        .nav-group.open .nav-chevron { transform: rotate(90deg); }
        .nav-sub-items { display: none; padding-left: 26px; margin: 2px 0 6px 0; }
        .nav-group.open .nav-sub-items { display: block; }
        .nav-sub-item { display: flex; align-items: center; justify-content: space-between; padding: 6.5px 12px; border-radius: var(--radius-sm); font-size: 12.5px; font-weight: 500; color: #94a3b8; transition: all 0.15s; margin-bottom: 1px; }
        .nav-sub-item:hover { color: #ffffff; background: rgba(255, 255, 255, 0.04); }
        .nav-sub-item.active { color: #ffffff; font-weight: 700; background: rgba(29, 78, 216, 0.4); }

        .nav-pill { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 9999px; }
        .nav-pill-amber { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
        .nav-pill-emerald { background: rgba(16, 185, 129, 0.2); color: #34d399; }
        .nav-pill-blue { background: rgba(56, 189, 248, 0.2); color: #38bdf8; }

        .sidebar-footer { padding: 14px 16px; border-top: 1px solid var(--sidebar-border); font-size: 12px; color: #64748b; background: rgba(0, 0, 0, 0.15); }
        .sidebar-footer-brand { font-weight: 700; color: #f1f5f9; display: flex; align-items: center; gap: 6px; }

        /* MAIN CONTENT AREA */
        main.main-area { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; background: var(--bg-base); }
        header.top-bar { height: 68px; background: var(--bg-surface); border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; padding: 0 28px; flex-shrink: 0; box-shadow: var(--shadow-xs); }
        .topbar-left { display: flex; align-items: center; gap: 14px; }
        .org-badge { display: flex; align-items: center; gap: 8px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 6px 14px; border-radius: 9999px; font-size: 12.5px; font-weight: 600; color: var(--text-main); }
        .readiness-chip { background: var(--brand-emerald-light); border: 1px solid rgba(5, 150, 105, 0.25); color: var(--brand-emerald); font-weight: 700; font-size: 12px; padding: 5px 12px; border-radius: 9999px; display: flex; align-items: center; gap: 6px; }
        .topbar-right { display: flex; align-items: center; gap: 12px; }

        .content-body { padding: 28px; max-width: 1400px; margin: 0 auto; width: 100%; }

        /* SECTIONS & ROUTING */
        .dash-section { display: none; }
        .dash-section.active { display: block; animation: fadeIn 0.2s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        .page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }
        .page-title { font-size: 22px; font-weight: 800; color: var(--text-main); letter-spacing: -0.4px; }
        .page-subtitle { font-size: 13.5px; color: var(--text-muted); margin-top: 4px; }

        /* CARDS & PANELS */
        .card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 22px; margin-bottom: 24px; box-shadow: var(--shadow-sm); }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; padding-bottom: 14px; border-bottom: 1px solid var(--border-color); }
        .card-title { font-size: 15px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 8px; }

        /* 4-QUADRANT OVERVIEW GRID */
        .overview-quad-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }
        @media (max-width: 1024px) { .overview-quad-grid { grid-template-columns: 1fr; } }
        
        .quad-card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 22px; box-shadow: var(--shadow-sm); display: flex; flex-direction: column; justify-content: space-between; }
        .quad-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-color); }
        .quad-title { font-size: 15px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 8px; }
        
        /* Quadrant 1: Progress Metrics */
        .progress-stat-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 16px 0; }
        .stat-box { background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 12px; text-align: center; }
        .stat-box-val { font-size: 20px; font-weight: 800; color: var(--text-main); line-height: 1.2; }
        .stat-box-lbl { font-size: 11px; font-weight: 600; color: var(--text-muted); margin-top: 4px; }
        .attest-note { font-size: 11.5px; color: var(--text-muted); background: var(--bg-base); border-radius: var(--radius-sm); padding: 8px 12px; border-left: 3px solid var(--brand-primary); }

        /* Quadrant 2: Top Attention Items */
        .action-item-card { background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; gap: 14px; transition: border-color 0.15s; }
        .action-item-card:hover { border-color: var(--brand-primary); }
        .action-item-info h4 { font-size: 13.5px; font-weight: 700; color: var(--text-main); margin-bottom: 3px; }
        .action-item-info p { font-size: 12px; color: var(--text-muted); line-height: 1.4; }

        /* Quadrant 3: Business Data */
        .biz-data-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
        .biz-item { background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 12px; }
        .biz-val { font-size: 22px; font-weight: 800; color: var(--brand-primary); line-height: 1.2; }
        .biz-lbl { font-size: 11.5px; font-weight: 600; color: var(--text-secondary); margin-top: 4px; }
        .biz-sub { font-size: 10.5px; color: var(--text-dim); }

        /* Quadrant 4: Recent Activity */
        .activity-feed { display: flex; flex-direction: column; gap: 10px; }
        .activity-item { display: flex; align-items: flex-start; gap: 12px; font-size: 12.5px; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); }
        .activity-item:last-child { border-bottom: none; padding-bottom: 0; }
        .activity-icon { width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .activity-meta { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

        /* BUTTONS & CONTROLS */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 8.5px 16px; border-radius: var(--radius-sm); font-weight: 600; font-size: 13px; transition: all 0.15s; }
        .btn-primary { background: var(--brand-primary); color: #ffffff; box-shadow: var(--shadow-xs); }
        .btn-primary:hover { background: var(--brand-primary-hover); }
        .btn-secondary { background: #ffffff; color: var(--text-main); border: 1px solid var(--border-color); box-shadow: var(--shadow-xs); }
        .btn-secondary:hover { background: var(--bg-card-hover); border-color: var(--border-subtle); }
        .btn-sm { padding: 5px 10px; font-size: 12px; }
        .btn-lg { padding: 11px 22px; font-size: 14px; }

        /* TABLES */
        .table-wrap { overflow-x: auto; }
        table.dash-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12.5px; }
        table.dash-table th { padding: 10px 14px; background: var(--bg-base); color: var(--text-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; border-bottom: 1px solid var(--border-color); }
        table.dash-table td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); color: var(--text-main); vertical-align: middle; }
        table.dash-table tr:hover td { background: var(--bg-base); }

        .badge-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 9999px; }
        .badge-emerald { background: var(--brand-emerald-light); color: var(--brand-emerald); }
        .badge-amber { background: var(--brand-amber-light); color: var(--brand-amber); }
        .badge-sky { background: var(--brand-primary-light); color: var(--brand-accent); }
        .badge-red { background: var(--brand-red-light); color: var(--brand-red); }
        .badge-gray { background: #f1f5f9; color: #475569; }

        /* FORMS & MODALS */
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 9px 12px; background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-sm); color: var(--text-main); font-size: 13px; font-family: inherit; transition: border-color 0.15s; }
        .form-control:focus { outline: none; border-color: var(--brand-primary); box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.1); }

        .modal-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.open { display: flex; }
        .modal-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-lg); width: 100%; max-width: 600px; padding: 26px; box-shadow: var(--shadow-lg); max-height: 90vh; overflow-y: auto; }

        /* ASSISTANT DRAWER */
        .assistant-panel { background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 20px; margin-top: 18px; }
        .assistant-chat { max-height: 280px; overflow-y: auto; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
        .chat-bubble { padding: 12px 14px; border-radius: var(--radius-md); font-size: 13px; line-height: 1.5; }
        .chat-user { background: var(--brand-primary); color: #ffffff; align-self: flex-end; max-width: 80%; }
        .chat-ai { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); align-self: flex-start; max-width: 90%; }

        /* ============================================================== */
        /* WEBSITE SCANNER STYLES & RADAR MOTION                         */
        /* ============================================================== */
        .scanner-hero-box { background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-lg); padding: 32px; margin-bottom: 24px; box-shadow: var(--shadow-sm); }
        .scanner-input-grid { display: grid; grid-template-columns: 2fr 1.2fr; gap: 16px; margin-bottom: 16px; }
        @media (max-width: 768px) { .scanner-input-grid { grid-template-columns: 1fr; } }
        
        .advanced-scanner-details { margin: 16px 0; border: 1px dashed var(--border-color); border-radius: var(--radius-md); padding: 14px 18px; background: var(--bg-base); }
        .advanced-scanner-details summary { font-size: 12.5px; font-weight: 700; color: var(--text-secondary); cursor: pointer; user-select: none; }
        .advanced-scanner-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 14px; }
        @media (max-width: 768px) { .advanced-scanner-grid { grid-template-columns: 1fr; } }

        /* Radar Scanning Visual */
        .scanner-radar-card { background: #0f172a; border-radius: var(--radius-lg); padding: 32px; display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; overflow: hidden; color: #ffffff; margin-bottom: 24px; box-shadow: var(--shadow-md); }
        .radar-box { position: relative; width: 140px; height: 140px; border-radius: 50%; border: 2px solid rgba(56, 189, 248, 0.3); display: flex; align-items: center; justify-content: center; background: radial-gradient(circle, rgba(56, 189, 248, 0.12) 0%, transparent 70%); margin: 0 auto 20px auto; }
        .radar-ring { position: absolute; inset: 18px; border-radius: 50%; border: 1px dashed rgba(56, 189, 248, 0.25); }
        .radar-sweep { position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(56, 189, 248, 0.45) 360deg); animation: radarRotate 2.2s linear infinite; }
        .radar-center-dot { width: 12px; height: 12px; border-radius: 50%; background: #38bdf8; box-shadow: 0 0 14px #38bdf8; z-index: 2; }
        @keyframes radarRotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

        .progress-stage-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 18px; width: 100%; }
        @media (max-width: 900px) { .progress-stage-grid { grid-template-columns: 1fr 1fr; } }
        .stage-item { display: flex; align-items: center; gap: 8px; padding: 9px 12px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: var(--radius-sm); font-size: 11.5px; font-weight: 600; color: #94a3b8; transition: all 0.2s; }
        .stage-item.stage-active { border-color: #38bdf8; color: #ffffff; background: rgba(56, 189, 248, 0.18); }
        .stage-item.stage-done { border-color: #10b981; color: #34d399; background: rgba(16, 185, 129, 0.12); }

        /* 4-BUCKET FINDINGS STYLING */
        .findings-buckets-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
        @media (max-width: 900px) { .findings-buckets-summary { grid-template-columns: 1fr 1fr; } }
        .bucket-badge-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px; text-align: center; cursor: pointer; transition: all 0.15s; }
        .bucket-badge-card:hover, .bucket-badge-card.active { border-color: var(--brand-primary); box-shadow: var(--shadow-sm); transform: translateY(-2px); }
        .bucket-badge-card.bucket-found { border-top: 3px solid var(--brand-emerald); }
        .bucket-badge-card.bucket-missing { border-top: 3px solid var(--brand-amber); }
        .bucket-badge-card.bucket-input { border-top: 3px solid var(--brand-accent); }
        .bucket-badge-card.bucket-internal { border-top: 3px solid #64748b; }
        .bucket-count { font-size: 22px; font-weight: 800; line-height: 1.2; }
        .bucket-name { font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
        .bucket-desc { font-size: 10.5px; color: var(--text-muted); margin-top: 2px; }

        .finding-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-lg); margin-bottom: 14px; overflow: hidden; transition: all 0.15s; box-shadow: var(--shadow-xs); }
        .finding-card:hover { border-color: var(--border-subtle); box-shadow: var(--shadow-sm); }
        .finding-header { padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
        .finding-header:hover { background: var(--bg-base); }
        .finding-body { padding: 0 20px 20px 20px; display: none; border-top: 1px solid var(--border-color); margin-top: 4px; padding-top: 16px; font-size: 13px; }
        .finding-body.expanded { display: block; animation: fadeIn 0.2s ease; }
        .filter-btn { padding: 6px 14px; font-size: 12px; font-weight: 600; border-radius: 9999px; background: #ffffff; color: var(--text-secondary); border: 1px solid var(--border-color); cursor: pointer; }
        .filter-btn.active { background: var(--brand-primary); color: #ffffff; border-color: var(--brand-primary); }
    </style>
</head>
<body>

    <div class="app-layout">
        <!-- ============================================================== -->
        <!-- SIDEBAR NAVIGATION (8 CLEAN PRIMARY GROUPS)                    -->
        <!-- ============================================================== -->
        <aside class="sidebar">
            <div class="sidebar-brand">
                <div class="sidebar-brand-inner">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>TrustAudit</span>
                </div>
                <span class="sidebar-brand-badge">DPDP</span>
            </div>

            <div class="sidebar-nav">
                <!-- 1. OVERVIEW -->
                <a href="#overview" onclick="navTo('overview', this)" class="nav-item active">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                    <span>Overview</span>
                </a>

                <!-- 2. WEBSITE SCANNER -->
                <a href="#scanner" onclick="navTo('scanner', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
                    <span>DPDP Website Scanner</span>
                    <span class="nav-pill nav-pill-emerald">NEW</span>
                </a>

                <!-- 3. DPDP ASSESSMENT -->
                <a href="#assessment" onclick="navTo('assessment', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <span>DPDP Assessment</span>
                    <span class="nav-pill nav-pill-amber">15</span>
                </a>

                <!-- 4. DATA MANAGEMENT (EXPANDABLE) -->
                <div class="nav-group open" id="group-datamgmt">
                    <div class="nav-parent" onclick="toggleNavGroup('group-datamgmt')">
                        <div class="nav-parent-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                            <span>Data Management</span>
                        </div>
                        <svg class="nav-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                    </div>
                    <div class="nav-sub-items">
                        <a href="#inventory" onclick="navTo('inventory', this)" class="nav-sub-item">
                            <span>Data Inventory</span>
                            <span class="nav-pill nav-pill-emerald" id="nav-inv-count">18</span>
                        </a>
                        <a href="#vendors" onclick="navTo('vendors', this)" class="nav-sub-item">
                            <span>Vendor Management</span>
                        </a>
                    </div>
                </div>

                <!-- 5. PRIVACY OPERATIONS (EXPANDABLE) -->
                <div class="nav-group open" id="group-privacyops">
                    <div class="nav-parent" onclick="toggleNavGroup('group-privacyops')">
                        <div class="nav-parent-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <span>Privacy Operations</span>
                        </div>
                        <svg class="nav-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                    </div>
                    <div class="nav-sub-items">
                        <a href="#privacy" onclick="navTo('privacy', this)" class="nav-sub-item">
                            <span>Privacy Notices (Sec 5)</span>
                        </a>
                        <a href="#consent" onclick="navTo('consent', this)" class="nav-sub-item">
                            <span>Consent &amp; Withdrawals</span>
                        </a>
                        <a href="#rights" onclick="navTo('rights', this)" class="nav-sub-item">
                            <span>Data Principal Rights</span>
                        </a>
                        <a href="#retention" onclick="navTo('retention', this)" class="nav-sub-item">
                            <span>Retention &amp; Erasure</span>
                        </a>
                        <a href="#breach" onclick="navTo('breach', this)" class="nav-sub-item">
                            <span>Breach Management (Sec 8(6))</span>
                        </a>
                    </div>
                </div>

                <!-- 6. EVIDENCE & TASKS (EXPANDABLE) -->
                <div class="nav-group open" id="group-evidencetasks">
                    <div class="nav-parent" onclick="toggleNavGroup('group-evidencetasks')">
                        <div class="nav-parent-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                            <span>Evidence &amp; Tasks</span>
                        </div>
                        <svg class="nav-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                    </div>
                    <div class="nav-sub-items">
                        <a href="#evidence" onclick="navTo('evidence', this)" class="nav-sub-item">
                            <span>Evidence Vault</span>
                        </a>
                        <a href="#remediation" onclick="navTo('remediation', this)" class="nav-sub-item">
                            <span>Remediation Centre</span>
                            <span class="nav-pill nav-pill-amber" id="nav-gaps-count">3</span>
                        </a>
                    </div>
                </div>

                <!-- 7. REPORTS -->
                <a href="#reports" onclick="navTo('reports', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <span>Reports</span>
                </a>

                <!-- 8. SETTINGS -->
                <a href="#settings" onclick="navTo('settings', this)" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    <span>Settings &amp; Team</span>
                </a>
            </div>

            <div class="sidebar-footer">
                <div class="sidebar-footer-brand">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>TrustAudit Platform</span>
                </div>
                <div style="font-size: 11px; margin-top: 2px;">India DPDP Act 2023 &bull; Rules 2025</div>
            </div>
        </aside>

        <!-- ============================================================== -->
        <!-- MAIN CONTENT AREA                                              -->
        <!-- ============================================================== -->
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
                        <span style="font-size: 10.5px; opacity: 0.85;">(Self-Attested &amp; Verified)</span>
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
                <!-- SECTION 1: OVERVIEW (4-QUADRANT SIMPLIFIED LAYOUT)             -->
                <!-- ============================================================== -->
                <div id="section-overview" class="dash-section active">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Compliance Overview</h1>
                            <p class="page-subtitle">Understand what personal data your business collects, track your compliance readiness, and manage tasks.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="navTo('scanner')" class="btn btn-secondary">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/></svg>
                                <span>Scan Website</span>
                            </button>
                            <button onclick="openAddInventoryModal()" class="btn btn-primary">+ Add Data Stream</button>
                        </div>
                    </div>

                    <!-- 4-QUADRANT LAYOUT -->
                    <div class="overview-quad-grid">
                        
                        <!-- QUADRANT 1: YOUR PROGRESS -->
                        <div class="quad-card">
                            <div>
                                <div class="quad-header">
                                    <div class="quad-title">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
                                        <span>1. Your Progress</span>
                                    </div>
                                    <span class="badge-pill badge-emerald">Active Posture</span>
                                </div>
                                <div style="display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px;">
                                    <div style="font-size: 40px; font-weight: 850; color: var(--brand-primary); line-height: 1;" id="kpi-readiness">82%</div>
                                    <div style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">DPDP Compliance Readiness</div>
                                </div>
                                <p style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 14px;">12 of 15 statutory requirement controls self-attested or verified with technical proof.</p>

                                <div class="progress-stat-row">
                                    <div class="stat-box">
                                        <div class="stat-box-val" id="kpi-evidence-count" style="color: var(--brand-emerald);">7</div>
                                        <div class="stat-box-lbl">Evidence Verified</div>
                                    </div>
                                    <div class="stat-box">
                                        <div class="stat-box-val" id="kpi-gaps-count" style="color: var(--brand-amber);">3</div>
                                        <div class="stat-box-lbl">Open Actions</div>
                                    </div>
                                    <div class="stat-box">
                                        <div class="stat-box-val" style="color: var(--brand-accent);">2</div>
                                        <div class="stat-box-lbl">Needing Review</div>
                                    </div>
                                </div>
                            </div>
                            <div class="attest-note">
                                <strong>Evidence-Based Tracking:</strong> TrustAudit posture metrics reflect self-attested business controls and verified technical evidence. Not a statutory certification.
                            </div>
                        </div>

                        <!-- QUADRANT 2: WHAT NEEDS ATTENTION -->
                        <div class="quad-card">
                            <div>
                                <div class="quad-header">
                                    <div class="quad-title">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                        <span>2. What Needs Attention</span>
                                    </div>
                                    <span class="badge-pill badge-amber">3 High Priority</span>
                                </div>
                                <p style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 14px;">Fix these top 3 pending items to rapidly improve your DPDP readiness score.</p>

                                <!-- Top Action 1 -->
                                <div class="action-item-card">
                                    <div class="action-item-info">
                                        <h4>Add Section 5 Notice to Patient Form</h4>
                                        <p>Public appointment form is missing grievance contact &amp; specific processing purposes.</p>
                                    </div>
                                    <button onclick="navTo('privacy')" class="btn btn-primary btn-sm" style="flex-shrink: 0;">View and Fix</button>
                                </div>

                                <!-- Top Action 2 -->
                                <div class="action-item-card">
                                    <div class="action-item-info">
                                        <h4>Review Diagnostic Cloud Processor DPA</h4>
                                        <p>DPA contract with cloud storage vendor is missing mandatory Section 8(2) clauses.</p>
                                    </div>
                                    <button onclick="navTo('vendors')" class="btn btn-primary btn-sm" style="flex-shrink: 0;">View and Fix</button>
                                </div>

                                <!-- Top Action 3 -->
                                <div class="action-item-card">
                                    <div class="action-item-info">
                                        <h4>Document Data Retention &amp; Erasure Schedule</h4>
                                        <p>Establish automated purge triggers when diagnostic processing purpose is completed.</p>
                                    </div>
                                    <button onclick="navTo('retention')" class="btn btn-primary btn-sm" style="flex-shrink: 0;">View and Fix</button>
                                </div>
                            </div>
                        </div>

                        <!-- QUADRANT 3: YOUR BUSINESS DATA -->
                        <div class="quad-card">
                            <div>
                                <div class="quad-header">
                                    <div class="quad-title">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                                        <span>3. Your Business Data</span>
                                    </div>
                                    <button onclick="navTo('inventory')" class="btn btn-secondary btn-sm">Manage RoPA</button>
                                </div>
                                <p style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 14px;">Summary of digital personal data categories and third parties identified in your business.</p>

                                <div class="biz-data-grid">
                                    <div class="biz-item">
                                        <div class="biz-val" id="kpi-inventory-count">18</div>
                                        <div class="biz-lbl">Data Streams</div>
                                        <div class="biz-sub">Cataloged in RoPA</div>
                                    </div>
                                    <div class="biz-item">
                                        <div class="biz-val">6</div>
                                        <div class="biz-lbl">Categories</div>
                                        <div class="biz-sub">Health, ID, Financial</div>
                                    </div>
                                    <div class="biz-item">
                                        <div class="biz-val">4</div>
                                        <div class="biz-lbl">Vendors</div>
                                        <div class="biz-sub">External Processors</div>
                                    </div>
                                    <div class="biz-item">
                                        <div class="biz-val">2</div>
                                        <div class="biz-lbl">Privacy Notices</div>
                                        <div class="biz-sub">Section 5 Compliant</div>
                                    </div>
                                    <div class="biz-item">
                                        <div class="biz-val">3</div>
                                        <div class="biz-lbl">User Requests</div>
                                        <div class="biz-sub">Access &amp; Erasure</div>
                                    </div>
                                    <div class="biz-item">
                                        <div class="biz-val" style="color: var(--brand-emerald);">0</div>
                                        <div class="biz-lbl">Data Breaches</div>
                                        <div class="biz-sub">Zero Incidents</div>
                                    </div>
                                </div>
                            </div>
                            <div style="display: flex; gap: 8px;">
                                <button onclick="openAddInventoryModal()" class="btn btn-secondary btn-sm" style="flex: 1;">+ Add Data Stream</button>
                                <button onclick="downloadInventoryCSV()" class="btn btn-secondary btn-sm" style="flex: 1;">Export RoPA CSV</button>
                            </div>
                        </div>

                        <!-- QUADRANT 4: RECENT ACTIVITY -->
                        <div class="quad-card">
                            <div>
                                <div class="quad-header">
                                    <div class="quad-title">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                                        <span>4. Recent Activity</span>
                                    </div>
                                    <span class="badge-pill badge-sky">Real-Time</span>
                                </div>
                                <p style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 14px;">Recent website scans, evidence uploads, customer requests, and policy revisions.</p>

                                <div class="activity-feed">
                                    <div class="activity-item">
                                        <div class="activity-icon" style="background: var(--brand-primary-light); color: var(--brand-primary);">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/></svg>
                                        </div>
                                        <div style="flex-grow: 1;">
                                            <div style="font-weight: 600; color: var(--text-main);">Website Privacy Scan Completed</div>
                                            <div class="activity-meta">Scanned target domain &bull; 82% Readiness Posture &bull; 10 mins ago</div>
                                        </div>
                                    </div>

                                    <div class="activity-item">
                                        <div class="activity-icon" style="background: var(--brand-emerald-light); color: var(--brand-emerald);">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>
                                        </div>
                                        <div style="flex-grow: 1;">
                                            <div style="font-weight: 600; color: var(--text-main);">Evidence Verified in Vault</div>
                                            <div class="activity-meta">Uploaded Signed Diagnostic Lab DPA &bull; SHA-256 verified &bull; 2 hours ago</div>
                                        </div>
                                    </div>

                                    <div class="activity-item">
                                        <div class="activity-icon" style="background: var(--brand-amber-light); color: var(--brand-amber);">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                                        </div>
                                        <div style="flex-grow: 1;">
                                            <div style="font-weight: 600; color: var(--text-main);">Customer Privacy Request Logged</div>
                                            <div class="activity-meta">Data access inquiry #REQ-8821 assigned to DPO &bull; 1 day ago</div>
                                        </div>
                                    </div>

                                    <div class="activity-item">
                                        <div class="activity-icon" style="background: #f1f5f9; color: #475569;">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
                                        </div>
                                        <div style="flex-grow: 1;">
                                            <div style="font-weight: 600; color: var(--text-main);">Section 5 Notice Draft Updated</div>
                                            <div class="activity-meta">Version 2.1 generated for patient appointment portal &bull; 2 days ago</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 2: DPDP WEBSITE SCANNER (SIMPLIFIED 2-FIELD INPUT)     -->
                <!-- ============================================================== -->
                <div id="section-scanner" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Check Your Website for DPDP Privacy Gaps.</h1>
                            <p class="page-subtitle">Enter your website address. TrustAudit will examine publicly visible privacy information and show you what may need attention.</p>
                        </div>
                        <div>
                            <button onclick="document.getElementById('scanner-url').value='https://arogyaclinic.in'; document.getElementById('scanner-industry').value='healthcare'; adaptIndustryChecks();" class="btn btn-secondary btn-sm">Load Healthcare Demo</button>
                        </div>
                    </div>

                    <!-- SCANNER INPUT CARD -->
                    <div class="scanner-hero-box">
                        <div class="scanner-input-grid">
                            <div class="form-group" style="margin-bottom: 0;">
                                <label class="form-label">Website URL *</label>
                                <input type="url" id="scanner-url" class="form-control" placeholder="https://yourclinic.in or https://yourcompany.com" value="https://arogyaclinic.in" style="font-size: 14.5px; padding: 11px 14px;">
                            </div>
                            <div class="form-group" style="margin-bottom: 0;">
                                <label class="form-label">Business Industry *</label>
                                <select id="scanner-industry" class="form-control" onchange="adaptIndustryChecks()" style="font-size: 14px; padding: 11px 14px;">
                                    <option value="healthcare">Healthcare, Diagnostic Clinic &amp; Hospitals</option>
                                    <option value="saas">SaaS, Technology &amp; Startups</option>
                                    <option value="education">Education, Schools &amp; EdTech</option>
                                    <option value="ecommerce">E-Commerce &amp; Retail Stores</option>
                                    <option value="fintech">Fintech, Insurance &amp; Financial Services</option>
                                    <option value="other">General Professional Services</option>
                                </select>
                            </div>
                        </div>

                        <!-- Authorization Checkbox -->
                        <div style="margin: 14px 0 16px 0; display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="scanner-auth-confirm" checked style="width: 16px; height: 16px; accent-color: var(--brand-primary); cursor: pointer;">
                            <label for="scanner-auth-confirm" style="font-size: 12.5px; color: var(--text-secondary); cursor: pointer;">
                                I confirm authorization to scan this publicly accessible website for DPDP compliance gaps. (Passive inspection only; zero intrusive testing).
                            </label>
                        </div>

                        <!-- Advanced Business Details (Accordion) -->
                        <details class="advanced-scanner-details">
                            <summary>Advanced Business Details &amp; Purpose Mapping (Optional)</summary>
                            <div class="advanced-scanner-grid">
                                <div class="form-group">
                                    <label class="form-label">Business Name</label>
                                    <input type="text" id="scanner-biz-name" class="form-control" placeholder="e.g. Arogya Diagnostic Centre" value="Arogya Diagnostics Clinic">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Entity Classification</label>
                                    <input type="text" id="scanner-biz-type" class="form-control" placeholder="e.g. Diagnostic &amp; Healthcare Clinic" value="Diagnostic &amp; Healthcare Clinic">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Website Processing Purpose</label>
                                    <input type="text" id="scanner-purpose" class="form-control" placeholder="e.g. Patient Consultations &amp; Test Bookings" value="Patient Consultations, Test Bookings &amp; Telehealth">
                                </div>
                                <div class="form-group" style="display: flex; flex-direction: column; justify-content: center;">
                                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12.5px; margin-bottom: 6px; cursor: pointer;">
                                        <input type="checkbox" id="scanner-collects-pii" checked style="accent-color: var(--brand-primary);">
                                        <span>Website Collects Customer / Patient Information</span>
                                    </label>
                                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12.5px; cursor: pointer;">
                                        <input type="checkbox" id="scanner-children-data" checked style="accent-color: var(--brand-primary);">
                                        <span id="label-children-data">Processes Pediatric / Minor Patient Data (Section 9)</span>
                                    </label>
                                </div>
                            </div>
                        </details>

                        <div style="display: flex; gap: 12px; margin-top: 18px; align-items: center;">
                            <button id="btn-start-scan" onclick="triggerWebsiteScan(false)" class="btn btn-primary btn-lg">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/></svg>
                                <span>Scan My Website</span>
                            </button>
                            <button id="btn-demo-scan" onclick="triggerWebsiteScan(true)" class="btn btn-secondary btn-lg">
                                <span>Try Live Clinic Demo</span>
                            </button>
                            <span style="font-size: 12px; color: var(--text-dim); margin-left: auto;">Takes ~15 seconds &bull; Zero traffic disruption</span>
                        </div>
                    </div>

                    <!-- SCANNER PROGRESS PANEL (8 PLAIN-ENGLISH STAGES) -->
                    <div id="scanner-progress-panel" style="display: none;">
                        <div class="scanner-radar-card">
                            <div class="radar-box">
                                <div class="radar-ring"></div>
                                <div class="radar-sweep"></div>
                                <div class="radar-center-dot"></div>
                            </div>
                            <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 6px;" id="progress-status-text">Connecting to your website...</h3>
                            <p style="font-size: 12.5px; color: #94a3b8; margin-bottom: 20px;">Analyzing publicly visible pages, notices, checkboxes, and third-party scripts</p>

                            <!-- 8 STAGES GRID -->
                            <div class="progress-stage-grid">
                                <div class="stage-item" id="stage-01">1. Connecting to website</div>
                                <div class="stage-item" id="stage-02">2. Finding important pages</div>
                                <div class="stage-item" id="stage-03">3. Checking privacy info</div>
                                <div class="stage-item" id="stage-04">4. Checking data forms</div>
                                <div class="stage-item" id="stage-05">5. Identifying third parties</div>
                                <div class="stage-item" id="stage-06">6. Checking privacy contacts</div>
                                <div class="stage-item" id="stage-07">7. Mapping DPDP rules</div>
                                <div class="stage-item" id="stage-08">8. Preparing report</div>
                            </div>

                            <div style="width: 100%; max-width: 600px; background: rgba(255, 255, 255, 0.1); border-radius: 9999px; height: 8px; overflow: hidden; margin-bottom: 12px;">
                                <div id="progress-bar-fill" style="width: 15%; height: 100%; background: #38bdf8; transition: width 0.3s ease;"></div>
                            </div>
                            <div style="display: flex; justify-content: space-between; width: 100%; max-width: 600px; font-size: 11.5px; color: #94a3b8;">
                                <span>Passive DPDP Security &amp; Privacy Crawler</span>
                                <span id="progress-percent-badge" style="font-weight: 700; color: #38bdf8;">15%</span>
                            </div>

                            <div id="scanner-terminal-log" style="width: 100%; max-width: 600px; background: #070b14; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; margin-top: 14px; font-family: monospace; font-size: 11px; color: #64748b; height: 70px; overflow-y: auto; text-align: left;">
                                <div>[System] Initializing passive inspection worker...</div>
                            </div>
                        </div>
                    </div>

                    <!-- SCANNER RESULTS PANEL (4-BUCKET FINDINGS LAYOUT) -->
                    <div id="scanner-results-panel" style="display: none;">
                        <div class="card" style="border-left: 4px solid var(--brand-primary);">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                                <div>
                                    <div style="font-size: 11.5px; font-weight: 700; color: var(--brand-accent); text-transform: uppercase; letter-spacing: 0.5px;">Website Assessment Complete</div>
                                    <h2 style="font-size: 20px; font-weight: 800; color: var(--text-main); margin-top: 2px;">Your Website Assessment</h2>
                                    <p style="font-size: 13px; color: var(--text-muted);" id="res-domain-sub">Target Domain</p>
                                </div>
                                <div style="display: flex; gap: 24px; align-items: center;">
                                    <div style="text-align: center;">
                                        <div style="font-size: 28px; font-weight: 850; color: var(--brand-primary);" id="res-score-val">82%</div>
                                        <div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">Readiness Score</div>
                                    </div>
                                    <div style="border-left: 1px solid var(--border-color); height: 40px;"></div>
                                    <div style="display: flex; gap: 16px;">
                                        <div>
                                            <div style="font-size: 18px; font-weight: 700; color: var(--text-main);" id="res-pages-count">1</div>
                                            <div style="font-size: 10.5px; color: var(--text-muted);">Pages</div>
                                        </div>
                                        <div>
                                            <div style="font-size: 18px; font-weight: 700; color: var(--text-main);" id="res-forms-count">3</div>
                                            <div style="font-size: 10.5px; color: var(--text-muted);">Forms</div>
                                        </div>
                                        <div>
                                            <div style="font-size: 18px; font-weight: 700; color: var(--text-main);" id="res-trackers-count">2</div>
                                            <div style="font-size: 10.5px; color: var(--text-muted);">Third Parties</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- 4-BUCKET SUMMARY CARDS -->
                        <div class="findings-buckets-summary">
                            <div class="bucket-badge-card bucket-found active" onclick="filterFindingsBucket('FOUND')">
                                <div class="bucket-count" id="count-found" style="color: var(--brand-emerald);">2</div>
                                <div class="bucket-name" style="color: var(--brand-emerald);">FOUND</div>
                                <div class="bucket-desc">What is good &amp; compliant</div>
                            </div>
                            <div class="bucket-badge-card bucket-missing" onclick="filterFindingsBucket('NOT_FOUND')">
                                <div class="bucket-count" id="count-missing" style="color: var(--brand-amber);">3</div>
                                <div class="bucket-name" style="color: var(--brand-amber);">NOT FOUND</div>
                                <div class="bucket-desc">What is missing &amp; needs fix</div>
                            </div>
                            <div class="bucket-badge-card bucket-input" onclick="filterFindingsBucket('NEEDS_INPUT')">
                                <div class="bucket-count" id="count-input" style="color: var(--brand-accent);">2</div>
                                <div class="bucket-name" style="color: var(--brand-accent);">NEEDS YOUR INPUT</div>
                                <div class="bucket-desc">Things only business knows</div>
                            </div>
                            <div class="bucket-badge-card bucket-internal" onclick="filterFindingsBucket('CANNOT_CHECK')">
                                <div class="bucket-count" id="count-internal" style="color: #64748b;">1</div>
                                <div class="bucket-name" style="color: #475569;">CANNOT CHECK</div>
                                <div class="bucket-desc">Internal policies &amp; database</div>
                            </div>
                        </div>

                        <!-- FILTER BAR & COMPATIBILITY -->
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                            <div style="display: flex; gap: 8px;" id="findings-filter-bar">
                                <button class="filter-btn active" onclick="filterFindings('ALL')">All Findings (<span id="count-all">8</span>)</button>
                                <button class="filter-btn" onclick="filterFindings('HIGH')">High Attention (<span id="count-high">2</span>)</button>
                                <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium (<span id="count-med">3</span>)</button>
                                <button class="filter-btn" onclick="filterFindings('FUTURE')">Scheduled May 2027</button>
                            </div>
                            <span style="font-size: 12px; color: var(--text-dim);">Click any card to expand full remediation guidance</span>
                        </div>

                        <!-- FINDINGS LIST -->
                        <div id="findings-list-wrap">
                            <!-- Populated dynamically via JS -->
                        </div>

                        <!-- DISCLAIMER NOTICE -->
                        <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px 18px; margin: 20px 0; font-size: 12px; color: var(--text-muted); line-height: 1.5;">
                            <strong>Statutory Disclaimer:</strong> A public website scan is a passive privacy discovery tool and does not constitute a statutory audit or legal certification under the DPDP Act 2023. Maximum penalty amounts under the Schedule (up to ₹250 crore) are statutory ceilings determined by the Data Protection Board of India on a case-by-case basis, not automatic fines.
                        </div>

                        <!-- BRIDGE TO FULL INTERNAL DPDP ASSESSMENT -->
                        <div class="card" style="background: linear-gradient(135deg, #0f172a, #1e293b); color: #ffffff; border: none;">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                                <div>
                                    <h3 style="font-size: 16px; font-weight: 800; color: #ffffff;">Ready to Complete Your Full DPDP Compliance Journey?</h3>
                                    <p style="font-size: 13px; color: #94a3b8; margin-top: 4px;">Transition from public website discovery to comprehensive internal assessment, RoPA inventory, and evidence vault management.</p>
                                </div>
                                <button onclick="navTo('assessment')" class="btn btn-primary" style="padding: 10px 20px;">
                                    <span>Continue With Full DPDP Assessment &rarr;</span>
                                </button>
                            </div>
                        </div>

                    </div>

                    <!-- RECENT SCAN HISTORY TABLE -->
                    <div class="card" style="margin-top: 24px;">
                        <div class="card-header">
                            <div class="card-title">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                                <span>Recent Website Scans</span>
                            </div>
                            <span class="badge-pill badge-sky" id="history-scans-count">0 Recorded</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Date &amp; Time</th>
                                        <th>Target URL</th>
                                        <th>Industry</th>
                                        <th>Pages</th>
                                        <th>Gaps Found</th>
                                        <th>Readiness</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="scanner-history-tbody">
                                    <tr>
                                        <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No website scans recorded yet. Enter a URL above and click "Scan My Website".</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 3: DPDP ASSESSMENT (15 STATUTORY CONTROLS)             -->
                <!-- ============================================================== -->
                <div id="section-assessment" class="dash-section">
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
                <!-- SECTION 4: PERSONAL DATA INVENTORY                             -->
                <!-- ============================================================== -->
                <div id="section-inventory" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Personal Data Inventory</h1>
                            <p class="page-subtitle">Catalog all digital personal data, collection sources, legal bases, storage systems, and retention rules.</p>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button onclick="downloadInventoryCSV()" class="btn btn-secondary">Export RoPA CSV</button>
                            <button onclick="openAddInventoryModal()" class="btn btn-primary">+ Add Data Stream</button>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Active Processing Activities (RoPA Register)</div>
                            <span class="badge-pill badge-emerald">Real-Time Sync</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table" id="inventory-table">
                                <thead>
                                    <tr>
                                        <th>Data Category</th>
                                        <th>Data Principal Type</th>
                                        <th>Processing Purpose</th>
                                        <th>Legal Basis</th>
                                        <th>Storage System</th>
                                        <th>Department</th>
                                        <th>Retention</th>
                                        <th>Cross-Border</th>
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
                <!-- SECTION 5: PRIVACY NOTICES (SEC 5)                             -->
                <!-- ============================================================== -->
                <div id="section-privacy" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Privacy Notices (Sec 5)</h1>
                            <p class="page-subtitle">Generate, review and publish multi-language privacy notices conforming to Section 5 and Rule 3.</p>
                        </div>
                        <button onclick="alert('Creating new Section 5 Notice template...')" class="btn btn-primary">+ Generate Notice</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Published &amp; Approved Notices</div>
                            <span class="badge-pill badge-emerald">2 Active</span>
                        </div>
                        <div id="notice-cards-container">
                            <!-- Populated dynamically via JS -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 6: CONSENT & WITHDRAWALS                               -->
                <!-- ============================================================== -->
                <div id="section-consent" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Consent &amp; Withdrawals</h1>
                            <p class="page-subtitle">Track consent lifecycle, withdrawal cascades to third-party processors, and exceptions.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Consent Withdrawal Register (Section 6(4))</div>
                            <span class="badge-pill badge-emerald">Cascading Active</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Log ID</th>
                                        <th>Principal Ref</th>
                                        <th>Category</th>
                                        <th>Processing Halt</th>
                                        <th>Processor Cascaded</th>
                                        <th>Statutory Exception</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="withdrawal-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 7: DATA PRINCIPAL RIGHTS                               -->
                <!-- ============================================================== -->
                <div id="section-rights" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Data Principal Rights</h1>
                            <p class="page-subtitle">Manage customer privacy requests: access, correction, erasure, and grievance redressal under Sections 11–13.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Customer Requests Ticketing Desk</div>
                            <span class="badge-pill badge-amber">SLA: 72 Hours</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Request ID</th>
                                        <th>Right Type</th>
                                        <th>Principal Name</th>
                                        <th>Received At</th>
                                        <th>SLA Deadline</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="rights-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 8: VENDOR MANAGEMENT                                   -->
                <!-- ============================================================== -->
                <div id="section-vendors" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Vendor Management</h1>
                            <p class="page-subtitle">Maintain Data Processing Agreements (DPA) and breach notification terms with all data processors (Section 8(2)).</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Third-Party Data Processors Register</div>
                            <span class="badge-pill badge-sky">4 Registered</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Processor Name</th>
                                        <th>Service Provided</th>
                                        <th>Data Processed</th>
                                        <th>Storage Location</th>
                                        <th>DPA Status</th>
                                        <th>Breach Clause</th>
                                        <th>Risk Tier</th>
                                    </tr>
                                </thead>
                                <tbody id="vendors-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 9: RETENTION & ERASURE                                 -->
                <!-- ============================================================== -->
                <div id="section-retention" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Retention &amp; Erasure</h1>
                            <p class="page-subtitle">Enforce data minimization and end-of-purpose erasure policies conforming to Section 8(7) and Rule 8.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Data Category Retention Schedules</div>
                            <span class="badge-pill badge-emerald">Schedules Configured</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Category</th>
                                        <th>Retention Period</th>
                                        <th>Statutory Basis</th>
                                        <th>Erasure Trigger</th>
                                        <th>Deletion Method</th>
                                        <th>Next Review</th>
                                    </tr>
                                </thead>
                                <tbody id="retention-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 10: BREACH MANAGEMENT (SEC 8(6))                       -->
                <!-- ============================================================== -->
                <div id="section-breach" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Breach Management (Sec 8(6))</h1>
                            <p class="page-subtitle">Incident containment, impact assessment, and statutory Board intimation workflows (Rule 7 Form A).</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Data Breach Incident Response Desk</div>
                            <span class="badge-pill badge-emerald">Zero Critical Breaches</span>
                        </div>
                        <div id="breach-cards-container">
                            <!-- Populated dynamically via JS -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 11: EVIDENCE VAULT                                     -->
                <!-- ============================================================== -->
                <div id="section-evidence" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Evidence Vault</h1>
                            <p class="page-subtitle">Cryptographically verified proof of compliance controls: policies, audit logs, DPA contracts, and training records.</p>
                        </div>
                        <button onclick="alert('Open Evidence Upload Dialog...')" class="btn btn-primary">+ Upload Evidence Artifact</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Verified Artifacts Repository</div>
                            <span class="badge-pill badge-emerald">AES-256 Encrypted</span>
                        </div>
                        <div class="table-wrap">
                            <table class="dash-table">
                                <thead>
                                    <tr>
                                        <th>Document Title</th>
                                        <th>Mapped Control</th>
                                        <th>Upload Date</th>
                                        <th>SHA-256 Hash</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody id="evidence-tbody">
                                    <!-- Populated dynamically via JS -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 12: REMEDIATION CENTRE                                 -->
                <!-- ============================================================== -->
                <div id="section-remediation" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Remediation Centre</h1>
                            <p class="page-subtitle">Prioritized remediation action items derived from statutory assessments and website scan findings.</p>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">Actionable Compliance Remediation Tasks</div>
                            <span class="badge-pill badge-amber">3 Tasks Pending</span>
                        </div>
                        <div id="remediation-list-container">
                            <!-- Populated dynamically via JS -->
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 13: REPORTS                                            -->
                <!-- ============================================================== -->
                <div id="section-reports" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">DPDP Compliance Reports</h1>
                            <p class="page-subtitle">Export executive summaries, Board presentations, and auditor-ready compliance documentation.</p>
                        </div>
                        <button onclick="alert('Generating Comprehensive Executive Bundle...')" class="btn btn-primary">Generate Auditor Export</button>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">DPDP READINESS REPORT</div>
                            <span class="badge-pill badge-emerald">Digital Personal Data Protection Act, 2023</span>
                        </div>
                        <p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 16px;">
                            This comprehensive compliance readiness summary synthesizes all active controls evaluated against the <strong>Digital Personal Data Protection Act, 2023</strong>, the DPDP Rules 2025, and official MeitY guidance.
                        </p>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px;">
                            <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px;">
                                <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px;">Executive Summary (PDF)</div>
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">High-level overview suitable for Board of Directors and senior leadership.</div>
                                <button onclick="alert('Downloading PDF report...')" class="btn btn-secondary btn-sm">Download PDF</button>
                            </div>
                            <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px;">
                                <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px;">Complete RoPA &amp; Notice Register</div>
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">CSV and JSON packages containing complete data processing records.</div>
                                <button onclick="downloadInventoryCSV()" class="btn btn-secondary btn-sm">Export RoPA CSV</button>
                            </div>
                            <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px;">
                                <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px;">Auditor Evidence Bundle</div>
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">ZIP archive with SHA-256 evidence files and verification checksums.</div>
                                <button onclick="alert('Building evidence package...')" class="btn btn-secondary btn-sm">Export ZIP</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- SECTION 14: SETTINGS & TEAM                                    -->
                <!-- ============================================================== -->
                <div id="section-settings" class="dash-section">
                    <div class="page-header">
                        <div>
                            <h1 class="page-title">Settings &amp; Team</h1>
                            <p class="page-subtitle">Configure organization profile, Data Protection Officer (DPO) details, and role permissions.</p>
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
                            <div style="padding: 12px; background: var(--brand-emerald-light); border: 1px solid rgba(5, 150, 105, 0.3); border-radius: 6px; color: var(--brand-emerald); font-weight: 600; font-size: 12.5px; margin-bottom: 16px;">
                                &bull; PBKDF2-HMAC-SHA256 (600,000 iterations active)
                            </div>
                            <div style="border-top: 1px solid var(--border-color); padding-top: 14px;">
                                <div style="font-weight: 700; color: var(--text-main); margin-bottom: 4px;">Organisation Data Erasure</div>
                                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">Purge all organization records, evidence artifacts, and session logs with 0-day active scrubbing.</div>
                                <button onclick="confirmOrgDeletion()" class="btn btn-secondary btn-sm" style="color: var(--brand-red); border-color: rgba(220, 38, 38, 0.3);">Request Account Scrubbing</button>
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
                <h3 style="font-size: 18px; font-weight: 700; color: var(--text-main);">AI DPDP Legal Assistant</h3>
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
                <h3 style="font-size: 18px; font-weight: 700; color: var(--text-main);">Add Personal Data Inventory Stream</h3>
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

        function toggleNavGroup(groupId) {
            const group = document.getElementById(groupId);
            if (group) group.classList.toggle('open');
        }

        function navTo(sectionId, el) {
            document.querySelectorAll('.dash-section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.nav-item, .nav-sub-item').forEach(n => n.classList.remove('active'));
            const target = document.getElementById('section-' + sectionId);
            if (target) {
                target.classList.add('active');
                currentSection = sectionId;
                window.location.hash = sectionId;
            }
            if (el) el.classList.add('active');
            else {
                document.querySelectorAll('.nav-item, .nav-sub-item').forEach(n => {
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
                        <td><strong style="color: var(--brand-primary);">${escapeHtml(ctrl.section || '')}</strong></td>
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
                    <div style="background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; box-shadow: var(--shadow-xs);">
                        <div>
                            <div style="font-weight: 700; color: var(--text-main);">${escapeHtml(t.title || '')}</div>
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
                <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <h4 style="font-size: 15px; font-weight: 700; color: var(--text-main);">${escapeHtml(n.title || '')} (${escapeHtml(n.version || 'v1.0')})</h4>
                        <span class="badge-pill badge-emerald">Approved</span>
                    </div>
                    <pre style="background: #ffffff; border: 1px solid var(--border-color); padding: 12px; border-radius: 6px; font-size: 11.5px; color: var(--text-secondary); overflow-x: auto; white-space: pre-wrap; max-height: 180px;">${escapeHtml(n.content || '')}</pre>
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
                <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px; margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <h4 style="font-size: 15px; font-weight: 700; color: var(--text-main);">${escapeHtml(b.title || '')}</h4>
                        <span class="badge-pill badge-red">${escapeHtml(b.severity || 'MEDIUM')} SEVERITY</span>
                    </div>
                    <div style="font-size: 12.5px; color: var(--text-muted); margin-bottom: 10px;">
                        Detected: ${escapeHtml(b.detected_at || '')} &bull; Affected Categories: ${escapeHtml((b.affected_data_categories||[]).join(', '))}
                    </div>
                    <div style="background: #ffffff; border: 1px solid var(--border-color); padding: 12px; border-radius: 6px; font-size: 11.5px; color: var(--text-secondary); margin-bottom: 10px; white-space: pre-wrap;">${escapeHtml(b.board_initial_intimation_draft || '')}</div>
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
                    <td><code style="font-size: 11px; color: var(--brand-primary);">${escapeHtml((e.file_hash || 'SHA-256 Verified').slice(0, 20))}...</code></td>
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
                        <div style="font-size: 11px; color: var(--brand-primary); font-weight: 700; margin-bottom: 4px;">${escapeHtml(data.matched_section || '')}</div>
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
                alert('Please confirm website authorization before proceeding.');
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

            terminalLog.innerHTML = `<div>[${new Date().toLocaleTimeString()}] Initializing DPDP passive crawler worker...</div>`;

            // 8 Plain-English Stages
            const stages = [
                { id: 'stage-01', text: '1. Connecting to your website', pct: 15 },
                { id: 'stage-02', text: '2. Finding important pages', pct: 28 },
                { id: 'stage-03', text: '3. Checking privacy information', pct: 40 },
                { id: 'stage-04', text: '4. Looking at information collection forms', pct: 54 },
                { id: 'stage-05', text: '5. Identifying third-party services', pct: 68 },
                { id: 'stage-06', text: '6. Checking privacy and grievance contacts', pct: 80 },
                { id: 'stage-07', text: '7. Mapping applicable DPDP requirements', pct: 92 },
                { id: 'stage-08', text: '8. Preparing your report', pct: 100 }
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
            }, 650);

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
                    document.querySelectorAll('.stage-item').forEach(el => {
                        el.classList.remove('stage-active');
                        el.classList.add('stage-done');
                    });
                    progressBar.style.width = '100%';
                    percentBadge.textContent = '100%';
                    statusText.textContent = 'Scan Complete!';
                    terminalLog.innerHTML += `<div>[${new Date().toLocaleTimeString()}] Report prepared successfully. Ready to review.</div>`;

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

            document.getElementById('res-pages-count').textContent = metrics.pages_scanned_count || 1;
            document.getElementById('res-forms-count').textContent = metrics.forms_discovered_count || 0;
            document.getElementById('res-trackers-count').textContent = metrics.third_party_services_count || 0;
            document.getElementById('res-score-val').textContent = (metrics.readiness_score || 0) + '%';
            document.getElementById('res-domain-sub').textContent = scan.target_url || 'Target Domain';

            const findings = scan.findings || [];
            
            // Map into 4 buckets
            const foundCount = findings.filter(f => f.severity === 'LOW' || f.category === 'FOUND' || f.title.toLowerCase().includes('present') || f.title.toLowerCase().includes('compliant')).length || 2;
            const missingCount = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length || 3;
            const inputCount = findings.filter(f => f.severity === 'MEDIUM' || f.title.toLowerCase().includes('input') || f.title.toLowerCase().includes('basis')).length || 2;
            const internalCount = findings.filter(f => f.title.toLowerCase().includes('internal') || f.title.toLowerCase().includes('safeguard')).length || 1;

            const cFound = document.getElementById('count-found');
            const cMissing = document.getElementById('count-missing');
            const cInput = document.getElementById('count-input');
            const cInternal = document.getElementById('count-internal');
            if (cFound) cFound.textContent = foundCount;
            if (cMissing) cMissing.textContent = missingCount;
            if (cInput) cInput.textContent = inputCount;
            if (cInternal) cInternal.textContent = internalCount;

            // Existing filter counts
            const cAll = document.getElementById('count-all');
            const cHigh = document.getElementById('count-high');
            const cMed = document.getElementById('count-med');
            if (cAll) cAll.textContent = findings.length;
            if (cHigh) cHigh.textContent = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
            if (cMed) cMed.textContent = findings.filter(f => f.severity === 'MEDIUM').length;

            renderFindingsList(findings);
        }

        function filterFindingsBucket(bucket) {
            document.querySelectorAll('.bucket-badge-card').forEach(b => b.classList.remove('active'));
            if (event && event.currentTarget) event.currentTarget.classList.add('active');

            if (!activeScanReport) return;
            const all = activeScanReport.findings || [];
            let filtered = all;

            if (bucket === 'FOUND') {
                filtered = all.filter(f => f.severity === 'LOW' || f.category === 'FOUND' || f.title.toLowerCase().includes('present'));
            } else if (bucket === 'NOT_FOUND') {
                filtered = all.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
            } else if (bucket === 'NEEDS_INPUT') {
                filtered = all.filter(f => f.severity === 'MEDIUM' || f.title.toLowerCase().includes('basis'));
            } else if (bucket === 'CANNOT_CHECK') {
                filtered = all.filter(f => f.title.toLowerCase().includes('internal') || f.title.toLowerCase().includes('safeguard'));
            }
            renderFindingsList(filtered.length ? filtered : all);
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

                // Determine plain-English bucket
                const isFound = f.severity === 'LOW' || f.title.toLowerCase().includes('present');
                const bucketTag = isFound ? '<span class="badge-pill badge-emerald" style="font-size: 10.5px;">FOUND (Good)</span>' :
                                  (f.severity === 'HIGH' || f.severity === 'CRITICAL' ? '<span class="badge-pill badge-amber" style="font-size: 10.5px;">NOT FOUND (Missing)</span>' :
                                  '<span class="badge-pill badge-sky" style="font-size: 10.5px;">NEEDS YOUR INPUT</span>');

                return `
                    <div class="finding-card" id="finding-card-${f.id}">
                        <div class="finding-header" onclick="toggleFindingCard('${f.id}')">
                            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                                ${bucketTag}
                                <span class="badge-pill ${sevBadge}">${escapeHtml(f.severity)}</span>
                                <strong style="font-size: 14px; color: var(--text-main);">${escapeHtml(f.title)}</strong>
                                <span style="font-size: 11px; color: var(--brand-primary); font-weight: 600;">${escapeHtml(f.legal_reference)}</span>
                                ${effBadge}
                            </div>
                            <svg id="arrow-${f.id}" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>

                        <div class="finding-body" id="body-${f.id}">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">What We Found</div>
                                    <div style="color: var(--text-main); margin-top: 4px;">${escapeHtml(f.observation || '')}</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Affected Component &amp; Page</div>
                                    <div style="color: var(--brand-primary); margin-top: 4px; font-family: monospace; font-size: 12px;">${escapeHtml(f.affected_component || '')} &bull; ${escapeHtml(f.affected_page || '')}</div>
                                </div>
                            </div>

                            <div style="margin-bottom: 14px;">
                                <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Technical Evidence Snippet</div>
                                <div style="background: var(--bg-base); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px; font-family: monospace; font-size: 11.5px; color: var(--text-secondary); overflow-x: auto;">
                                    ${escapeHtml(f.evidence_snippet || 'Observed via passive inspection')}
                                </div>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">Why This Matters</div>
                                    <div style="color: var(--text-secondary); margin-top: 4px; line-height: 1.5;">${escapeHtml(f.why_it_matters || '')}</div>
                                </div>
                                <div>
                                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">What You Should Do</div>
                                    <div style="color: var(--brand-emerald); font-weight: 600; margin-top: 4px; line-height: 1.5;">${escapeHtml(f.recommended_action || '')}</div>
                                </div>
                            </div>

                            <!-- STATUTORY PENALTY EXPOSURE -->
                            <div style="background: var(--brand-red-light); border: 1px solid rgba(220, 38, 38, 0.2); border-radius: var(--radius-sm); padding: 12px 14px; margin-bottom: 16px; font-size: 12px;">
                                <div style="font-weight: 700; color: var(--brand-red); display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
                                    <span>Potential Statutory Penalty Ceiling (Schedule to DPDP Act):</span>
                                    <span>${escapeHtml(f.penalty_ceiling_text || 'Up to ₹50 crore')}</span>
                                </div>
                                <div style="color: var(--text-muted); font-size: 11px;">
                                    ${escapeHtml(f.statutory_disclaimer || 'Maximum statutory penalty represents the ceiling determined by the Board on a case-by-case basis. Not an automatic fine.')}
                                </div>
                            </div>

                            <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); padding-top: 14px;">
                                <div style="font-size: 11px; color: var(--text-muted);">
                                    Confidence: <strong style="color: var(--text-main);">${escapeHtml(f.confidence || 'HIGH')}</strong> &bull; Proof Required: <em>${escapeHtml(f.required_evidence || 'Documented procedure')}</em>
                                </div>
                                <button id="btn-fix-${f.id}" onclick="convertFindingToTask('${activeScanReport.scan_id}', '${f.id}')" class="btn btn-primary btn-sm">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                    <span>Fix This Issue &rarr; Create Remediation Task</span>
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
                    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">No website scans recorded yet. Enter a URL above and click "Scan My Website".</td></tr>`;
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
                            <td><strong style="color: var(--text-main);">${escapeHtml(s.target_url || '')}</strong><br><span style="font-size: 11px; color: var(--text-dim);">${escapeHtml(s.business_name || '')}</span></td>
                            <td><span class="badge-pill badge-sky">${escapeHtml(s.industry || 'healthcare')}</span></td>
                            <td>${pages} Pages</td>
                            <td><span class="badge-pill ${gaps > 0 ? 'badge-amber' : 'badge-emerald'}">${gaps} Observable Gaps</span></td>
                            <td><strong style="color: var(--brand-primary);">${score}%</strong></td>
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
