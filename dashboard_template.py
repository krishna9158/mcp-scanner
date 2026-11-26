"""
TrustAudit — Final Public Launch Customer Workspace (Parts 2-18)
Plain-language, security-hardened, fully interactive DPDP Compliance & Data Operations Dashboard.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrustAudit Workspace — DPDP Readiness &amp; Data Operations</title>
<style>
  :root {
    --bg: #F8FAFC;
    --surface: #FFFFFF;
    --surface-2: #F1F5F9;
    --ink: #0F172A;
    --ink-2: #334155;
    --muted: #64748B;
    --border: #E2E8F0;
    --border-strong: #CBD5E1;
    --accent: #2563EB;
    --accent-hover: #1D4ED8;
    --accent-soft: #EFF6FF;
    --emerald: #059669;
    --emerald-soft: #ECFDF5;
    --amber: #D97706;
    --amber-soft: #FFFBEB;
    --rose: #E11D48;
    --rose-soft: #FFF1F2;
    --sidebar-w: 272px;
    --radius: 12px;
    --shadow: 0 1px 3px rgba(15,23,42,0.06), 0 4px 12px rgba(15,23,42,0.04);
  }
  [data-theme="dark"] {
    --bg: #0B1120;
    --surface: #111827;
    --surface-2: #1E293B;
    --ink: #F8FAFC;
    --ink-2: #CBD5E1;
    --muted: #94A3B8;
    --border: #1F2937;
    --border-strong: #334155;
    --accent: #3B82F6;
    --accent-hover: #2563EB;
    --accent-soft: rgba(59, 130, 246, 0.14);
    --emerald: #10B981;
    --emerald-soft: rgba(16, 185, 129, 0.14);
    --amber: #F59E0B;
    --amber-soft: rgba(245, 158, 11, 0.14);
    --rose: #FB7185;
    --rose-soft: rgba(244, 63, 94, 0.14);
    --shadow: 0 2px 8px rgba(0,0,0,0.35);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--ink); line-height: 1.55; -webkit-font-smoothing: antialiased;
  }
  @media (prefers-reduced-motion: reduce) {
    * { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }
  }

  /* AUTH GATE OVERLAY */
  .auth-screen {
    min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px;
    background: radial-gradient(circle at 80% 15%, rgba(37,99,235,0.08), transparent 45%), var(--bg);
  }
  .auth-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
    box-shadow: var(--shadow); width: 100%; max-width: 460px; padding: 30px;
  }
  .tab-pills { display: flex; gap: 6px; background: var(--surface-2); padding: 4px; border-radius: 10px; margin-bottom: 18px; }
  .tab-pill {
    flex: 1; padding: 8px 12px; border: none; border-radius: 7px; font-size: 13.5px; font-weight: 600;
    cursor: pointer; background: transparent; color: var(--muted);
  }
  .tab-pill.active { background: var(--surface); color: var(--ink); box-shadow: 0 1px 2px rgba(0,0,0,0.08); }

  /* APP SHELL */
  .app-shell { display: flex; min-height: 100vh; }
  .sidebar {
    width: var(--sidebar-w); background: var(--surface); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; position: fixed; top: 0; bottom: 0; left: 0; z-index: 40;
    overflow-y: auto; transition: transform 0.2s ease;
  }
  .sidebar-head {
    padding: 18px 18px 14px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .brand-row { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 17px; color: var(--ink); text-decoration: none; }
  .brand-icon {
    width: 30px; height: 30px; border-radius: 8px; background: #0F172A; color: #fff;
    display: flex; align-items: center; justify-content: center;
  }
  .nav-group { padding: 10px 12px 4px; }
  .nav-group-btn {
    width: 100%; display: flex; align-items: center; justify-content: space-between;
    background: none; border: none; color: var(--muted); font-size: 11px; font-weight: 800;
    letter-spacing: 0.07em; text-transform: uppercase; padding: 6px 8px; cursor: pointer;
  }
  .nav-items { display: flex; flex-direction: column; gap: 2px; margin-top: 2px; }
  .nav-items.collapsed { display: none; }
  .nav-item {
    display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
    padding: 9px 10px; border-radius: 8px; border: none; background: none;
    color: var(--ink-2); font-size: 13.5px; font-weight: 500; cursor: pointer;
  }
  .nav-item:hover { background: var(--surface-2); color: var(--ink); }
  .nav-item.active { background: var(--accent-soft); color: var(--accent); font-weight: 700; }

  .main-wrap { margin-left: var(--sidebar-w); flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .topbar {
    height: 62px; background: var(--surface); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; padding: 0 24px;
    position: sticky; top: 0; z-index: 30; gap: 12px;
  }
  .content { padding: 26px 28px 60px; max-width: 1240px; width: 100%; margin: 0 auto; }

  .demo-banner {
    background: var(--amber-soft); border: 1px solid #FDE68A; color: #92400E;
    padding: 10px 16px; border-radius: 10px; font-size: 13px; font-weight: 700;
    margin-bottom: 18px; display: flex; align-items: center; justify-content: space-between; gap: 12px;
  }

  /* PLAIN ENGLISH INTRO HEADER */
  .plain-header {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 20px 22px; margin-bottom: 20px; box-shadow: var(--shadow);
  }
  .plain-header h1 { font-size: 22px; font-weight: 800; margin-bottom: 6px; letter-spacing: -0.02em; }
  .plain-3q { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 12px; }
  .q-card { background: var(--surface-2); border-radius: 9px; padding: 10px 13px; font-size: 13px; }
  .q-card strong { display: block; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent); margin-bottom: 2px; }
  .legal-expand { margin-top: 10px; font-size: 12.5px; color: var(--muted); }
  .legal-expand summary { cursor: pointer; font-weight: 600; color: var(--ink-2); }

  /* CARDS & GRIDS */
  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 20px; box-shadow: var(--shadow); margin-bottom: 18px;
  }
  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px; }
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }

  .stat-tile { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; }
  .stat-label { font-size: 12.5px; color: var(--muted); font-weight: 600; }
  .stat-val { font-size: 26px; font-weight: 800; margin-top: 4px; color: var(--ink); }

  /* CONTROLS & FORMS */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 7px;
    padding: 9px 16px; border-radius: 8px; font-size: 13.5px; font-weight: 600;
    cursor: pointer; border: 1px solid transparent; transition: all 0.15s; text-decoration: none;
  }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-secondary { background: var(--surface); color: var(--ink); border-color: var(--border-strong); }
  .btn-secondary:hover { background: var(--surface-2); }
  .btn-danger { background: var(--rose-soft); color: var(--rose); border-color: rgba(225,29,72,0.25); }
  .btn-sm { padding: 6px 11px; font-size: 12.5px; }

  .badge {
    display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 999px;
    font-size: 11.5px; font-weight: 700;
  }
  .b-blue { background: var(--accent-soft); color: var(--accent); }
  .b-green { background: var(--emerald-soft); color: var(--emerald); }
  .b-amber { background: var(--amber-soft); color: var(--amber); }
  .b-rose { background: var(--rose-soft); color: var(--rose); }
  .b-slate { background: var(--surface-2); color: var(--ink-2); }

  label.fl { display: block; font-size: 12.5px; font-weight: 600; color: var(--ink-2); margin-bottom: 5px; }
  input.fi, select.fi, textarea.fi {
    width: 100%; padding: 9px 12px; border: 1px solid var(--border-strong); border-radius: 8px;
    background: var(--surface); color: var(--ink); font-size: 13.5px; font-family: inherit;
  }
  input.fi:focus, select.fi:focus, textarea.fi:focus { outline: none; border-color: var(--accent); }
  .fg { margin-bottom: 13px; }

  .tbl-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
  table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  th, td { text-align: left; padding: 11px 13px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { background: var(--surface-2); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
  tr:last-child td { border-bottom: none; }

  .view-section { display: none; }
  .view-section.active { display: block; }

  .empty-state {
    text-align: center; padding: 36px 20px; border: 1px dashed var(--border-strong);
    border-radius: var(--radius); color: var(--muted); background: var(--surface);
  }

  /* MODAL & TOAST */
  .modal-bg {
    position: fixed; inset: 0; background: rgba(15,23,42,0.55); z-index: 120;
    display: none; align-items: center; justify-content: center; padding: 18px;
  }
  .modal-bg.open { display: flex; }
  .modal-panel {
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    max-width: 620px; width: 100%; max-height: 90vh; overflow-y: auto; padding: 24px; box-shadow: var(--shadow);
  }
  .toast-wrap { position: fixed; right: 20px; bottom: 20px; z-index: 200; display: flex; flex-direction: column; gap: 8px; }
  .toast {
    padding: 11px 16px; border-radius: 9px; font-size: 13.5px; font-weight: 600;
    color: #fff; background: #0F172A; box-shadow: 0 8px 24px rgba(0,0,0,0.2);
  }
  .toast.ok { background: var(--emerald); }
  .toast.err { background: var(--rose); }

  .mobile-menu-trigger { display: none; }
  @media (max-width: 960px) {
    .sidebar { transform: translateX(-100%); }
    .sidebar.mobile-open { transform: translateX(0); }
    .main-wrap { margin-left: 0; }
    .mobile-menu-trigger { display: inline-flex; }
    .plain-3q, .grid-2, .grid-3, .grid-4 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<!-- AUTHENTICATION GATE -->
<div id="auth-gate" class="auth-screen" style="display:none;">
  <div class="auth-card">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
      <div class="brand-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <strong style="font-size:18px;">TrustAudit Workspace</strong>
        <div style="font-size:12px;color:var(--muted);">DPDP Readiness &amp; Data Operations for Indian Businesses</div>
      </div>
    </div>

    <div class="tab-pills">
      <button class="tab-pill active" id="auth-tab-login" onclick="switchAuthTab('login')">Sign In</button>
      <button class="tab-pill" id="auth-tab-register" onclick="switchAuthTab('register')">Create Free Account</button>
    </div>

    <form id="login-form" onsubmit="event.preventDefault(); handleLogin();">
      <div class="fg"><label class="fl">Work Email</label><input class="fi" id="login-email" type="email" required placeholder="you@company.in"/></div>
      <div class="fg"><label class="fl">Password</label><input class="fi" id="login-password" type="password" required placeholder="Minimum 8 characters"/></div>
      <div class="fg" id="login-mfa-wrap" style="display:none;"><label class="fl">6-Digit Authenticator Code (MFA)</label><input class="fi" id="login-totp" placeholder="123456"/></div>
      <div id="login-err" style="font-size:13px;color:var(--rose);margin-bottom:10px;"></div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Sign In to Workspace</button>
    </form>

    <form id="register-form" style="display:none;" onsubmit="event.preventDefault(); handleRegister();">
      <div class="fg"><label class="fl">Your Name</label><input class="fi" id="reg-name" required placeholder="Dr. Ananya Sharma"/></div>
      <div class="fg"><label class="fl">Business / Organisation Name</label><input class="fi" id="reg-org" required placeholder="Sunrise Care Clinic Pvt Ltd"/></div>
      <div class="fg"><label class="fl">Work Email</label><input class="fi" id="reg-email" type="email" required placeholder="admin@sunrisecare.in"/></div>
      <div class="fg"><label class="fl">Password (8+ characters)</label><input class="fi" id="reg-password" type="password" minlength="8" required/></div>
      <div class="fg"><label class="fl">Plan</label>
        <select class="fi" id="reg-plan">
          <option value="free">Free Community (&#8377;0/mo)</option>
          <option value="starter" selected>Starter (&#8377;999/mo)</option>
          <option value="growth">Growth (&#8377;1,999/mo)</option>
          <option value="business">Business (&#8377;2,999/mo)</option>
        </select>
      </div>
      <div id="reg-err" style="font-size:13px;color:var(--rose);margin-bottom:10px;"></div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Create Account &amp; Start 6-Step Setup</button>
    </form>

    <hr style="border:none;border-top:1px solid var(--border);margin:18px 0;">
    <button onclick="enterDemoSandbox()" class="btn btn-secondary" style="width:100%;">Explore Read-Only Demo Sandbox</button>
    <p style="font-size:12px;color:var(--muted);text-align:center;margin-top:8px;">
      Demo Sandbox shows clearly labeled sample data without creating a live business account. <a href="/" style="color:var(--accent);">Back to homepage</a>
    </p>
  </div>
</div>

<!-- MAIN WORKSPACE SHELL -->
<div id="workspace-shell" class="app-shell">
  <aside class="sidebar" id="main-sidebar" aria-label="Primary Workspace Navigation">
    <div class="sidebar-head">
      <a href="/" class="brand-row">
        <div class="brand-icon"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
        <span>TrustAudit</span>
      </a>
      <button onclick="toggleSidebar(false)" class="btn btn-secondary btn-sm mobile-menu-trigger">&times;</button>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-home')"><span>Home</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-home">
        <button class="nav-item active" data-view="overview" onclick="navigateTo('overview')">Overview</button>
        <button class="nav-item" data-view="remediation" onclick="navigateTo('remediation')">My Action Plan</button>
        <button class="nav-item" data-view="onboarding" onclick="navigateTo('onboarding')">6-Step Setup Guide</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-data')"><span>My Business Data</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-data">
        <button class="nav-item" data-view="inventory" onclick="navigateTo('inventory')">Customer Data List</button>
        <button class="nav-item" data-view="scanner" onclick="navigateTo('scanner')">Website Privacy Check</button>
        <button class="nav-item" data-view="data-flow" onclick="navigateTo('data-flow')">Where My Data Goes</button>
        <button class="nav-item" data-view="vendors" onclick="navigateTo('vendors')">Companies I Share Data With</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-privacy')"><span>Privacy Management</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-privacy">
        <button class="nav-item" data-view="notices" onclick="navigateTo('notices')">Privacy Notice</button>
        <button class="nav-item" data-view="consent" onclick="navigateTo('consent')">Consent Records</button>
        <button class="nav-item" data-view="rights" onclick="navigateTo('rights')">Customer Privacy Requests</button>
        <button class="nav-item" data-view="retention" onclick="navigateTo('retention')">Data Retention &amp; Deletion</button>
        <button class="nav-item" data-view="breaches" onclick="navigateTo('breaches')">Privacy Incident Response</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-docs')"><span>Documents &amp; Proof</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-docs">
        <button class="nav-item" data-view="documents" onclick="navigateTo('documents')">Document Centre</button>
        <button class="nav-item" data-view="evidence" onclick="navigateTo('evidence')">Evidence Vault</button>
        <button class="nav-item" data-view="reports" onclick="navigateTo('reports')">Reports &amp; ZIP Bundle</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-help')"><span>Help</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-help">
        <button class="nav-item" data-view="assistant" onclick="navigateTo('assistant')">AI DPDP Assistant</button>
        <button class="nav-item" data-view="glossary" onclick="navigateTo('glossary')">Learning Centre &amp; Glossary</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-settings')"><span>Settings</span><span>&#9662;</span></button>
      <div class="nav-items" id="grp-settings">
        <button class="nav-item" data-view="settings" onclick="navigateTo('settings')">Business Profile, Team &amp; Security</button>
      </div>
    </div>

    <div class="nav-group">
      <button class="nav-group-btn" onclick="toggleNavGroup('grp-legal')"><span>Advanced Legal Centre</span><span>&#9656;</span></button>
      <div class="nav-items collapsed" id="grp-legal">
        <button class="nav-item" data-view="assessment" onclick="navigateTo('assessment')">DPDP Requirements (Sec 3&ndash;17)</button>
        <button class="nav-item" data-view="org-assessment" onclick="navigateTo('org-assessment')">Full Deep Assessment</button>
        <button class="nav-item" data-view="penalties" onclick="navigateTo('penalties')">Penalty Schedule &amp; Sec 33</button>
        <button class="nav-item" data-view="timeline" onclick="navigateTo('timeline')">Commencement Timeline</button>
      </div>
    </div>
  </aside>

  <div class="main-wrap">
    <header class="topbar">
      <div style="display:flex;align-items:center;gap:12px;">
        <button onclick="toggleSidebar(true)" class="btn btn-secondary btn-sm mobile-menu-trigger">&#9776;</button>
        <div>
          <strong id="topbar-org-name" style="font-size:14.5px;">TrustAudit Workspace</strong>
          <span class="badge b-blue" id="topbar-plan-badge" style="margin-left:6px;">Starter</span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <button onclick="toggleTheme()" class="btn btn-secondary btn-sm" id="theme-toggle-btn">Dark Mode</button>
        <span id="topbar-user-label" style="font-size:13px;color:var(--muted);"></span>
        <button onclick="handleLogout()" class="btn btn-secondary btn-sm" id="topbar-logout-btn">Sign Out</button>
      </div>
    </header>

    <main class="content">
      <div id="demo-mode-banner" class="demo-banner" style="display:none;">
        <span>DEMO DATA &mdash; Example information for demonstration only. Changes here are not stored in a real company account.</span>
        <button onclick="showAuthGate('register')" class="btn btn-primary btn-sm">Create Real Free Account</button>
      </div>

      <!-- 1. OVERVIEW -->
      <section id="section-overview" class="view-section active">
        <div class="plain-header">
          <h1 id="home-greeting">Welcome to your privacy workspace</h1>
          <p style="color:var(--ink-2);font-size:14px;">Follow your 6-step setup checklist below, resolve real items that need attention, and keep proof organised before 13 May 2027.</p>
        </div>

        <div class="grid-2">
          <div class="card">
            <div style="display:flex;align-items:center;gap:18px;">
              <svg width="86" height="86" viewBox="0 0 100 100" aria-label="Setup progress ring">
                <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface-2)" stroke-width="10"/>
                <circle id="setup-ring-arc" cx="50" cy="50" r="42" fill="none" stroke="var(--accent)" stroke-width="10" stroke-linecap="round" stroke-dasharray="264" stroke-dashoffset="264" transform="rotate(-90 50 50)"/>
                <text id="setup-ring-text" x="50" y="55" text-anchor="middle" font-size="18" font-weight="800" fill="currentColor">0 / 6</text>
              </svg>
              <div style="flex:1;">
                <h2 style="font-size:17px;font-weight:700;margin-bottom:4px;">Your Setup Progress</h2>
                <p id="setup-progress-subtitle" style="font-size:13.5px;color:var(--muted);">Loading your workspace checklist...</p>
                <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
                  <button onclick="navigateTo('onboarding')" class="btn btn-primary btn-sm">Open 6-Step Setup</button>
                  <button id="home-next-action-btn" onclick="navigateTo('inventory')" class="btn btn-secondary btn-sm">Next Step</button>
                </div>
              </div>
            </div>
            <div id="setup-checklist-rows" style="margin-top:14px;display:grid;gap:6px;"></div>
          </div>

          <div class="card">
            <h2 style="font-size:17px;font-weight:700;margin-bottom:10px;">What Needs Attention Right Now</h2>
            <p style="font-size:13px;color:var(--muted);margin-bottom:12px;">Showing up to 3 top practical items detected in your workspace.</p>
            <div id="home-attention-list" style="display:grid;gap:10px;"></div>
          </div>
        </div>

        <div class="grid-4" style="margin-bottom:18px;">
          <div class="stat-tile"><div class="stat-label">Customer Data Records</div><div class="stat-val" id="cnt-inventory">0</div></div>
          <div class="stat-tile"><div class="stat-label">Companies Shared With</div><div class="stat-val" id="cnt-vendors">0</div></div>
          <div class="stat-tile"><div class="stat-label">Customer Requests</div><div class="stat-val" id="cnt-requests">0</div></div>
          <div class="stat-tile"><div class="stat-label">Evidence Files Ready</div><div class="stat-val" id="cnt-evidence">0</div></div>
        </div>

        <div class="card">
          <h2 style="font-size:16px;font-weight:700;margin-bottom:12px;">Quick Actions</h2>
          <div style="display:flex;flex-wrap:wrap;gap:10px;">
            <button onclick="navigateTo('scanner')" class="btn btn-secondary">Scan Website</button>
            <button onclick="navigateTo('inventory')" class="btn btn-secondary">Add Customer Data</button>
            <button onclick="navigateTo('notices')" class="btn btn-secondary">Create Privacy Notice</button>
            <button onclick="navigateTo('vendors')" class="btn btn-secondary">Add Vendor Company</button>
            <button onclick="navigateTo('evidence')" class="btn btn-secondary">Upload Evidence Proof</button>
            <button onclick="downloadReportFile('/api/dpdp/reports/pdf')" class="btn btn-primary">Download Readiness PDF</button>
          </div>
        </div>

        <div class="card">
          <h2 style="font-size:16px;font-weight:700;margin-bottom:10px;">Recent Activity</h2>
          <div id="home-recent-activity"></div>
        </div>
      </section>

      <!-- 2. 6-STEP GUIDED ONBOARDING -->
      <section id="section-onboarding" class="view-section">
        <div class="plain-header">
          <h1>6-Step Business Privacy Setup</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A quick plain-language guide so TrustAudit configures your workspace around your real business.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>No guessed company info, no unnecessary forms — only tasks relevant to your industry.</div>
            <div class="q-card"><strong>What to do next?</strong>Fill what you know and save anytime. You can skip and resume later.</div>
          </div>
        </div>
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
            <strong id="ob-step-label">Step 1 of 6 &mdash; About Your Business</strong>
            <span class="badge b-blue" id="ob-progress-pill">Saved Progress Ready</span>
          </div>
          <div id="ob-step-1" class="ob-panel">
            <div class="grid-2">
              <div class="fg"><label class="fl">Business / Clinic / Company Name</label><input class="fi" id="ob-company" placeholder="e.g., Sunrise Dental &amp; Diagnostics"/></div>
              <div class="fg"><label class="fl">Industry Sector</label>
                <select class="fi" id="ob-industry">
                  <option value="clinics">Outpatient Clinic / Hospital / Healthcare</option>
                  <option value="diagnostic_centres">Diagnostic Centre / Lab</option>
                  <option value="saas">SaaS / Software / Technology</option>
                  <option value="ecommerce">Online Store / E-Commerce</option>
                  <option value="education">School / Coaching / EdTech</option>
                  <option value="fintech">Financial / Advisory Services</option>
                  <option value="professional_services">Accounting / Law / Consulting</option>
                  <option value="general">General Indian Business</option>
                </select>
              </div>
              <div class="fg"><label class="fl">Business Size</label>
                <select class="fi" id="ob-size">
                  <option value="1-10">1&ndash;10 People</option>
                  <option value="11-50">11&ndash;50 People</option>
                  <option value="51-250">51&ndash;250 People</option>
                  <option value="250+">250+ People</option>
                </select>
              </div>
              <div class="fg"><label class="fl">Privacy / Grievance Contact Email</label><input class="fi" id="ob-email" type="email" placeholder="privacy@yourbusiness.in"/></div>
            </div>
          </div>
          <div id="ob-step-2" class="ob-panel" style="display:none;">
            <p style="font-size:13.5px;color:var(--ink-2);margin-bottom:12px;">Which details do you collect digitally (forms, billing, WhatsApp, or software)?</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:14px;">
              <label style="display:flex;gap:8px;align-items:center;"><input type="checkbox" class="ob-data-chk" value="Customer Contact Info" checked/> Names, Phone Numbers &amp; Emails</label>
              <label style="display:flex;gap:8px;align-items:center;"><input type="checkbox" class="ob-data-chk" value="Billing & Tax Invoices" checked/> Billing &amp; GST Invoices</label>
              <label style="display:flex;gap:8px;align-items:center;"><input type="checkbox" class="ob-data-chk" value="Patient Health Records"/> Patient / Clinical Health Records</label>
              <label style="display:flex;gap:8px;align-items:center;"><input type="checkbox" class="ob-data-chk" value="Children / Minor Data (<18)"/> Student or Minor Data (Under 18)</label>
              <label style="display:flex;gap:8px;align-items:center;"><input type="checkbox" class="ob-data-chk" value="Employee HR & Payroll"/> Staff Attendance &amp; Payroll</label>
            </div>
            <label style="display:flex;gap:8px;align-items:center;font-weight:600;font-size:13.5px;">
              <input type="checkbox" id="ob-apply-template" checked/> Populate starter Customer Data List suggestions for my selected industry
            </label>
          </div>
          <div id="ob-step-3" class="ob-panel" style="display:none;">
            <div class="fg"><label class="fl">Public Website URL (Optional &mdash; used only when you choose to run a check)</label><input class="fi" id="ob-website" placeholder="https://yourbusiness.in"/></div>
            <p style="font-size:13px;color:var(--muted);">A website scan only checks public pages (privacy link, forms, scripts). It cannot inspect internal databases.</p>
          </div>
          <div id="ob-step-4" class="ob-panel" style="display:none;">
            <p style="font-size:13.5px;color:var(--ink-2);margin-bottom:10px;">Select software or service companies your business shares customer details with (saved with status "Not Started"):</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;">
              <label style="display:flex;gap:8px;"><input type="checkbox" class="ob-vnd-chk" value="Razorpay / Payment Gateway"/> Payment Gateway (Razorpay / Stripe)</label>
              <label style="display:flex;gap:8px;"><input type="checkbox" class="ob-vnd-chk" value="WhatsApp / SMS Alerts Provider"/> SMS / WhatsApp Notification Tool</label>
              <label style="display:flex;gap:8px;"><input type="checkbox" class="ob-vnd-chk" value="Cloud Hosting / Database"/> Cloud Hosting (AWS / Google / Azure)</label>
              <label style="display:flex;gap:8px;"><input type="checkbox" class="ob-vnd-chk" value="Clinic / Billing Software"/> Clinic / Billing / ERP Software</label>
            </div>
          </div>
          <div id="ob-step-5" class="ob-panel" style="display:none;">
            <div class="grid-2">
              <div class="fg"><label class="fl">Do you already have a published Privacy Notice?</label>
                <select class="fi" id="ob-has-notice"><option value="no">No, help me create one</option><option value="draft">I have a rough draft</option><option value="yes">Yes, published on website</option></select>
              </div>
              <div class="fg"><label class="fl">Can staff delete old records on schedule?</label>
                <select class="fi" id="ob-has-retention"><option value="no">Not set up yet</option><option value="yes">Yes, reviewed periodically</option></select>
              </div>
            </div>
          </div>
          <div id="ob-step-6" class="ob-panel" style="display:none;">
            <h3 style="font-size:16px;font-weight:700;margin-bottom:8px;">Ready to Build Your Personalised Workspace</h3>
            <p style="font-size:13.5px;color:var(--ink-2);margin-bottom:12px;">Clicking "Finish Setup" saves your genuine answers only — no unverified scores or invented activity will be created.</p>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:18px;">
            <button onclick="prevOnboardingStep()" class="btn btn-secondary" id="ob-prev-btn">Back</button>
            <div style="display:flex;gap:8px;">
              <button onclick="saveOnboardingStep(false)" class="btn btn-secondary">Save &amp; Continue Later</button>
              <button onclick="nextOnboardingStep()" class="btn btn-primary" id="ob-next-btn">Next Step</button>
            </div>
          </div>
        </div>
      </section>

      <!-- 3. MY ACTION PLAN -->
      <section id="section-remediation" class="view-section">
        <div class="plain-header">
          <h1>My Action Plan</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A clear to-do list of privacy fixes from your onboarding and website checks.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Shows who owns each fix, its priority, and proof of completion.</div>
            <div class="q-card"><strong>What to do next?</strong>Assign a team owner and move items from Open to Resolved as you finish them.</div>
          </div>
        </div>
        <div class="card" id="remediation-list-card">Loading tasks...</div>
      </section>

      <!-- 4. CUSTOMER DATA LIST -->
      <section id="section-inventory" class="view-section">
        <div class="plain-header">
          <h1>Your Customer Data List</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A plain list of what personal details your business collects and where you store them.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Powers your Privacy Notice, Deletion Rules, and Customer Requests accurately.</div>
            <div class="q-card"><strong>What to do next?</strong>Add each type of customer record below or import/export via CSV.</div>
          </div>
          <details class="legal-expand"><summary>View legal reference (DPDP Act, 2023)</summary>Supports Section 4 (Lawful grounds: Consent under Section 6 OR Certain Legitimate Uses under Section 7) and Section 5 itemised notice accuracy.</details>
        </div>
        <div class="card">
          <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:space-between;align-items:center;margin-bottom:14px;">
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <button onclick="openInventoryModal()" class="btn btn-primary">+ Add Customer Data</button>
              <button onclick="downloadReportFile('/api/dpdp/inventory/export')" class="btn btn-secondary">Export CSV</button>
              <label class="btn btn-secondary" style="margin:0;">Import CSV <input type="file" accept=".csv" style="display:none;" onchange="importInventoryCsv(this)"/></label>
            </div>
            <input class="fi" style="max-width:240px;" id="inv-search" placeholder="Search data list..." oninput="renderInventoryTable()"/>
          </div>
          <div class="tbl-wrap"><table><thead><tr><th>Category &amp; Data Fields</th><th>Why Collected (Purpose)</th><th>Lawful Ground</th><th>Where Stored &amp; Shared</th><th>Actions</th></tr></thead><tbody id="inv-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 5. WEBSITE PRIVACY CHECK (SCANNER — KEEPS EXACT IDs FOR COMPATIBILITY) -->
      <section id="section-scanner" class="view-section">
        <div class="plain-header">
          <h1>Website Privacy Check (DPDP Website Scanner)</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Checks public website pages for a Privacy Notice link, forms, pre-ticked checkboxes, HTTPS, and scripts.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Public websites are the first thing customers and regulators see.</div>
            <div class="q-card"><strong>What to do next?</strong>Enter your website URL, confirm you own/manage it, and review the 4 honest result groups.</div>
          </div>
          <details class="legal-expand"><summary>What this scan can and cannot check</summary>External website scans inspect public HTML, headers, forms, and scripts only. They cannot inspect internal databases, vendor contracts, or private access controls.</details>
        </div>
        <div class="card">
          <div class="grid-3">
            <div class="fg"><label class="fl">Website URL</label><input class="fi" id="scan-url-input" placeholder="https://yourbusiness.in"/></div>
            <div class="fg"><label class="fl">Business Name</label><input class="fi" id="scan-biz-input" placeholder="Your Business Name"/></div>
            <div class="fg"><label class="fl">Industry</label>
              <select class="fi" id="scan-ind-input">
                <option value="healthcare">Healthcare / Clinic</option><option value="saas">SaaS / Software</option><option value="ecommerce">E-Commerce</option><option value="education">Education</option>
              </select>
            </div>
          </div>
          <label style="display:flex;gap:8px;align-items:center;font-size:13px;margin-bottom:12px;">
            <input type="checkbox" id="scan-auth-confirm" checked/> I confirm I am authorised to scan this website (non-invasive public read-only inspection).
          </label>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button id="btn-start-scan" onclick="runWebsiteScan(false)" class="btn btn-primary">Run Real Website Check</button>
            <button onclick="runWebsiteScan(true)" class="btn btn-secondary">Load Sample Example Report</button>
          </div>
          <div id="scanner-progress-panel" style="display:none;margin-top:14px;padding:12px;background:var(--accent-soft);border-radius:8px;font-size:13.5px;font-weight:600;color:var(--accent);">Checking public website safely...</div>
        </div>
        <div id="scanner-results-panel"></div>
        <div class="card">
          <h3 style="font-size:16px;font-weight:700;margin-bottom:10px;">Past Website Scans</h3>
          <div id="scanner-history-list"></div>
        </div>
      </section>

      <!-- 6. WHERE MY DATA GOES -->
      <section id="section-data-flow" class="view-section">
        <div class="plain-header">
          <h1>Where My Customer Data Goes</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A visual picture showing how customer details enter your business, where they live, and which vendors receive them.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Helps spot untracked sharing before signing contracts or preparing notices.</div>
            <div class="q-card"><strong>What to do next?</strong>Keep your Customer Data List and Vendors updated to update this live map.</div>
          </div>
        </div>
        <div class="card" id="data-flow-canvas">Loading live map...</div>
      </section>

      <!-- 7. COMPANIES I SHARE DATA WITH (VENDORS) -->
      <section id="section-vendors" class="view-section">
        <div class="plain-header">
          <h1>Companies I Share Data With</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A tracker for billing software, labs, couriers, cloud hosts, and payment gateways that handle customer data.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Under DPDP Section 8(1)&ndash;(2), your business remains responsible for vendor security and contracts.</div>
            <div class="q-card"><strong>What to do next?</strong>Add every vendor, record contract status (6 clear stages), and upload signed agreements.</div>
          </div>
        </div>
        <div class="card">
          <button onclick="openVendorModal()" class="btn btn-primary" style="margin-bottom:14px;">+ Add Company / Vendor</button>
          <div class="tbl-wrap"><table><thead><tr><th>Company &amp; Service</th><th>Data Shared &amp; Region</th><th>Contract (DPA) Status</th><th>Risk &amp; Expiry</th><th>Actions</th></tr></thead><tbody id="vnd-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 8. PRIVACY NOTICE -->
      <section id="section-notices" class="view-section">
        <div class="plain-header">
          <h1>Your Customer Privacy Notice</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>The clear explanation shown to customers before or when you ask for their details.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Required under Section 5 &amp; Rule 3 in clear language alongside Privacy Contact details.</div>
            <div class="q-card"><strong>What to do next?</strong>Generate a tailored draft from your Customer Data List, edit it, approve it, and export it.</div>
          </div>
        </div>
        <div class="card">
          <div class="grid-3">
            <div class="fg"><label class="fl">Notice Title</label><input class="fi" id="not-title" placeholder="Customer Privacy Notice"/></div>
            <div class="fg"><label class="fl">Grievance / Privacy Contact Name</label><input class="fi" id="not-officer" placeholder="Priya Nair"/></div>
            <div class="fg"><label class="fl">Grievance Email</label><input class="fi" id="not-email" placeholder="grievance@yourbusiness.in"/></div>
          </div>
          <button onclick="generateNotice()" class="btn btn-primary">Generate Notice From Data List</button>
        </div>
        <div id="notices-list"></div>
      </section>

      <!-- 9. CONSENT RECORDS -->
      <section id="section-consent" class="view-section">
        <div class="plain-header">
          <h1>Consent &amp; Permission Records</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A log of when a customer agreed to share data, what purpose they saw, and if they withdrew permission.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Note: Consent is ONLY needed when you rely on permission (Section 6) &mdash; not for Section 7 legitimate uses like medical emergencies or employment records.</div>
            <div class="q-card"><strong>What to do next?</strong>Record customer consent sources or log any opt-out / withdrawal cleanly.</div>
          </div>
        </div>
        <div class="card">
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;justify-content:space-between;">
            <div style="display:flex;gap:8px;">
              <button onclick="openConsentModal()" class="btn btn-primary">+ Log Consent Record</button>
              <button onclick="openWithdrawalModal()" class="btn btn-secondary">Log Consent Withdrawal</button>
            </div>
            <input class="fi" style="max-width:230px;" id="cst-search" placeholder="Search consent logs..." oninput="loadConsent()"/>
          </div>
          <div class="tbl-wrap"><table><thead><tr><th>Customer Ref</th><th>Data Category</th><th>Purpose &amp; Notice Version</th><th>Channel</th><th>Status</th></tr></thead><tbody id="cst-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 10. CUSTOMER PRIVACY REQUESTS -->
      <section id="section-rights" class="view-section">
        <div class="plain-header">
          <h1>Customer Privacy Requests</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>A helpdesk tracker when customers ask to view, fix, or delete their data, raise a complaint, or name a nominee.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Sections 11&ndash;14 &amp; Rule 14 give customers rights to access, correction, erasure, grievance redressal, and nomination.</div>
            <div class="q-card"><strong>What to do next?</strong>Log incoming requests, verify requester identity before sharing records, and resolve cleanly.</div>
          </div>
        </div>
        <div class="card">
          <button onclick="openRightsModal()" class="btn btn-primary" style="margin-bottom:14px;">+ Log Customer Request</button>
          <div class="tbl-wrap"><table><thead><tr><th>Requester &amp; Type</th><th>Details</th><th>Identity Verified?</th><th>Status &amp; Owner</th><th>Actions</th></tr></thead><tbody id="req-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 11. DATA RETENTION & DELETION -->
      <section id="section-retention" class="view-section">
        <div class="plain-header">
          <h1>Data Retention &amp; Deletion</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Rules defining how long you keep each type of customer record before safely deleting it.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Section 8(7) requires erasing personal data once its purpose ends, unless another Indian law (tax, clinical) mandates keeping it.</div>
            <div class="q-card"><strong>What to do next?</strong>Add schedules for your records and log deletion confirmation tasks with proof.</div>
          </div>
        </div>
        <div class="grid-2">
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><h3 style="font-size:16px;">Retention Schedules</h3><button onclick="openRetentionModal()" class="btn btn-primary btn-sm">+ Add Rule</button></div>
            <div id="ret-list"></div>
          </div>
          <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><h3 style="font-size:16px;">Deletion Execution Tasks</h3><button onclick="openErasureModal()" class="btn btn-secondary btn-sm">+ Log Deletion Task</button></div>
            <div id="era-list"></div>
          </div>
        </div>
      </section>

      <!-- 12. PRIVACY INCIDENT RESPONSE -->
      <section id="section-breaches" class="view-section">
        <div class="plain-header">
          <h1>Privacy Incident Response</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>An incident workbook to record leaks or unauthorised access, contain harm, and draft notifications.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Under Section 8(6) &amp; Rule 7, confirmed breaches require notifying the Data Protection Board and affected individuals cleanly.</div>
            <div class="q-card"><strong>What to do next?</strong>Log any suspected incident, track affected systems &amp; timeline steps, and authorise drafts before sending.</div>
          </div>
        </div>
        <div class="card">
          <button onclick="openIncidentModal()" class="btn btn-primary" style="margin-bottom:14px;">+ Log Privacy Incident</button>
          <div id="brc-list"></div>
        </div>
      </section>

      <!-- 13. DOCUMENT CENTRE -->
      <section id="section-documents" class="view-section">
        <div class="plain-header">
          <h1>Document Centre</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Ready-to-customise policy &amp; procedure drafts generated with your business details.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Saves weeks writing privacy notices, vendor registers, incident SOPs, and staff guides from blank pages.</div>
            <div class="q-card"><strong>What to do next?</strong>Generate a draft, review with your team/counsel, and download or save it to Evidence Vault.</div>
          </div>
        </div>
        <div id="doc-templates-grid" class="grid-3"></div>
        <div id="doc-preview-card" class="card" style="display:none;"></div>
      </section>

      <!-- 14. EVIDENCE VAULT -->
      <section id="section-evidence" class="view-section">
        <div class="plain-header">
          <h1>Evidence Vault</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Secure folder for storing signed contracts, notices, backup proof, and security checks.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Every upload is checked for safety (extension, 5 MB cap, magic bytes) and fingerprinted with SHA-256.</div>
            <div class="q-card"><strong>What to do next?</strong>Upload files, preview/download them anytime, update versions, and review status across 5 review states.</div>
          </div>
        </div>
        <div class="card">
          <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:space-between;margin-bottom:14px;">
            <button onclick="openEvidenceUploadModal()" class="btn btn-primary">+ Upload Evidence File</button>
            <select class="fi" style="max-width:200px;" id="evi-status-filter" onchange="loadEvidence()">
              <option value="">All Review Statuses</option>
              <option value="Uploaded">Uploaded</option>
              <option value="Pending review">Pending review</option>
              <option value="Verified">Verified</option>
              <option value="Rejected">Rejected</option>
              <option value="Expired">Expired</option>
            </select>
          </div>
          <div class="tbl-wrap"><table><thead><tr><th>Title &amp; File</th><th>Control</th><th>Review Status</th><th>Expiry &amp; SHA-256</th><th>Actions</th></tr></thead><tbody id="evi-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 15. REPORTS & BUNDLES -->
      <section id="section-reports" class="view-section">
        <div class="plain-header">
          <h1>Reports &amp; Evidence Bundles</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Real downloadable reports built straight from your organisation's live data.</div>
            <div class="q-card"><strong>Why does my business need it?</strong>Share clear readiness progress with leadership, hospital partners, enterprise buyers, or auditors.</div>
            <div class="q-card"><strong>What to do next?</strong>Download your PDF summary, CSV spreadsheets, or complete ZIP Evidence Bundle.</div>
          </div>
        </div>
        <div class="grid-3">
          <div class="card">
            <h3>Executive Readiness PDF</h3>
            <p style="font-size:13.5px;color:var(--ink-2);margin:8px 0 14px;">Real multi-page binary PDF report covering Setup Progress, Customer Data List, Vendors, Scans, and Next Steps.</p>
            <button onclick="downloadReportFile('/api/dpdp/reports/pdf')" class="btn btn-primary" style="width:100%;">Download PDF Report</button>
          </div>
          <div class="card">
            <h3>Complete ZIP Evidence Bundle</h3>
            <p style="font-size:13.5px;color:var(--ink-2);margin:8px 0 14px;">ZIP package containing your PDF summary, 4 CSV registers, Privacy Notices, SHA-256 manifest, and uploaded Evidence files.</p>
            <button onclick="downloadReportFile('/api/dpdp/reports/bundle')" class="btn btn-primary" style="width:100%;">Download Evidence ZIP</button>
          </div>
          <div class="card">
            <h3>Unified Workspace CSV Export</h3>
            <p style="font-size:13.5px;color:var(--ink-2);margin:8px 0 14px;">Download your complete data list, vendor contracts, retention rules, requests, and evidence index for Excel.</p>
            <button onclick="downloadReportFile('/api/dpdp/reports/csv?scope=full')" class="btn btn-secondary" style="width:100%;">Download Full CSV</button>
          </div>
        </div>
      </section>

      <!-- 16. AI DPDP ASSISTANT -->
      <section id="section-assistant" class="view-section">
        <div class="plain-header">
          <h1>AI DPDP Assistant</h1>
          <div class="plain-3q">
            <div class="q-card"><strong>What is this?</strong>Plain-language DPDP Q&amp;A grounded in India's DPDP Act, 2023 &amp; DPDP Rules, 2025.</div>
            <div class="q-card"><strong>Privacy Note</strong>Your Customer Data List &amp; Evidence Vault files are never sent externally. Any optional Gemini calls strip emails/phones/IDs automatically.</div>
            <div class="q-card"><strong>What to do next?</strong>Click a starter question or ask in everyday words.</div>
          </div>
        </div>
        <div class="card">
          <div style="margin-bottom:12px;">
            <strong style="font-size:13px;">Popular Starter Questions (Click to Ask):</strong>
            <div id="ai-starter-chips" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;"></div>
          </div>
          <div id="ai-chat-history" style="max-height:420px;overflow-y:auto;display:grid;gap:12px;margin-bottom:14px;"></div>
          <form onsubmit="event.preventDefault(); askAssistant();" style="display:flex;gap:10px;">
            <input class="fi" id="ai-query-input" placeholder="Ask in plain language (e.g., How long can clinics retain invoices and records?)"/>
            <button type="submit" class="btn btn-primary" id="ai-ask-btn">Ask Assistant</button>
          </form>
        </div>
      </section>

      <!-- 17. LEARNING CENTRE & GLOSSARY -->
      <section id="section-glossary" class="view-section">
        <div class="plain-header"><h1>Learning Centre &amp; Plain-English Glossary</h1></div>
        <div class="grid-2" id="glossary-grid"></div>
      </section>

      <!-- 18. SETTINGS, TEAM, SECURITY, AUDIT LOGS -->
      <section id="section-settings" class="view-section">
        <div class="plain-header"><h1>Business Profile, Team Members, Plan &amp; Security</h1></div>
        <div class="grid-2">
          <div class="card">
            <h3 style="margin-bottom:12px;">Business Details</h3>
            <div class="fg"><label class="fl">Company / Clinic Name</label><input class="fi" id="set-company"/></div>
            <div class="fg"><label class="fl">Website URL</label><input class="fi" id="set-website"/></div>
            <div class="fg"><label class="fl">Privacy / Grievance Contact Email</label><input class="fi" id="set-email"/></div>
            <div class="fg"><label class="fl">Industry</label><input class="fi" id="set-industry"/></div>
            <button onclick="saveBusinessSettings()" class="btn btn-primary">Save Business Details</button>
          </div>
          <div class="card">
            <h3 style="margin-bottom:12px;">Account Security (2FA / MFA &amp; Account Deletion)</h3>
            <div id="mfa-box" style="margin-bottom:14px;"></div>
            <hr style="border:none;border-top:1px solid var(--border);margin:14px 0;">
            <h4 style="font-size:14px;margin-bottom:6px;color:var(--rose);">Delete Organisation &amp; All Data</h4>
            <p style="font-size:12.5px;color:var(--muted);margin-bottom:10px;">Permanently removes your account, customer data list, vendors, scans, and evidence files.</p>
            <button onclick="openDeleteAccountModal()" class="btn btn-danger btn-sm">Delete Organisation Account</button>
          </div>
        </div>
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
            <h3>Team Members &amp; Role Access (Admin / Member / Viewer)</h3>
            <button onclick="openTeamModal()" class="btn btn-primary btn-sm">+ Invite Team Member</button>
          </div>
          <div class="tbl-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead><tbody id="team-tbody"></tbody></table></div>
        </div>
        <div class="card">
          <h3 style="margin-bottom:10px;">Recent Account Audit Log</h3>
          <div class="tbl-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th></tr></thead><tbody id="audit-tbody"></tbody></table></div>
        </div>
      </section>

      <!-- 19. ADVANCED LEGAL CENTRE SECTIONS -->
      <section id="section-assessment" class="view-section">
        <div class="plain-header"><h1>DPDP Act Requirements Register</h1></div>
        <div class="card" id="legal-reqs-list">Loading statutory register...</div>
      </section>
      <section id="section-org-assessment" class="view-section">
        <div class="plain-header"><h1>Deep Organisational Assessment</h1></div>
        <div class="card" id="org-ass-box">Loading...</div>
      </section>
      <section id="section-penalties" class="view-section">
        <div class="plain-header"><h1>Statutory Penalty Schedule &amp; 7 Section 33 Factors</h1></div>
        <div class="card" id="penalties-matrix-box">Loading penalty schedule...</div>
      </section>
      <section id="section-timeline" class="view-section">
        <div class="plain-header"><h1>DPDP Commencement Timeline</h1></div>
        <div class="card" id="timeline-box">Loading timeline...</div>
      </section>
    </main>
  </div>
</div>

<!-- REUSABLE MODAL CONTAINER -->
<div id="generic-modal" class="modal-bg" role="dialog" aria-modal="true">
  <div class="modal-panel">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
      <h3 id="modal-title" style="font-size:18px;font-weight:700;">Modal</h3>
      <button onclick="closeModal()" style="border:none;background:none;font-size:22px;cursor:pointer;color:var(--muted);">&times;</button>
    </div>
    <div id="modal-body"></div>
  </div>
</div>

<div class="toast-wrap" id="toast-wrap"></div>

<script>
let STATE = {
  demoMode: false,
  user: null,
  org: null,
  onboardingStep: 1,
  inventory: [],
  vendors: [],
  notices: [],
  rights: [],
  retention: [],
  erasures: [],
  incidents: [],
  evidence: [],
  scans: []
};

function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toast(msg, type = 'ok') {
  const el = document.createElement('div');
  el.className = 'toast ' + (type === 'err' ? 'err' : 'ok');
  el.textContent = msg;
  document.getElementById('toast-wrap').appendChild(el);
  setTimeout(() => el.remove(), 3800);
}

function toggleTheme() {
  const curr = document.documentElement.getAttribute('data-theme') || 'light';
  const next = curr === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('trustaudit_theme', next);
  document.getElementById('theme-toggle-btn').textContent = next === 'dark' ? 'Light Mode' : 'Dark Mode';
}

function toggleSidebar(open) {
  document.getElementById('main-sidebar').classList.toggle('mobile-open', !!open);
}

function toggleNavGroup(id) {
  document.getElementById(id).classList.toggle('collapsed');
}

function openModal(title, html) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('generic-modal').classList.add('open');
}

function closeModal() {
  document.getElementById('generic-modal').classList.remove('open');
}

function downloadReportFile(url) {
  if (STATE.demoMode) {
    toast('Create a free account to generate downloadable reports for your own business.', 'err');
    return;
  }
  window.location.href = url;
}

function switchAuthTab(tab) {
  document.getElementById('auth-tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('auth-tab-register').classList.toggle('active', tab === 'register');
  document.getElementById('login-form').style.display = tab === 'login' ? 'block' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? 'block' : 'none';
}

function showAuthGate(tab = 'login') {
  document.getElementById('workspace-shell').style.display = 'none';
  document.getElementById('auth-gate').style.display = 'flex';
  switchAuthTab(tab);
}

async function apiJson(url, opts = {}) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || data.message || ('Request failed (' + res.status + ')'));
  }
  return data;
}

async function initApp() {
  const savedTheme = localStorage.getItem('trustaudit_theme');
  if (savedTheme === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.getElementById('theme-toggle-btn').textContent = 'Light Mode';
  }
  try {
    const me = await fetch('/api/auth/me');
    if (me.status === 200) {
      const info = await me.json();
      if (info.authenticated) {
        STATE.demoMode = false;
        STATE.user = info.user;
        STATE.org = info.organization;
        document.getElementById('auth-gate').style.display = 'none';
        document.getElementById('workspace-shell').style.display = 'flex';
        document.getElementById('demo-mode-banner').style.display = 'none';
        document.getElementById('topbar-org-name').textContent = (info.organization || {}).name || 'Your Business';
        document.getElementById('topbar-plan-badge').textContent = ((info.organization || {}).plan_details || {}).name || 'Starter';
        document.getElementById('topbar-user-label').textContent = (info.user || {}).email || '';
        await loadHomeSummary();
        const hashView = (window.location.hash || '').replace('#', '');
        if (hashView && document.getElementById('section-' + hashView)) navigateTo(hashView);
        return;
      }
    }
  } catch (e) {}
  showAuthGate(window.location.hash === '#onboarding' ? 'register' : 'login');
}

async function handleLogin() {
  const errEl = document.getElementById('login-err');
  errEl.textContent = '';
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: document.getElementById('login-email').value,
        password: document.getElementById('login-password').value,
        totp_code: document.getElementById('login-totp').value || undefined
      })
    });
    const data = await res.json();
    if (data.status === 'mfa_required') {
      document.getElementById('login-mfa-wrap').style.display = 'block';
      errEl.textContent = 'Please enter your 6-digit MFA authenticator code.';
      return;
    }
    if (!res.ok) throw new Error(data.message || 'Sign in failed.');
    toast('Welcome back!');
    await initApp();
  } catch (e) {
    errEl.textContent = e.message;
  }
}

async function handleRegister() {
  const errEl = document.getElementById('reg-err');
  errEl.textContent = '';
  try {
    await apiJson('/api/auth/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        name: document.getElementById('reg-name').value,
        company_name: document.getElementById('reg-org').value,
        email: document.getElementById('reg-email').value,
        password: document.getElementById('reg-password').value,
        plan: document.getElementById('reg-plan').value
      })
    });
    toast('Account created! Let us configure your privacy setup.');
    window.location.hash = '#onboarding';
    await initApp();
  } catch (e) {
    errEl.textContent = e.message;
  }
}

async function handleLogout() {
  if (!STATE.demoMode) {
    await fetch('/api/auth/logout', {method: 'POST'});
  }
  STATE.demoMode = false;
  STATE.user = null;
  STATE.org = null;
  showAuthGate('login');
}

async function enterDemoSandbox() {
  STATE.demoMode = true;
  document.getElementById('auth-gate').style.display = 'none';
  document.getElementById('workspace-shell').style.display = 'flex';
  document.getElementById('demo-mode-banner').style.display = 'flex';
  document.getElementById('topbar-org-name').textContent = 'Sample Indian Clinic (Demo Sandbox)';
  document.getElementById('topbar-plan-badge').textContent = 'DEMO DATA';
  document.getElementById('topbar-user-label').textContent = 'Read-Only Preview';
  document.getElementById('topbar-logout-btn').textContent = 'Sign In / Create Account';
  const d = await apiJson('/api/demo/workspace');
  renderHomeData({
    user: {name: 'Visitor'},
    profile: d.profile,
    setup_progress: d.setup_progress,
    counts: d.counts,
    attention_tasks: [
      {title: 'Sample Attention Item: Review vendor agreements (Example)', why: 'Demo Mode illustrates how TrustAudit surfaces actionable items.', action_label: 'View Vendors', fix_target: 'vendors'}
    ],
    recent_activity: []
  });
}

async function navigateTo(view) {
  document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.getAttribute('data-view') === view));
  const target = document.getElementById('section-' + view);
  if (target) target.classList.add('active');
  toggleSidebar(false);

  if (view === 'overview') return loadHomeSummary();
  if (view === 'remediation') return loadRemediation();
  if (view === 'inventory') return loadInventory();
  if (view === 'scanner') return loadScannerHistory();
  if (view === 'data-flow') return loadDataFlow();
  if (view === 'vendors') return loadVendors();
  if (view === 'notices') return loadNotices();
  if (view === 'consent') return loadConsent();
  if (view === 'rights') return loadRights();
  if (view === 'retention') return loadRetention();
  if (view === 'breaches') return loadIncidents();
  if (view === 'documents') return loadDocumentTemplates();
  if (view === 'evidence') return loadEvidence();
  if (view === 'assistant') return loadAssistant();
  if (view === 'glossary') return renderGlossary();
  if (view === 'settings') return loadSettings();
  if (view === 'assessment') return loadLegalAssessment();
  if (view === 'org-assessment') return loadOrgAssessment();
  if (view === 'penalties') return loadPenalties();
  if (view === 'timeline') return loadTimeline();
}

async function loadHomeSummary() {
  if (STATE.demoMode) return;
  try {
    const d = await apiJson('/api/dpdp/home-summary');
    renderHomeData(d);
  } catch (e) { toast(e.message, 'err'); }
}

function renderHomeData(d) {
  const name = ((d.user || {}).name || 'there').split(' ')[0];
  document.getElementById('home-greeting').textContent = 'Welcome back, ' + name;
  const prog = d.setup_progress || {completed_count: 0, total_steps: 6, steps: []};
  document.getElementById('setup-ring-text').textContent = prog.completed_count + ' / ' + prog.total_steps;
  const pct = Math.min(1, Math.max(0, prog.completed_count / (prog.total_steps || 6)));
  document.getElementById('setup-ring-arc').style.strokeDashoffset = String(Math.round(264 * (1 - pct)));
  document.getElementById('setup-progress-subtitle').textContent =
    prog.completed_count === prog.total_steps
      ? 'All 6 core setup steps completed.'
      : (prog.total_steps - prog.completed_count) + ' setup step(s) left to finish organising your workspace.';

  const nextStep = prog.next_recommended_step;
  const nextBtn = document.getElementById('home-next-action-btn');
  if (nextStep) {
    nextBtn.textContent = nextStep.action_label || 'Next Step';
    nextBtn.onclick = () => navigateTo(nextStep.action_view || 'onboarding');
    nextBtn.style.display = 'inline-flex';
  } else {
    nextBtn.style.display = 'none';
  }

  document.getElementById('setup-checklist-rows').innerHTML = (prog.steps || []).map(s => (
    '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;border-radius:8px;background:var(--surface-2);font-size:13px;">' +
    '<span>' + (s.completed ? '&#10003; ' : '&#9675; ') + esc(s.title) + '</span>' +
    '<button class="btn btn-secondary btn-sm" onclick="navigateTo(\\'' + esc(s.action_view || 'onboarding') + '\\')">' + (s.completed ? 'View' : esc(s.action_label || 'Start')) + '</button>' +
    '</div>'
  )).join('');

  const tasks = d.attention_tasks || [];
  document.getElementById('home-attention-list').innerHTML = tasks.length
    ? tasks.map(t => (
        '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;display:flex;justify-content:space-between;gap:12px;align-items:center;">' +
        '<div><strong style="font-size:13.5px;display:block;">' + esc(t.title) + '</strong>' +
        '<span style="font-size:12.5px;color:var(--muted);">' + esc(t.why) + '</span></div>' +
        '<button class="btn btn-primary btn-sm" onclick="navigateTo(\\'' + esc(t.fix_target || 'remediation') + '\\')">' + esc(t.action_label || 'Fix this') + '</button>' +
        '</div>'
      )).join('')
    : '<div class="empty-state">No urgent gaps detected right now.</div>';

  const c = d.counts || {};
  document.getElementById('cnt-inventory').textContent = c.inventory_count || 0;
  document.getElementById('cnt-vendors').textContent = c.vendor_count || 0;
  document.getElementById('cnt-requests').textContent = c.request_count || 0;
  document.getElementById('cnt-evidence').textContent = c.evidence_count || 0;

  const act = d.recent_activity || [];
  document.getElementById('home-recent-activity').innerHTML = act.length
    ? act.map(a => '<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;font-size:13px;"><span><strong>' + esc(a.category) + ':</strong> ' + esc(a.title) + '</span><span style="color:var(--muted);">' + esc(String(a.timestamp).slice(0,16).replace('T',' ')) + '</span></div>').join('')
    : '<div style="font-size:13.5px;color:var(--muted);padding:10px 0;">No workspace activity recorded yet. Your actions will appear here chronologically.</div>';
}

/* ONBOARDING */
function updateOnboardingUI() {
  document.querySelectorAll('.ob-panel').forEach((p, idx) => p.style.display = (idx + 1 === STATE.onboardingStep) ? 'block' : 'none');
  document.getElementById('ob-step-label').textContent = 'Step ' + STATE.onboardingStep + ' of 6';
  document.getElementById('ob-prev-btn').disabled = STATE.onboardingStep <= 1;
  document.getElementById('ob-next-btn').textContent = STATE.onboardingStep === 6 ? 'Finish Setup' : 'Next Step';
}
function prevOnboardingStep() { if (STATE.onboardingStep > 1) { STATE.onboardingStep--; updateOnboardingUI(); } }
async function nextOnboardingStep() {
  if (STATE.onboardingStep < 6) {
    await saveOnboardingStep(false);
    STATE.onboardingStep++;
    updateOnboardingUI();
  } else {
    await saveOnboardingStep(true);
    navigateTo('overview');
  }
}
async function saveOnboardingStep(markComplete) {
  if (STATE.demoMode) { toast('Sign in to save onboarding for your business.', 'err'); return; }
  const dataCats = Array.from(document.querySelectorAll('.ob-data-chk:checked')).map(c => c.value);
  const vndList = Array.from(document.querySelectorAll('.ob-vnd-chk:checked')).map(c => c.value);
  try {
    await apiJson('/api/dpdp/onboarding', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        company_name: document.getElementById('ob-company').value,
        industry: document.getElementById('ob-industry').value,
        organisation_size: document.getElementById('ob-size').value,
        contact_email: document.getElementById('ob-email').value,
        website_url: document.getElementById('ob-website').value,
        data_categories_selected: dataCats,
        apply_industry_template: !!markComplete && document.getElementById('ob-apply-template').checked,
        selected_vendors: markComplete ? vndList : undefined,
        has_privacy_notice: document.getElementById('ob-has-notice').value,
        has_retention_plan: document.getElementById('ob-has-retention').value,
        onboarding_step: STATE.onboardingStep,
        onboarding_completed: !!markComplete
      })
    });
    toast(markComplete ? 'Onboarding complete! Workspace personalised.' : 'Setup progress saved.');
  } catch (e) { toast(e.message, 'err'); }
}

/* ACTION PLAN */
async function loadRemediation() {
  const el = document.getElementById('remediation-list-card');
  if (STATE.demoMode) { el.innerHTML = '<div class="empty-state">Create an account to manage live action tasks.</div>'; return; }
  try {
    const res = await apiJson('/api/dpdp/assessment');
    const tasks = res.remediation_tasks || [];
    el.innerHTML = tasks.length ? tasks.map(t => (
      '<div style="padding:12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:10px;">' +
      '<div><strong>' + esc(t.title) + '</strong> <span class="badge b-amber">' + esc(t.status || 'Open') + '</span><div style="font-size:12.5px;color:var(--muted);">' + esc(t.description || t.action || '') + '</div></div>' +
      '<button class="btn btn-primary btn-sm" onclick="markTaskStatus(\\'' + esc(t.id) + '\\', \\'Resolved\\')">Mark Resolved</button></div>'
    )).join('') : '<div class="empty-state">No action items yet. Run a website check or complete onboarding to populate your Action Plan.</div>';
  } catch (e) { el.innerHTML = '<div class="empty-state">' + esc(e.message) + '</div>'; }
}
async function markTaskStatus(taskId, status) {
  try {
    await apiJson('/api/dpdp/tasks/' + encodeURIComponent(taskId) + '/update', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status})
    });
    toast('Task marked ' + status);
    loadRemediation();
  } catch (e) { toast(e.message, 'err'); }
}

/* CUSTOMER DATA LIST */
async function loadInventory() {
  if (STATE.demoMode) return;
  try {
    const d = await apiJson('/api/dpdp/inventory');
    STATE.inventory = d.items || [];
    renderInventoryTable();
  } catch (e) { toast(e.message, 'err'); }
}
function renderInventoryTable() {
  const q = (document.getElementById('inv-search').value || '').toLowerCase();
  const rows = (STATE.inventory || []).filter(i => !q || JSON.stringify(i).toLowerCase().includes(q));
  document.getElementById('inv-tbody').innerHTML = rows.length ? rows.map(i => (
    '<tr><td><strong>' + esc(i.category) + '</strong><div style="font-size:12px;color:var(--muted);">' + esc((i.data_elements || []).join(', ') || i.department || '') + '</div></td>' +
    '<td>' + esc(i.purpose) + '</td><td><span class="badge b-blue">' + esc(i.legal_basis) + '</span></td>' +
    '<td>' + esc(i.storage_location) + '</td>' +
    '<td style="white-space:nowrap;"><button class="btn btn-secondary btn-sm" onclick="openInventoryModal(\\'' + esc(i.id) + '\\')">Edit</button> ' +
    '<button class="btn btn-danger btn-sm" onclick="deleteInventory(\\'' + esc(i.id) + '\\')">Delete</button></td></tr>'
  )).join('') : '<tr><td colspan="5"><div class="empty-state">No customer data records yet. Click "+ Add Customer Data" or complete Onboarding to start.</div></td></tr>';
}
function openInventoryModal(editId = null) {
  const existing = editId ? STATE.inventory.find(x => x.id === editId) : null;
  openModal(existing ? 'Edit Customer Data Record' : 'Add Customer Data Record',
    '<form onsubmit="event.preventDefault(); saveInventory(\\'' + esc(editId || '') + '\\');">' +
    '<div class="fg"><label class="fl">Category Name (e.g., Patient Intake, Customer Orders)</label><input class="fi" id="m-inv-cat" required value="' + esc(existing ? existing.category : '') + '"/></div>' +
    '<div class="fg"><label class="fl">Data Fields (comma-separated)</label><input class="fi" id="m-inv-fields" value="' + esc(existing ? (existing.data_elements || []).join(', ') : 'Name, Phone, Email') + '"/></div>' +
    '<div class="fg"><label class="fl">Why Do You Collect This? (Purpose)</label><input class="fi" id="m-inv-purpose" required value="' + esc(existing ? existing.purpose : '') + '"/></div>' +
    '<div class="fg"><label class="fl">Lawful Ground (DPDP Act)</label><select class="fi" id="m-inv-basis">' +
    '<option>Consent (Section 6)</option><option>Voluntary Service Request (Section 7(a))</option><option>Legal / Tax Compliance (Section 7(d))</option><option>Medical Emergency (Section 7(f))</option><option>Employment Purpose (Section 7(i))</option>' +
    '</select></div>' +
    '<div class="fg"><label class="fl">Where Is It Stored?</label><input class="fi" id="m-inv-loc" value="' + esc(existing ? existing.storage_location : 'Billing Software / Cloud') + '"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Record</button></form>');
}
async function saveInventory(editId) {
  const payload = {
    category: document.getElementById('m-inv-cat').value,
    data_elements: document.getElementById('m-inv-fields').value.split(',').map(s => s.trim()).filter(Boolean),
    purpose: document.getElementById('m-inv-purpose').value,
    legal_basis: document.getElementById('m-inv-basis').value,
    storage_location: document.getElementById('m-inv-loc').value
  };
  try {
    if (editId) {
      await apiJson('/api/dpdp/inventory/' + encodeURIComponent(editId), {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    } else {
      await apiJson('/api/dpdp/inventory', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    }
    closeModal(); toast('Customer data record saved.'); loadInventory();
  } catch (e) { toast(e.message, 'err'); }
}
async function deleteInventory(id) {
  try { await apiJson('/api/dpdp/inventory/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Record deleted.'); loadInventory(); } catch (e) { toast(e.message, 'err'); }
}
async function importInventoryCsv(input) {
  if (!input.files || !input.files[0]) return;
  const fd = new FormData(); fd.append('file', input.files[0]);
  try {
    const res = await fetch('/api/dpdp/inventory/import', {method: 'POST', body: fd});
    const d = await res.json();
    if (!res.ok) throw new Error(d.message || 'Import failed');
    toast('Imported ' + d.imported_count + ' row(s).');
    loadInventory();
  } catch (e) { toast(e.message, 'err'); }
}

/* WEBSITE SCANNER */
async function runWebsiteScan(isDemo = false) {
  const url = document.getElementById('scan-url-input').value.trim() || (isDemo ? 'https://arogyaclinic.example.in' : '');
  const auth = document.getElementById('scan-auth-confirm').checked;
  if (!url) { toast('Enter a website URL first.', 'err'); return; }
  if (!auth) { toast('Please tick the authorisation confirmation box first.', 'err'); return; }
  const prog = document.getElementById('scanner-progress-panel');
  prog.style.display = 'block';
  try {
    const d = await apiJson('/api/dpdp/scanner/start', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        website_url: url,
        business_name: document.getElementById('scan-biz-input').value || 'My Business',
        industry: document.getElementById('scan-ind-input').value,
        authorization_confirmed: true,
        is_demo: isDemo
      })
    });
    renderScanReport(d.scan);
    loadScannerHistory();
    toast('Website scan completed.');
  } catch (e) { toast(e.message, 'err'); }
  finally { prog.style.display = 'none'; }
}
function renderScanReport(scan) {
  if (!scan) return;
  const b = scan.scan_buckets || {};
  const found = b.what_was_found || [];
  const gaps = b.what_was_not_found || (scan.findings || []).filter(f => f.severity !== 'INFORMATIONAL');
  const needs = b.what_needs_input || [];
  const cannot = b.what_cannot_be_checked || [];
  document.getElementById('scanner-results-panel').innerHTML =
    '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
    '<div><strong>Scan Results: ' + esc(scan.target_url) + '</strong>' + (scan.is_demo ? ' <span class="badge b-amber">DEMO EXAMPLE</span>' : '') + '</div>' +
    '<span class="badge b-blue">Pages Checked: ' + ((scan.summary_metrics || {}).pages_scanned_count || 0) + '</span></div>' +
    '<div class="grid-2">' +
    '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;"><strong style="color:var(--emerald);">1. What We Found (' + found.length + ')</strong>' + (found.map(x => '<div style="font-size:13px;margin-top:6px;">&#10003; ' + esc(x.title) + '<div style="color:var(--muted);font-size:12px;">' + esc(x.detail) + '</div></div>').join('') || '<div style="font-size:13px;color:var(--muted);margin-top:6px;">No positive public privacy indicators detected.</div>') + '</div>' +
    '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;"><strong style="color:var(--rose);">2. What Was Not Found / Needs Attention (' + gaps.length + ')</strong>' + (gaps.map(x => '<div style="font-size:13px;margin-top:6px;">&#9888; ' + esc(x.title) + '<div style="color:var(--muted);font-size:12px;">' + esc(x.detail || x.observation) + '</div></div>').join('') || '<div style="font-size:13px;color:var(--muted);margin-top:6px;">No obvious public gaps flagged.</div>') + '</div>' +
    '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;"><strong style="color:var(--amber);">3. What Needs Your Input (' + needs.length + ')</strong>' + (needs.map(x => '<div style="font-size:13px;margin-top:6px;">? ' + esc(x.title) + '<div style="color:var(--muted);font-size:12px;">' + esc(x.detail) + '</div></div>').join('') || '<div style="font-size:13px;color:var(--muted);margin-top:6px;">Nothing additional pending.</div>') + '</div>' +
    '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;"><strong style="color:var(--ink-2);">4. What Cannot Be Checked Externally (' + cannot.length + ')</strong>' + (cannot.map(x => '<div style="font-size:13px;margin-top:6px;">&bull; ' + esc(x.title) + '<div style="color:var(--muted);font-size:12px;">' + esc(x.reason) + '</div></div>').join('')) + '</div>' +
    '</div></div>';
}
async function loadScannerHistory() {
  if (STATE.demoMode) return;
  try {
    const d = await apiJson('/api/dpdp/scanner/history');
    STATE.scans = d.scans || [];
    document.getElementById('scanner-history-list').innerHTML = STATE.scans.length
      ? STATE.scans.map(s => '<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;"><span><strong>' + esc(s.target_url) + '</strong> (' + esc(String(s.scanned_at).slice(0,16)) + ')</span><div><button class="btn btn-secondary btn-sm" onclick="viewPastScan(\\'' + esc(s.scan_id) + '\\')">View</button> <button class="btn btn-danger btn-sm" onclick="deleteScan(\\'' + esc(s.scan_id) + '\\')">Delete</button></div></div>').join('')
      : '<div style="font-size:13px;color:var(--muted);">No scans run yet.</div>';
    if (STATE.scans.length && !document.getElementById('scanner-results-panel').innerHTML) renderScanReport(STATE.scans[0]);
  } catch (e) {}
}
function viewPastScan(id) { const s = STATE.scans.find(x => x.scan_id === id); if (s) renderScanReport(s); }
async function deleteScan(id) { await apiJson('/api/dpdp/scanner/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Scan deleted.'); loadScannerHistory(); }

/* WHERE MY DATA GOES (SVG FLOW MAP) */
async function loadDataFlow() {
  const el = document.getElementById('data-flow-canvas');
  if (STATE.demoMode) { el.innerHTML = '<div class="empty-state">Sign in to view your live business data flow diagram.</div>'; return; }
  const inv = await apiJson('/api/dpdp/inventory').then(r => r.items || []).catch(() => []);
  const vnd = await apiJson('/api/dpdp/vendors').then(r => r.items || []).catch(() => []);
  const srcList = inv.slice(0, 4).map(i => i.category).join(', ') || 'No sources added yet';
  const strList = [...new Set(inv.map(i => i.storage_location).filter(Boolean))].slice(0, 4).join(', ') || 'No storage configured';
  const vndList = vnd.slice(0, 4).map(v => v.name).join(', ') || 'No vendors added yet';
  el.innerHTML = '<svg viewBox="0 0 760 220" width="100%" height="auto"><rect x="14" y="45" width="160" height="120" rx="12" fill="var(--accent-soft)" stroke="var(--accent)"/><text x="94" y="82" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">1. Collected Data</text><text x="94" y="106" text-anchor="middle" font-size="11" fill="var(--muted)">' + esc(srcList.slice(0,26)) + '</text><path d="M174 105 L234 105" stroke="var(--accent)" stroke-width="2" stroke-dasharray="4 4"/><rect x="234" y="45" width="170" height="120" rx="12" fill="var(--emerald-soft)" stroke="var(--emerald)"/><text x="319" y="82" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">2. Where It Lives</text><text x="319" y="106" text-anchor="middle" font-size="11" fill="var(--muted)">' + esc(strList.slice(0,26)) + '</text><path d="M404 105 L464 105" stroke="var(--emerald)" stroke-width="2" stroke-dasharray="4 4"/><rect x="464" y="45" width="270" height="120" rx="12" fill="var(--amber-soft)" stroke="var(--amber)"/><text x="599" y="82" text-anchor="middle" font-size="13" font-weight="700" fill="currentColor">3. Companies Shared With</text><text x="599" y="106" text-anchor="middle" font-size="11" fill="var(--muted)">' + esc(vndList.slice(0,36)) + '</text></svg>';
}

/* VENDORS */
async function loadVendors() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/vendors');
  STATE.vendors = d.items || [];
  document.getElementById('vnd-tbody').innerHTML = STATE.vendors.length ? STATE.vendors.map(v => (
    '<tr><td><strong>' + esc(v.name) + '</strong><div style="font-size:12px;color:var(--muted);">' + esc(v.service) + '</div></td>' +
    '<td>' + esc(v.personal_data_processed) + '<div style="font-size:12px;color:var(--muted);">' + esc(v.storage_location) + '</div></td>' +
    '<td><span class="badge b-blue">' + esc(v.dpa_status) + '</span></td>' +
    '<td><span class="badge b-slate">' + esc(v.risk_rating) + '</span> ' + esc(v.agreement_expiry || '') + '</td>' +
    '<td style="white-space:nowrap;"><button class="btn btn-secondary btn-sm" onclick="openVendorModal(\\'' + esc(v.id) + '\\')">Edit</button> ' +
    '<button class="btn btn-danger btn-sm" onclick="deleteVendor(\\'' + esc(v.id) + '\\')">Delete</button></td></tr>'
  )).join('') : '<tr><td colspan="5"><div class="empty-state">No third-party vendors recorded yet. Add your software tools, payment gateways, or partner labs.</div></td></tr>';
}
function openVendorModal(editId = null) {
  const v = editId ? STATE.vendors.find(x => x.id === editId) : null;
  openModal(v ? 'Edit Vendor Company' : 'Add Company You Share Data With',
    '<form onsubmit="event.preventDefault(); saveVendor(\\'' + esc(editId || '') + '\\');">' +
    '<div class="fg"><label class="fl">Company / Tool Name</label><input class="fi" id="m-vnd-name" required value="' + esc(v ? v.name : '') + '"/></div>' +
    '<div class="fg"><label class="fl">Service Provided</label><input class="fi" id="m-vnd-svc" value="' + esc(v ? v.service : 'Cloud / Software') + '"/></div>' +
    '<div class="fg"><label class="fl">Data Shared</label><input class="fi" id="m-vnd-data" value="' + esc(v ? v.personal_data_processed : 'Customer Contacts') + '"/></div>' +
    '<div class="fg"><label class="fl">Storage Location</label><input class="fi" id="m-vnd-loc" value="' + esc(v ? v.storage_location : 'India') + '"/></div>' +
    '<div class="fg"><label class="fl">Contract (DPA) Status</label><select class="fi" id="m-vnd-dpa">' +
    '<option>Not Started</option><option>Requested</option><option>Under Review</option><option>Signed</option><option>Expiring Soon</option><option>Needs Attention</option>' +
    '</select></div>' +
    '<div class="fg"><label class="fl">Risk Level</label><select class="fi" id="m-vnd-risk"><option>LOW</option><option>MEDIUM</option><option>HIGH</option></select></div>' +
    '<div class="fg"><label class="fl">Agreement Expiry Date</label><input class="fi" type="date" id="m-vnd-exp" value="' + esc(v ? v.agreement_expiry : '') + '"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Vendor</button></form>');
}
async function saveVendor(editId) {
  const payload = {
    name: document.getElementById('m-vnd-name').value,
    service: document.getElementById('m-vnd-svc').value,
    personal_data_processed: document.getElementById('m-vnd-data').value,
    storage_location: document.getElementById('m-vnd-loc').value,
    dpa_status: document.getElementById('m-vnd-dpa').value,
    risk_rating: document.getElementById('m-vnd-risk').value,
    agreement_expiry: document.getElementById('m-vnd-exp').value
  };
  try {
    if (editId) await apiJson('/api/dpdp/vendors/' + encodeURIComponent(editId), {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    else await apiJson('/api/dpdp/vendors', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    closeModal(); toast('Vendor saved.'); loadVendors();
  } catch (e) { toast(e.message, 'err'); }
}
async function deleteVendor(id) { await apiJson('/api/dpdp/vendors/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Vendor deleted.'); loadVendors(); }

/* PRIVACY NOTICES */
async function loadNotices() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/notices');
  STATE.notices = d.items || [];
  document.getElementById('notices-list').innerHTML = STATE.notices.length ? STATE.notices.map(n => (
    '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">' +
    '<div><strong>' + esc(n.title) + '</strong> <span class="badge b-blue">' + esc(n.version) + '</span> <span class="badge ' + (n.status === 'APPROVED_PUBLISHED' ? 'b-green' : 'b-amber') + '">' + esc(n.status) + '</span></div>' +
    '<div style="display:flex;gap:6px;"><button class="btn btn-secondary btn-sm" onclick="editNoticeModal(\\'' + esc(n.id) + '\\')">Edit &amp; Preview</button>' +
    '<button class="btn btn-primary btn-sm" onclick="approveNotice(\\'' + esc(n.id) + '\\')">Approve</button>' +
    '<button class="btn btn-danger btn-sm" onclick="deleteNotice(\\'' + esc(n.id) + '\\')">Delete</button></div></div>' +
    '<pre style="white-space:pre-wrap;font-size:12.5px;background:var(--surface-2);padding:12px;border-radius:8px;max-height:220px;overflow-y:auto;">' + esc(n.content) + '</pre></div>'
  )).join('') : '<div class="empty-state">No Privacy Notice drafts created yet. Fill your contact info above and click Generate.</div>';
}
async function generateNotice() {
  try {
    await apiJson('/api/dpdp/notices/generate', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        title: document.getElementById('not-title').value || 'Customer Privacy Notice',
        grievance_officer: document.getElementById('not-officer').value,
        grievance_email: document.getElementById('not-email').value
      })
    });
    toast('Privacy Notice draft created.'); loadNotices();
  } catch (e) { toast(e.message, 'err'); }
}
function editNoticeModal(id) {
  const n = STATE.notices.find(x => x.id === id); if (!n) return;
  openModal('Edit Privacy Notice',
    '<form onsubmit="event.preventDefault(); saveNoticeEdit(\\'' + esc(id) + '\\');">' +
    '<div class="fg"><label class="fl">Title</label><input class="fi" id="m-not-title" value="' + esc(n.title) + '"/></div>' +
    '<div class="fg"><label class="fl">Notice Content</label><textarea class="fi" id="m-not-body" rows="12">' + esc(n.content) + '</textarea></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save New Version</button></form>');
}
async function saveNoticeEdit(id) {
  await apiJson('/api/dpdp/notices/' + encodeURIComponent(id), {
    method: 'PUT', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({title: document.getElementById('m-not-title').value, content: document.getElementById('m-not-body').value, bump_version: true})
  });
  closeModal(); toast('Privacy Notice updated.'); loadNotices();
}
async function approveNotice(id) {
  await apiJson('/api/dpdp/notices/' + encodeURIComponent(id), {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: 'APPROVED_PUBLISHED'})});
  toast('Privacy Notice approved.'); loadNotices();
}
async function deleteNotice(id) { await apiJson('/api/dpdp/notices/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Notice deleted.'); loadNotices(); }

/* CONSENT RECORDS */
async function loadConsent() {
  if (STATE.demoMode) return;
  const q = encodeURIComponent(document.getElementById('cst-search').value || '');
  const d = await apiJson('/api/dpdp/consent?q=' + q);
  const items = d.items || [];
  document.getElementById('cst-tbody').innerHTML = items.length ? items.map(r => (
    '<tr><td>' + esc(r.data_principal_ref) + '</td><td>' + esc(r.data_category) + '</td><td>' + esc(r.purpose) + ' (' + esc(r.notice_version) + ')</td><td>' + esc(r.collection_channel) + '</td><td><span class="badge ' + (r.status === 'ACTIVE' ? 'b-green' : 'b-amber') + '">' + esc(r.status) + '</span></td></tr>'
  )).join('') : '<tr><td colspan="5"><div class="empty-state">No consent records logged yet.</div></td></tr>';
}
function openConsentModal() {
  openModal('Log Consent Record',
    '<form onsubmit="event.preventDefault(); saveConsent();">' +
    '<div class="fg"><label class="fl">Customer Reference ID</label><input class="fi" id="m-cst-ref" required placeholder="CUST-1042"/></div>' +
    '<div class="fg"><label class="fl">Data Category</label><input class="fi" id="m-cst-cat" value="Marketing & Updates"/></div>' +
    '<div class="fg"><label class="fl">Purpose Shown</label><input class="fi" id="m-cst-pur" value="Appointment reminders & offers"/></div>' +
    '<div class="fg"><label class="fl">Notice Version</label><input class="fi" id="m-cst-ver" value="v1.0"/></div>' +
    '<div class="fg"><label class="fl">Source / Channel</label><input class="fi" id="m-cst-ch" value="Website Form"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Consent Log</button></form>');
}
async function saveConsent() {
  await apiJson('/api/dpdp/consent', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    principal_ref: document.getElementById('m-cst-ref').value, category: document.getElementById('m-cst-cat').value,
    purpose: document.getElementById('m-cst-pur').value, notice_version: document.getElementById('m-cst-ver').value,
    channel: document.getElementById('m-cst-ch').value
  })});
  closeModal(); toast('Consent logged.'); loadConsent();
}
function openWithdrawalModal() {
  openModal('Log Consent Withdrawal (Section 6(4))',
    '<form onsubmit="event.preventDefault(); saveWithdrawal();">' +
    '<div class="fg"><label class="fl">Customer Reference ID</label><input class="fi" id="m-wth-ref" required placeholder="CUST-1042"/></div>' +
    '<div class="fg"><label class="fl">Category Withdrawn</label><input class="fi" id="m-wth-cat" value="Marketing Communications"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Record Withdrawal</button></form>');
}
async function saveWithdrawal() {
  await apiJson('/api/dpdp/withdrawals', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    principal_ref: document.getElementById('m-wth-ref').value, category: document.getElementById('m-wth-cat').value
  })});
  closeModal(); toast('Consent withdrawal recorded.'); loadConsent();
}

/* CUSTOMER PRIVACY REQUESTS */
async function loadRights() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/rights');
  STATE.rights = d.items || [];
  document.getElementById('req-tbody').innerHTML = STATE.rights.length ? STATE.rights.map(r => (
    '<tr><td><strong>' + esc(r.principal_name) + '</strong><div><span class="badge b-blue">' + esc(r.type) + '</span></div></td>' +
    '<td>' + esc(r.description) + '<div style="font-size:12px;color:var(--muted);">' + esc(r.principal_contact) + '</div></td>' +
    '<td>' + (r.identity_verified ? '<span class="badge b-green">Verified</span>' : '<span class="badge b-amber">Pending Check</span>') + '</td>' +
    '<td><span class="badge b-slate">' + esc(r.status) + '</span><div style="font-size:12px;color:var(--muted);">' + esc(r.assigned_to) + '</div></td>' +
    '<td><button class="btn btn-secondary btn-sm" onclick="openRightsUpdateModal(\\'' + esc(r.id) + '\\')">Manage / Resolve</button></td></tr>'
  )).join('') : '<tr><td colspan="5"><div class="empty-state">No customer privacy requests logged yet.</div></td></tr>';
}
function openRightsModal() {
  openModal('Log Customer Privacy Request',
    '<form onsubmit="event.preventDefault(); saveRightReq();">' +
    '<div class="fg"><label class="fl">Request Type</label><select class="fi" id="m-req-type"><option value="ACCESS">Access My Data</option><option value="CORRECTION">Correct Mistakes</option><option value="ERASURE">Delete My Data</option><option value="GRIEVANCE">Grievance / Complaint</option><option value="NOMINATION">Add Nominee</option></select></div>' +
    '<div class="fg"><label class="fl">Customer Name</label><input class="fi" id="m-req-name" required/></div>' +
    '<div class="fg"><label class="fl">Customer Email / Phone</label><input class="fi" id="m-req-contact" required/></div>' +
    '<div class="fg"><label class="fl">Request Summary</label><textarea class="fi" id="m-req-desc" rows="3"></textarea></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Create Request Ticket</button></form>');
}
async function saveRightReq() {
  await apiJson('/api/dpdp/rights', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    type: document.getElementById('m-req-type').value, principal_name: document.getElementById('m-req-name').value,
    principal_contact: document.getElementById('m-req-contact').value, description: document.getElementById('m-req-desc').value
  })});
  closeModal(); toast('Customer request logged.'); loadRights();
}
function openRightsUpdateModal(id) {
  openModal('Update Customer Request',
    '<form onsubmit="event.preventDefault(); saveRightsUpdate(\\'' + esc(id) + '\\');">' +
    '<div class="fg"><label class="fl">Status</label><select class="fi" id="m-ru-st"><option>VERIFIED</option><option>IN_PROGRESS</option><option>COMPLETED</option><option>REJECTED</option></select></div>' +
    '<div class="fg"><label><input type="checkbox" id="m-ru-ver" checked/> Identity verified before releasing/deleting data</label></div>' +
    '<div class="fg"><label class="fl">Assigned Owner</label><input class="fi" id="m-ru-own" value="Privacy Officer"/></div>' +
    '<div class="fg"><label class="fl">Response / Resolution Note</label><textarea class="fi" id="m-ru-note" rows="3"></textarea></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Update</button></form>');
}
async function saveRightsUpdate(id) {
  await apiJson('/api/dpdp/rights/' + encodeURIComponent(id) + '/status', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    status: document.getElementById('m-ru-st').value, identity_verified: document.getElementById('m-ru-ver').checked,
    assigned_to: document.getElementById('m-ru-own').value, response_summary: document.getElementById('m-ru-note').value
  })});
  closeModal(); toast('Request updated.'); loadRights();
}

/* RETENTION & ERASURE */
async function loadRetention() {
  if (STATE.demoMode) return;
  const r = await apiJson('/api/dpdp/retention'); STATE.retention = r.items || [];
  const e = await apiJson('/api/dpdp/erasure-tasks'); STATE.erasures = e.items || [];
  document.getElementById('ret-list').innerHTML = STATE.retention.length ? STATE.retention.map(s => (
    '<div style="padding:10px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">' +
    '<div><strong>' + esc(s.category) + '</strong> (' + esc(s.period_years) + ' yrs)<div style="font-size:12px;color:var(--muted);">' + esc(s.statutory_basis) + ' &bull; Owner: ' + esc(s.owner || 'Privacy Lead') + '</div></div>' +
    '<button class="btn btn-danger btn-sm" onclick="deleteRetention(\\'' + esc(s.id) + '\\')">Delete</button></div>'
  )).join('') : '<div class="empty-state">No retention schedules set yet.</div>';
  document.getElementById('era-list').innerHTML = STATE.erasures.length ? STATE.erasures.map(t => (
    '<div style="padding:10px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">' +
    '<div><strong>' + esc(t.data_category) + '</strong> <span class="badge b-blue">' + esc(t.status) + '</span><div style="font-size:12px;color:var(--muted);">' + esc(t.subject_identifier) + '</div></div>' +
    (t.status !== 'VERIFIED_ERASED' ? '<button class="btn btn-primary btn-sm" onclick="completeErasure(\\'' + esc(t.id) + '\\')">Mark Deleted</button>' : '') + '</div>'
  )).join('') : '<div class="empty-state">No deletion tasks created yet.</div>';
}
function openRetentionModal() {
  openModal('Add Retention Schedule',
    '<form onsubmit="event.preventDefault(); saveRetention();">' +
    '<div class="fg"><label class="fl">Record Category</label><input class="fi" id="m-ret-cat" required placeholder="Enquiry Forms / Invoices"/></div>' +
    '<div class="fg"><label class="fl">Keep Duration (Years)</label><input class="fi" type="number" step="0.5" id="m-ret-yrs" value="3"/></div>' +
    '<div class="fg"><label class="fl">Legal Reason</label><input class="fi" id="m-ret-law" value="DPDP Section 8(7) Purpose Limit"/></div>' +
    '<div class="fg"><label class="fl">Owner</label><input class="fi" id="m-ret-own" value="Operations Lead"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Schedule</button></form>');
}
async function saveRetention() {
  await apiJson('/api/dpdp/retention', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    category: document.getElementById('m-ret-cat').value, period_years: Number(document.getElementById('m-ret-yrs').value),
    statutory_basis: document.getElementById('m-ret-law').value, owner: document.getElementById('m-ret-own').value
  })});
  closeModal(); toast('Schedule saved.'); loadRetention();
}
async function deleteRetention(id) { await apiJson('/api/dpdp/retention/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Schedule deleted.'); loadRetention(); }
function openErasureModal() {
  openModal('Create Deletion Task',
    '<form onsubmit="event.preventDefault(); saveErasure();">' +
    '<div class="fg"><label class="fl">Data Category to Erase</label><input class="fi" id="m-era-cat" required placeholder="Old Website Leads 2024"/></div>' +
    '<div class="fg"><label class="fl">Reference / Batch ID</label><input class="fi" id="m-era-ref" value="BATCH-2026-01"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Create Deletion Task</button></form>');
}
async function saveErasure() {
  await apiJson('/api/dpdp/erasure-tasks', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    data_category: document.getElementById('m-era-cat').value, subject_identifier: document.getElementById('m-era-ref').value
  })});
  closeModal(); toast('Deletion task added.'); loadRetention();
}
async function completeErasure(id) {
  await apiJson('/api/dpdp/erasure-tasks/' + encodeURIComponent(id), {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: 'VERIFIED_ERASED', notes: 'Deleted and confirmed.'})});
  toast('Deletion verified.'); loadRetention();
}

/* INCIDENTS */
async function loadIncidents() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/breaches');
  const items = d.items || [];
  document.getElementById('brc-list').innerHTML = items.length ? items.map(inc => (
    '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">' +
    '<div><strong>' + esc(inc.title) + '</strong> <span class="badge b-rose">' + esc(inc.severity) + '</span> <span class="badge b-blue">' + esc(inc.board_notification_status) + '</span></div>' +
    '<div style="display:flex;gap:6px;"><button class="btn btn-secondary btn-sm" onclick="addTimelineNote(\\'' + esc(inc.id) + '\\')">Add Timeline Note</button>' +
    (inc.customer_authorized_to_send ? '' : '<button class="btn btn-primary btn-sm" onclick="authorizeIncident(\\'' + esc(inc.id) + '\\')">Approve Drafts</button>') + '</div></div>' +
    '<div style="font-size:12.5px;color:var(--muted);">Affected Systems: ' + esc((inc.systems_affected || []).join(', ') || 'Not specified') + ' | Records: ' + esc(inc.estimated_individuals_affected) + '</div>' +
    '<div style="margin-top:8px;font-size:12.5px;">' + (inc.timeline_events || []).map(ev => '<div>&bull; ' + esc(String(ev.timestamp).slice(0,16)) + ' &mdash; ' + esc(ev.event) + '</div>').join('') + '</div></div>'
  )).join('') : '<div class="empty-state">No privacy incidents recorded.</div>';
}
function openIncidentModal() {
  openModal('Log Privacy Incident',
    '<form onsubmit="event.preventDefault(); saveIncident();">' +
    '<div class="fg"><label class="fl">What Happened?</label><input class="fi" id="m-inc-title" required placeholder="e.g., Accidental email attachment sent to wrong clinic"/></div>' +
    '<div class="fg"><label class="fl">Severity</label><select class="fi" id="m-inc-sev"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>' +
    '<div class="fg"><label class="fl">Systems Affected (comma-separated)</label><input class="fi" id="m-inc-sys" value="Email, Billing Tool"/></div>' +
    '<div class="fg"><label class="fl">Estimated People Affected</label><input class="fi" type="number" id="m-inc-cnt" value="1"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Save Incident Log</button></form>');
}
async function saveIncident() {
  await apiJson('/api/dpdp/breaches', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    title: document.getElementById('m-inc-title').value, severity: document.getElementById('m-inc-sev').value,
    systems_affected: document.getElementById('m-inc-sys').value.split(',').map(s => s.trim()).filter(Boolean),
    estimated_individuals_affected: Number(document.getElementById('m-inc-cnt').value)
  })});
  closeModal(); toast('Incident logged.'); loadIncidents();
}
async function addTimelineNote(id) {
  openModal('Add Incident Timeline Event', '<form onsubmit="event.preventDefault(); submitTimelineNote(\\'' + esc(id) + '\\');"><div class="fg"><label class="fl">Timeline Update</label><input class="fi" id="m-tl-note" required placeholder="Revoked access & notified team"/></div><button type="submit" class="btn btn-primary" style="width:100%;">Add Event</button></form>');
}
async function submitTimelineNote(id) {
  await apiJson('/api/dpdp/breaches/' + encodeURIComponent(id), {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({timeline_note: document.getElementById('m-tl-note').value})});
  closeModal(); toast('Timeline event added.'); loadIncidents();
}
async function authorizeIncident(id) {
  await apiJson('/api/dpdp/breaches/' + encodeURIComponent(id) + '/authorize', {method: 'POST'});
  toast('Incident notice drafts authorised.'); loadIncidents();
}

/* DOCUMENT CENTRE */
async function loadDocumentTemplates() {
  const d = await apiJson('/api/dpdp/documents/templates');
  document.getElementById('doc-templates-grid').innerHTML = (d.templates || []).map(t => (
    '<div class="card"><h3>' + esc(t.title) + '</h3><p style="font-size:13px;color:var(--muted);margin:6px 0 12px;">' + esc(t.description) + '</p>' +
    '<button class="btn btn-primary btn-sm" onclick="generateDoc(\\'' + esc(t.id) + '\\')">Generate Draft</button></div>'
  )).join('');
}
async function generateDoc(docType) {
  if (STATE.demoMode) { toast('Sign in to generate tailored business documents.', 'err'); return; }
  const d = await apiJson('/api/dpdp/documents/generate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({doc_type: docType})});
  const doc = d.document;
  const box = document.getElementById('doc-preview-card');
  box.style.display = 'block';
  box.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;"><strong>' + esc(doc.title) + '</strong><span class="badge b-amber">' + esc(doc.watermark) + '</span></div>' +
    '<pre style="white-space:pre-wrap;font-size:12.5px;background:var(--surface-2);padding:14px;border-radius:8px;max-height:360px;overflow-y:auto;">' + esc(doc.content) + '</pre>';
  toast('Draft generated.');
}

/* EVIDENCE VAULT */
async function loadEvidence() {
  if (STATE.demoMode) return;
  const st = encodeURIComponent(document.getElementById('evi-status-filter').value || '');
  const d = await apiJson('/api/dpdp/evidence/list' + (st ? '?status=' + st : ''));
  STATE.evidence = d.artifacts || [];
  document.getElementById('evi-tbody').innerHTML = STATE.evidence.length ? STATE.evidence.map(e => (
    '<tr><td><strong>' + esc(e.title) + '</strong><div style="font-size:12px;color:var(--muted);">' + esc(e.filename) + ' (v' + ((e.versions || []).length || 1) + ')</div></td>' +
    '<td><span class="badge b-slate">' + esc(e.control_id) + '</span></td>' +
    '<td><select class="fi" style="min-width:130px;padding:4px 8px;font-size:12.5px;" onchange="changeEvidenceStatus(\\'' + esc(e.id) + '\\', this.value)">' +
    ['Uploaded','Pending review','Verified','Rejected','Expired'].map(opt => '<option' + (e.status === opt ? ' selected' : '') + '>' + opt + '</option>').join('') + '</select></td>' +
    '<td style="font-size:12px;">Exp: ' + esc(e.expiry_date) + '<div style="color:var(--muted);">' + esc(String(e.file_hash).slice(0,18)) + '...</div></td>' +
    '<td style="white-space:nowrap;">' +
    (e.has_physical_file ? '<a class="btn btn-secondary btn-sm" href="/api/dpdp/evidence/' + esc(e.id) + '/preview" target="_blank">Preview</a> <a class="btn btn-secondary btn-sm" href="/api/dpdp/evidence/' + esc(e.id) + '/download">Download</a> ' : '') +
    '<button class="btn btn-danger btn-sm" onclick="deleteEvidence(\\'' + esc(e.id) + '\\')">Delete</button></td></tr>'
  )).join('') : '<tr><td colspan="5"><div class="empty-state">No evidence uploaded yet. Click "+ Upload Evidence File" to add proof.</div></td></tr>';
}
function openEvidenceUploadModal() {
  openModal('Upload Evidence File (Max 5 MB)',
    '<form onsubmit="event.preventDefault(); uploadEvidenceFile();">' +
    '<div class="fg"><label class="fl">Title / Description</label><input class="fi" id="m-ev-title" required placeholder="Signed Cloud Vendor DPA 2026"/></div>' +
    '<div class="fg"><label class="fl">Linked DPDP Area</label><select class="fi" id="m-ev-ctrl"><option value="DPDP-SEC-05">Privacy Notice (Sec 5)</option><option value="DPDP-SEC-08-01">Vendor Contract / DPA (Sec 8(2))</option><option value="DPDP-SEC-08-05">Security Safeguards (Sec 8(5))</option><option value="DPDP-SEC-08-07">Retention & Deletion (Sec 8(7))</option><option value="DPDP-SEC-08-06">Breach Procedure (Sec 8(6))</option></select></div>' +
    '<div class="fg"><label class="fl">Select File (PDF, PNG, JPG, TXT, CSV, MD, DOCX, XLSX, JSON)</label><input class="fi" type="file" id="m-ev-file" required/></div>' +
    '<div class="fg"><label class="fl">Expiry Date</label><input class="fi" type="date" id="m-ev-exp"/></div>' +
    '<button type="submit" class="btn btn-primary" style="width:100%;">Upload &amp; Compute SHA-256</button></form>');
}
async function uploadEvidenceFile() {
  const f = document.getElementById('m-ev-file').files[0];
  if (!f) { toast('Choose a file to upload.', 'err'); return; }
  const fd = new FormData();
  fd.append('title', document.getElementById('m-ev-title').value);
  fd.append('control_id', document.getElementById('m-ev-ctrl').value);
  fd.append('expiry_date', document.getElementById('m-ev-exp').value);
  fd.append('file', f);
  try {
    const res = await fetch('/api/dpdp/evidence/upload', {method: 'POST', body: fd});
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || d.message || 'Upload failed');
    closeModal(); toast('Evidence uploaded with SHA-256 fingerprint.'); loadEvidence();
  } catch (e) { toast(e.message, 'err'); }
}
async function changeEvidenceStatus(id, st) {
  await apiJson('/api/dpdp/evidence/' + encodeURIComponent(id) + '/status', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: st})});
  toast('Status updated to ' + st);
}
async function deleteEvidence(id) { await apiJson('/api/dpdp/evidence/' + encodeURIComponent(id), {method: 'DELETE'}); toast('Evidence deleted.'); loadEvidence(); }

/* AI DPDP ASSISTANT (USES data.answer + STARTER QUESTIONS + FEEDBACK + HISTORY) */
async function loadAssistant() {
  if (STATE.demoMode) return;
  try {
    const d = await apiJson('/api/dpdp/assistant/history');
    document.getElementById('ai-starter-chips').innerHTML = (d.starter_questions || []).map(q => (
      '<button class="btn btn-secondary btn-sm" onclick="askAssistant(\\'' + esc(q).replace(/'/g, "&#39;") + '\\')">' + esc(q) + '</button>'
    )).join('');
    renderAssistantHistory(d.history || []);
  } catch (e) {}
}
function renderAssistantHistory(hist) {
  document.getElementById('ai-chat-history').innerHTML = hist.length ? hist.map(m => (
    '<div style="padding:12px;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);">' +
    '<div style="font-weight:700;font-size:13.5px;margin-bottom:6px;">You: ' + esc(m.query) + '</div>' +
    '<div style="font-size:13.5px;white-space:pre-wrap;">' + esc(m.answer) + '</div>' +
    '<div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:var(--muted);">' +
    '<span>Citation: ' + esc(m.matched_section) + ' | Engine: ' + esc(m.engine || '') + '</span>' +
    '<div style="display:flex;gap:6px;"><button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText(\\'' + esc(m.answer).replace(/'/g,'') + '\\'); toast(\\'Copied\\')">Copy</button>' +
    '<button class="btn btn-secondary btn-sm" onclick="sendAiFeedback(\\'' + esc(m.message_id) + '\\', \\'helpful\\')">Helpful</button></div></div></div>'
  )).join('') : '<div style="font-size:13px;color:var(--muted);">Click any starter question above or ask your question below.</div>';
}
async function askAssistant(presetQuery = null) {
  if (STATE.demoMode) { toast('Sign in to use the organisation AI DPDP Assistant.', 'err'); return; }
  const q = presetQuery || document.getElementById('ai-query-input').value.trim();
  if (!q) return;
  const btn = document.getElementById('ai-ask-btn'); btn.disabled = true;
  try {
    const res = await apiJson('/api/dpdp/assistant', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({query: q})});
    document.getElementById('ai-query-input').value = '';
    const histBox = document.getElementById('ai-chat-history');
    const card = '<div style="padding:12px;border:1px solid var(--accent);border-radius:10px;background:var(--accent-soft);">' +
      '<div style="font-weight:700;margin-bottom:6px;">You: ' + esc(res.query) + '</div>' +
      '<div style="font-size:13.5px;white-space:pre-wrap;">' + esc(res.answer) + '</div>' +
      '<div style="font-size:11.5px;color:var(--muted);margin-top:8px;">' + esc(res.data_handling_notice || '') + '</div></div>';
    histBox.innerHTML = card + histBox.innerHTML;
  } catch (e) { toast(e.message, 'err'); }
  finally { btn.disabled = false; }
}
async function sendAiFeedback(msgId, rating) {
  await apiJson('/api/dpdp/assistant/feedback', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({message_id: msgId, rating})});
  toast('Feedback recorded. Thank you!');
}

/* GLOSSARY */
function renderGlossary() {
  const items = [
    ['Data Fiduciary (Your Business)', 'Any business or clinic that decides why and how customer personal details are collected and used (Section 2(i)).'],
    ['Data Principal (Customer / Patient)', 'The person whose personal details your business holds (Section 2(j)).'],
    ['Data Processor (Vendor)', 'Any software company, diagnostic lab, cloud host, or courier processing personal data on your behalf (Section 2(k)).'],
    ['Privacy Notice (Section 5)', 'A clear message explaining what personal data you collect, why, customer rights, and how to contact your Grievance Officer.'],
    ['Certain Legitimate Uses (Section 7)', 'Specific legal grounds where consent is NOT required (for example, voluntary walk-in service requests, medical emergencies, tax compliance, and employment HR).'],
    ['Privacy Incident / Breach (Section 8(6))', 'Any accidental or unauthorised exposure, alteration, or loss of customer personal information requiring Board & customer intimation under Rule 7.']
  ];
  document.getElementById('glossary-grid').innerHTML = items.map(([t, d]) => '<div class="card"><h3>' + esc(t) + '</h3><p style="font-size:13.5px;color:var(--ink-2);margin-top:6px;">' + esc(d) + '</p></div>').join('');
}

/* SETTINGS, TEAM, MFA, AUDIT LOGS */
async function loadSettings() {
  if (STATE.demoMode) return;
  try {
    const prof = await apiJson('/api/dpdp/onboarding').then(r => r.profile || {});
    document.getElementById('set-company').value = prof.company_name || (STATE.org || {}).name || '';
    document.getElementById('set-website').value = prof.website_url || '';
    document.getElementById('set-email').value = prof.contact_email || '';
    document.getElementById('set-industry').value = prof.industry || '';

    const team = await apiJson('/api/team/members').then(r => r.team_members || []);
    document.getElementById('team-tbody').innerHTML = team.map(u => (
      '<tr><td>' + esc(u.name) + '</td><td>' + esc(u.email) + '</td><td>' +
      '<select class="fi" style="max-width:130px;padding:4px;" onchange="changeTeamRole(\\'' + esc(u.id) + '\\', this.value)">' +
      ['admin','member','viewer'].map(r => '<option' + (u.role === r ? ' selected' : '') + '>' + r + '</option>').join('') + '</select></td>' +
      '<td><button class="btn btn-danger btn-sm" onclick="removeTeamMember(\\'' + esc(u.id) + '\\')">Remove</button></td></tr>'
    )).join('');

    const audits = await apiJson('/api/audit-logs?limit=25').then(r => r.events || []);
    document.getElementById('audit-tbody').innerHTML = audits.map(a => (
      '<tr><td style="font-size:12px;">' + esc(String(a.timestamp).slice(0,19).replace('T',' ')) + '</td><td>' + esc(a.actor_email || '-') + '</td><td><strong>' + esc(a.action) + '</strong></td><td>' + esc(a.resource_type + ' ' + (a.resource_id || '')) + '</td></tr>'
    )).join('');

    const mfaEnabled = !!(STATE.user && STATE.user.mfa_enabled);
    document.getElementById('mfa-box').innerHTML = mfaEnabled
      ? '<span class="badge b-green">TOTP 2FA Enabled</span> <button class="btn btn-secondary btn-sm" onclick="disableMfaModal()" style="margin-left:8px;">Disable 2FA</button>'
      : '<span class="badge b-amber">2FA Not Enabled</span> <button class="btn btn-primary btn-sm" onclick="setupMfaModal()" style="margin-left:8px;">Enable TOTP 2FA</button>';
  } catch (e) {}
}
async function saveBusinessSettings() {
  await apiJson('/api/dpdp/onboarding', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
    company_name: document.getElementById('set-company').value, website_url: document.getElementById('set-website').value,
    contact_email: document.getElementById('set-email').value, industry: document.getElementById('set-industry').value
  })});
  toast('Business details saved.');
}
function openTeamModal() {
  openModal('Invite Team Member', '<form onsubmit="event.preventDefault(); addTeamMember();"><div class="fg"><label class="fl">Name</label><input class="fi" id="m-tm-name" required/></div><div class="fg"><label class="fl">Email</label><input class="fi" type="email" id="m-tm-email" required/></div><div class="fg"><label class="fl">Role</label><select class="fi" id="m-tm-role"><option value="member">Member (Read &amp; Write)</option><option value="viewer">Viewer (Read-Only)</option><option value="admin">Admin (Full Control)</option></select></div><button type="submit" class="btn btn-primary" style="width:100%;">Add Team Member</button></form>');
}
async function addTeamMember() {
  try { await apiJson('/api/team/members', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name: document.getElementById('m-tm-name').value, email: document.getElementById('m-tm-email').value, role: document.getElementById('m-tm-role').value})}); closeModal(); toast('Member added.'); loadSettings(); } catch (e) { toast(e.message, 'err'); }
}
async function changeTeamRole(uid, role) { try { await apiJson('/api/team/members/' + encodeURIComponent(uid) + '/role', {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({role})}); toast('Role updated.'); } catch (e) { toast(e.message, 'err'); loadSettings(); } }
async function removeTeamMember(uid) { try { await apiJson('/api/team/members/' + encodeURIComponent(uid), {method: 'DELETE'}); toast('Member removed.'); loadSettings(); } catch (e) { toast(e.message, 'err'); } }
async function setupMfaModal() {
  const res = await apiJson('/api/auth/mfa/setup', {method: 'POST'});
  openModal('Enable TOTP Multi-Factor Authentication', '<p style="font-size:13px;margin-bottom:10px;">Add this secret key to Google Authenticator or Authy:</p><code style="display:block;padding:10px;background:var(--surface-2);border-radius:8px;margin-bottom:12px;">' + esc(res.data.secret) + '</code><form onsubmit="event.preventDefault(); confirmMfa();"><div class="fg"><label class="fl">Enter 6-Digit Code</label><input class="fi" id="m-mfa-code" required/></div><button type="submit" class="btn btn-primary" style="width:100%;">Confirm &amp; Enable 2FA</button></form>');
}
async function confirmMfa() { try { await apiJson('/api/auth/mfa/enable', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({code: document.getElementById('m-mfa-code').value})}); closeModal(); toast('2FA enabled!'); initApp(); } catch (e) { toast(e.message, 'err'); } }
function disableMfaModal() { openModal('Disable 2FA', '<form onsubmit="event.preventDefault(); confirmDisableMfa();"><div class="fg"><label class="fl">Current 6-Digit Authenticator Code</label><input class="fi" id="m-mfa-dis" required/></div><button type="submit" class="btn btn-danger" style="width:100%;">Disable 2FA</button></form>'); }
async function confirmDisableMfa() { try { await apiJson('/api/auth/mfa/disable', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({code: document.getElementById('m-mfa-dis').value})}); closeModal(); toast('2FA disabled.'); initApp(); } catch (e) { toast(e.message, 'err'); } }
function openDeleteAccountModal() {
  openModal('Confirm Permanent Organisation Deletion', '<p style="font-size:13.5px;margin-bottom:14px;color:var(--rose);">This permanently deletes all customer data lists, vendors, scans, evidence files, and user accounts for your organisation.</p><button onclick="confirmAccountDelete()" class="btn btn-danger" style="width:100%;">Yes, Permanently Delete Everything</button>');
}
async function confirmAccountDelete() { try { await apiJson('/api/account/delete', {method: 'POST'}); closeModal(); toast('Organisation deleted.'); showAuthGate('register'); } catch (e) { toast(e.message, 'err'); } }

/* ADVANCED LEGAL CENTRE */
async function loadLegalAssessment() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/assessment');
  const ctrls = d.controls || [];
  document.getElementById('legal-reqs-list').innerHTML = ctrls.map(c => '<div style="padding:10px 0;border-bottom:1px solid var(--border);"><strong>' + esc(c.section) + ' &mdash; ' + esc(c.title) + '</strong> <span class="badge b-blue">' + esc(c.commencement_status || c.legal_status) + '</span><div style="font-size:12.5px;color:var(--muted);">' + esc(c.description) + '</div></div>').join('');
}
async function loadOrgAssessment() {
  if (STATE.demoMode) return;
  const d = await apiJson('/api/dpdp/assessment/organisational');
  const m = (d.assessment || {}).summary_metrics || {};
  document.getElementById('org-ass-box').innerHTML = '<p><strong>Readiness Coverage:</strong> ' + esc(m.coverage_percentage || 0) + '% | <strong>Confidence:</strong> ' + esc(m.confidence_level || 'UNASSESSED') + '</p>';
}
async function loadPenalties() {
  const d = await apiJson('/api/dpdp/penalties/matrix');
  const p = Object.values(d.penalties || {});
  const f = d.section_33_factors || [];
  document.getElementById('penalties-matrix-box').innerHTML =
    '<p style="font-size:12.5px;color:var(--muted);margin-bottom:12px;">' + esc(d.disclaimer) + '</p>' +
    '<div class="tbl-wrap"><table><thead><tr><th>Section</th><th>Violation Category</th><th>Maximum Statutory Ceiling</th></tr></thead><tbody>' +
    p.map(x => '<tr><td><strong>' + esc(x.section) + '</strong></td><td>' + esc(x.violation_category) + '</td><td><strong>' + esc(x.max_penalty_text) + '</strong></td></tr>').join('') +
    '</tbody></table></div><h4 style="margin:16px 0 8px;">7 Statutory Factors Under Section 33(2)</h4>' +
    f.map(x => '<div style="font-size:13px;padding:4px 0;"><strong>' + esc(x.clause) + ':</strong> ' + esc(x.title) + ' &mdash; ' + esc(x.plain_english) + '</div>').join('');
}
async function loadTimeline() {
  const d = await apiJson('/api/dpdp/commencement/registry');
  document.getElementById('timeline-box').innerHTML = (d.milestones || []).map(m => '<div style="padding:10px 0;border-bottom:1px solid var(--border);"><strong>' + esc(m.milestone_date) + ' &mdash; ' + esc(m.phase_name) + '</strong> <span class="badge b-blue">' + esc(m.status) + '</span><div style="font-size:13px;color:var(--muted);">' + esc(m.description) + '</div></div>').join('');
}

window.addEventListener('DOMContentLoaded', initApp);
</script>
</body>
</html>
"""
