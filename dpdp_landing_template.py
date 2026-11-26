"""
TrustAudit — Final Public Launch Homepage (Part 8 + Legal Accuracy + Interactive Quick Check)
Clean, high-trust enterprise SaaS presentation inspired by Linear / Stripe / Vanta / Certinal.
"""

DPDP_LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrustAudit — Know What Happens to Your Customer Data | DPDP Readiness for Indian Businesses</title>
<meta name="description" content="TrustAudit helps Indian businesses understand their DPDP readiness, organise customer data information, manage privacy tasks and keep important compliance evidence in one place.">
<style>
  :root {
    --bg: #FAFBFD;
    --surface: #FFFFFF;
    --surface-muted: #F1F5F9;
    --ink: #0F172A;
    --ink-soft: #475569;
    --ink-muted: #64748B;
    --border: #E2E8F0;
    --border-strong: #CBD5E1;
    --accent: #1D4ED8;
    --accent-hover: #1E40AF;
    --accent-soft: #EFF6FF;
    --emerald: #059669;
    --emerald-soft: #ECFDF5;
    --amber: #D97706;
    --amber-soft: #FFFBEB;
    --rose: #E11D48;
    --rose-soft: #FFF1F2;
    --navy: #0B1221;
    --radius-lg: 16px;
    --radius-md: 12px;
    --radius-sm: 8px;
    --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
    --shadow-md: 0 10px 25px -5px rgba(15, 23, 42, 0.08), 0 4px 10px -4px rgba(15, 23, 42, 0.04);
    --shadow-lg: 0 24px 48px -12px rgba(15, 23, 42, 0.12);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--ink);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }

  .container { max-width: 1180px; margin: 0 auto; padding: 0 24px; }

  /* NAVBAR */
  .navbar {
    position: sticky; top: 0; z-index: 60;
    background: rgba(250, 251, 253, 0.9);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
  }
  .nav-inner {
    display: flex; align-items: center; justify-content: space-between;
    height: 70px; gap: 16px;
  }
  .brand {
    display: flex; align-items: center; gap: 10px;
    text-decoration: none; color: var(--ink); font-weight: 800; font-size: 19px; letter-spacing: -0.02em;
  }
  .brand-mark {
    width: 34px; height: 34px; border-radius: 9px; background: var(--navy);
    display: flex; align-items: center; justify-content: center; color: #fff;
  }
  .nav-links { display: flex; align-items: center; gap: 24px; }
  .nav-links a {
    text-decoration: none; color: var(--ink-soft); font-size: 14px; font-weight: 500; transition: color 0.15s;
  }
  .nav-links a:hover { color: var(--accent); }
  .nav-actions { display: flex; align-items: center; gap: 10px; }
  .mobile-menu-btn {
    display: none; background: var(--surface); border: 1px solid var(--border);
    padding: 8px 10px; border-radius: 8px; cursor: pointer; color: var(--ink);
  }

  /* BUTTONS */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 11px 20px; border-radius: 9px; font-size: 14px; font-weight: 600;
    text-decoration: none; cursor: pointer; border: 1px solid transparent; transition: all 0.18s ease;
  }
  .btn-primary { background: var(--accent); color: #ffffff; box-shadow: 0 2px 6px rgba(29, 78, 216, 0.28); }
  .btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); }
  .btn-secondary { background: var(--surface); color: var(--ink); border-color: var(--border-strong); }
  .btn-secondary:hover { background: var(--surface-muted); }
  .btn-ghost { background: transparent; color: var(--ink-soft); }
  .btn-ghost:hover { color: var(--ink); background: var(--surface-muted); }
  .btn-sm { padding: 8px 14px; font-size: 13px; }
  .btn-lg { padding: 14px 26px; font-size: 15px; border-radius: 10px; }

  /* HERO */
  .hero {
    padding: 68px 0 56px;
    background: radial-gradient(circle at 82% 18%, rgba(29, 78, 216, 0.08), transparent 46%),
                radial-gradient(circle at 12% 80%, rgba(5, 150, 105, 0.06), transparent 42%);
    border-bottom: 1px solid var(--border);
  }
  .hero-grid { display: grid; grid-template-columns: 1.08fr 0.92fr; gap: 48px; align-items: center; }
  .eyebrow-pill {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 6px 14px; border-radius: 999px; font-size: 12px; font-weight: 700;
    letter-spacing: 0.04em; text-transform: uppercase;
    background: var(--accent-soft); color: var(--accent); border: 1px solid #BFDBFE;
    margin-bottom: 20px;
  }
  .hero h1 {
    font-size: clamp(2.2rem, 4.3vw, 3.35rem);
    line-height: 1.1; font-weight: 850; letter-spacing: -0.03em; color: var(--ink);
    margin-bottom: 18px;
  }
  .hero-sub {
    font-size: 18px; color: var(--ink-soft); max-width: 580px; margin-bottom: 28px; line-height: 1.6;
  }
  .hero-ctas { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }
  .hero-trust-notes { display: flex; flex-wrap: wrap; gap: 18px; font-size: 13px; color: var(--ink-muted); }
  .hero-trust-notes span { display: inline-flex; align-items: center; gap: 6px; }

  /* ANIMATED PRODUCT CANVAS CARD */
  .preview-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg); padding: 20px; position: relative; overflow: hidden;
  }
  .preview-top {
    display: flex; align-items: center; justify-content: space-between;
    padding-bottom: 12px; border-bottom: 1px solid var(--border); margin-bottom: 14px;
  }
  .preview-badge {
    font-size: 11px; font-weight: 700; color: var(--accent); background: var(--accent-soft);
    padding: 3px 9px; border-radius: 999px;
  }
  .flow-pulse { animation: pulseNode 3.2s infinite ease-in-out; }
  @keyframes pulseNode {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-3px); }
  }
  @media (prefers-reduced-motion: reduce) {
    .flow-pulse, .scan-line { animation: none !important; }
    html { scroll-behavior: auto; }
  }

  /* SECTIONS */
  .section { padding: 76px 0; }
  .section-alt { background: var(--surface); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
  .sec-head { max-width: 720px; margin-bottom: 40px; }
  .sec-head.center { margin-left: auto; margin-right: auto; text-align: center; }
  .sec-label {
    font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--accent); margin-bottom: 8px;
  }
  .sec-title {
    font-size: clamp(1.65rem, 2.8vw, 2.25rem); font-weight: 800; letter-spacing: -0.025em;
    color: var(--ink); margin-bottom: 12px; line-height: 1.2;
  }
  .sec-desc { font-size: 16px; color: var(--ink-soft); }

  /* QUICK CHECK BOX */
  .quick-check-box {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg);
    padding: 28px; box-shadow: var(--shadow-md);
  }
  .quick-form { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 14px; }
  .quick-form input {
    flex: 1; min-width: 240px; padding: 13px 16px; border: 1px solid var(--border-strong);
    border-radius: 9px; font-size: 15px; color: var(--ink); outline: none;
  }
  .quick-form input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.14); }
  .quick-results-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 12px; margin-top: 18px;
  }
  .q-pill {
    padding: 12px 14px; border: 1px solid var(--border); border-radius: 10px; background: var(--bg);
  }
  .q-pill-label { font-size: 12px; color: var(--ink-muted); margin-bottom: 4px; }
  .q-pill-val { font-size: 14px; font-weight: 700; }

  /* GRIDS & CARDS */
  .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 22px; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; }
  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; }

  .card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);
    padding: 24px; box-shadow: var(--shadow-sm); transition: box-shadow 0.2s, transform 0.2s;
  }
  .card:hover { box-shadow: var(--shadow-md); transform: translateY(-2px); }
  .step-tag {
    display: inline-block; font-size: 11px; font-weight: 800; letter-spacing: 0.08em;
    color: var(--accent); background: var(--accent-soft); padding: 4px 10px; border-radius: 6px; margin-bottom: 12px;
  }
  .card h3 { font-size: 18px; font-weight: 700; margin-bottom: 8px; color: var(--ink); }
  .card p { font-size: 14.5px; color: var(--ink-soft); }

  /* TIMELINE */
  .timeline-list { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .tl-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);
    padding: 20px; position: relative;
  }
  .tl-status {
    display: inline-block; font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; margin-bottom: 10px;
  }
  .tl-inforce { background: var(--emerald-soft); color: var(--emerald); }
  .tl-order { background: var(--accent-soft); color: var(--accent); }
  .tl-sched { background: var(--amber-soft); color: var(--amber); }

  /* TABLES */
  .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface); }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 14px 16px; border-bottom: 1px solid var(--border); }
  th { background: var(--surface-muted); font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--ink-soft); }
  tr:last-child td { border-bottom: none; }

  /* PRICING */
  .pricing-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; }
  .price-card {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);
    padding: 24px; display: flex; flex-direction: column; justify-content: space-between;
  }
  .price-card.featured { border-color: var(--accent); box-shadow: var(--shadow-md); position: relative; }
  .price-amount { font-size: 30px; font-weight: 850; color: var(--ink); margin: 10px 0 4px; }
  .price-period { font-size: 13px; color: var(--ink-muted); font-weight: 500; }
  .price-features { list-style: none; margin: 16px 0 22px; display: flex; flex-direction: column; gap: 9px; font-size: 13.5px; color: var(--ink-soft); }
  .price-features li::before { content: "✓ "; color: var(--emerald); font-weight: 700; }

  /* MODAL */
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(15, 23, 42, 0.55); z-index: 120;
    display: none; align-items: center; justify-content: center; padding: 20px;
  }
  .modal-backdrop.open { display: flex; }
  .modal-box {
    background: var(--surface); border-radius: var(--radius-lg); max-width: 520px; width: 100%;
    padding: 26px; box-shadow: var(--shadow-lg);
  }
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
  .form-group input, .form-group select, .form-group textarea {
    width: 100%; padding: 10px 12px; border: 1px solid var(--border-strong); border-radius: 8px; font-size: 14px; font-family: inherit;
  }

  /* FOOTER */
  .footer { background: var(--navy); color: #CBD5E1; padding: 56px 0 32px; }
  .footer a { color: #94A3B8; text-decoration: none; font-size: 13.5px; }
  .footer a:hover { color: #ffffff; }
  .footer-grid { display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; gap: 32px; margin-bottom: 36px; }
  .legal-strip {
    border-top: 1px solid rgba(255, 255, 255, 0.12); padding-top: 22px; font-size: 12.5px; color: #94A3B8; line-height: 1.65;
  }

  @media (max-width: 980px) {
    .hero-grid, .grid-3, .grid-4, .grid-2, .timeline-list, .pricing-grid, .footer-grid { grid-template-columns: 1fr; }
    .nav-links { display: none; }
    .mobile-menu-btn { display: inline-flex; }
    .nav-links.mobile-open {
      display: flex; flex-direction: column; position: absolute; top: 70px; left: 0; right: 0;
      background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; gap: 14px;
    }
  }
</style>
</head>
<body>

<header class="navbar">
  <div class="container nav-inner">
    <a href="/" class="brand">
      <div class="brand-mark">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <span>TrustAudit</span>
    </a>
    <nav class="nav-links" id="main-nav-links">
      <a href="#how-it-works">How It Works</a>
      <a href="#website-scanner">Website Scanner</a>
      <a href="#features">Features</a>
      <a href="#timeline">DPDP Law Timeline</a>
      <a href="#pricing">Pricing</a>
      <a href="/trust">Trust Centre</a>
      <a href="/demo">Interactive Demo</a>
    </nav>
    <div class="nav-actions">
      <a href="/dashboard" class="btn btn-secondary btn-sm">Sign In</a>
      <a href="/dashboard#onboarding" class="btn btn-primary btn-sm">Start Free Assessment</a>
      <button class="mobile-menu-btn" onclick="document.getElementById('main-nav-links').classList.toggle('mobile-open')" aria-label="Toggle Menu">&#9776;</button>
    </div>
  </div>
</header>

<!-- SECTION 1: HERO -->
<section class="hero">
  <div class="container hero-grid">
    <div>
      <div class="eyebrow-pill">
        <span>Built for Indian Businesses &bull; DPDP Act, 2023 Readiness</span>
      </div>
      <h1>Know What Happens to Your Customer Data.</h1>
      <p class="hero-sub">
        TrustAudit helps Indian businesses understand their DPDP readiness, organise customer data information, manage privacy tasks and keep important compliance evidence in one place.
      </p>
      <div class="hero-ctas">
        <a href="/dashboard" class="btn btn-primary btn-lg">Start My Free Assessment</a>
        <a href="#how-it-works" class="btn btn-secondary btn-lg">See How It Works</a>
      </div>
      <div class="hero-trust-notes">
        <span>&#10003; Plain everyday language first</span>
        <span>&#10003; Honest website gap check</span>
        <span>&#10003; Organised Evidence Vault &amp; PDF reports</span>
      </div>
    </div>

    <!-- Animated SVG Workspace Preview Card (explicitly labeled Example Preview) -->
    <div class="preview-card" aria-label="Example TrustAudit workspace workflow preview">
      <div class="preview-top">
        <strong style="font-size:14px;">DPDP Readiness &amp; Operations Flow</strong>
        <span class="preview-badge">Product Preview</span>
      </div>
      <svg viewBox="0 0 440 270" width="100%" height="auto" role="img" aria-label="Customer data discovery, website check, privacy notice, vendor tracking and evidence vault diagram">
        <defs>
          <linearGradient id="cardGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#EFF6FF"/>
            <stop offset="100%" stop-color="#ECFDF5"/>
          </linearGradient>
        </defs>
        <rect x="4" y="4" width="432" height="262" rx="14" fill="url(#cardGrad)" stroke="#CBD5E1"/>
        <!-- Connection lines -->
        <path d="M 122 66 L 168 66 M 272 66 L 318 66 M 220 96 L 220 132 M 122 162 L 168 162 M 272 162 L 318 162" stroke="#94A3B8" stroke-width="2" stroke-dasharray="4 4"/>
        <!-- Row 1 Nodes -->
        <g class="flow-pulse">
          <rect x="18" y="34" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#1D4ED8" stroke-width="1.5"/>
          <text x="70" y="59" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">1. Data List</text>
          <text x="70" y="76" text-anchor="middle" font-size="9.5" fill="#475569">What you collect</text>
        </g>
        <g class="flow-pulse" style="animation-delay:0.4s">
          <rect x="168" y="34" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#059669" stroke-width="1.5"/>
          <text x="220" y="59" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">2. Site Scan</text>
          <text x="220" y="76" text-anchor="middle" font-size="9.5" fill="#475569">Notices &amp; forms</text>
        </g>
        <g class="flow-pulse" style="animation-delay:0.8s">
          <rect x="318" y="34" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#1D4ED8" stroke-width="1.5"/>
          <text x="370" y="59" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">3. Notice Draft</text>
          <text x="370" y="76" text-anchor="middle" font-size="9.5" fill="#475569">Clear customer info</text>
        </g>
        <!-- Row 2 Nodes -->
        <g class="flow-pulse" style="animation-delay:1.2s">
          <rect x="18" y="132" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#64748B" stroke-width="1.2"/>
          <text x="70" y="157" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">4. Vendors</text>
          <text x="70" y="174" text-anchor="middle" font-size="9.5" fill="#475569">DPA contracts</text>
        </g>
        <g class="flow-pulse" style="animation-delay:1.6s">
          <rect x="168" y="132" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#D97706" stroke-width="1.5"/>
          <text x="220" y="157" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">5. Requests</text>
          <text x="220" y="174" text-anchor="middle" font-size="9.5" fill="#475569">View &amp; delete</text>
        </g>
        <g class="flow-pulse" style="animation-delay:2.0s">
          <rect x="318" y="132" width="104" height="62" rx="10" fill="#FFFFFF" stroke="#059669" stroke-width="1.5"/>
          <text x="370" y="157" text-anchor="middle" font-size="11.5" font-weight="700" fill="#0F172A">6. Evidence</text>
          <text x="370" y="174" text-anchor="middle" font-size="9.5" fill="#475569">PDF &amp; ZIP bundle</text>
        </g>
        <!-- Bottom Bar -->
        <rect x="18" y="212" width="404" height="38" rx="8" fill="#0B1221"/>
        <text x="220" y="235" text-anchor="middle" font-size="11" font-weight="600" fill="#E2E8F0">
          6-Step Setup Guide &bull; No False Compliance Claims &bull; Built for Teams
        </text>
      </svg>
    </div>
  </div>
</section>

<!-- SECTION 2: FREE WEBSITE PRIVACY QUICK CHECK -->
<section id="website-scanner" class="section">
  <div class="container">
    <div class="quick-check-box">
      <div class="sec-label">DPDP WEBSITE SCANNER</div>
      <h2 class="sec-title" style="font-size:26px;margin-bottom:6px;">Run a Quick Public Website Check</h2>
      <p class="sec-desc">Enter your business website URL to check HTTPS, HSTS header, Privacy Notice visibility, and privacy contact details safely.</p>
      <form class="quick-form" onsubmit="event.preventDefault(); runHomeQuickCheck();">
        <input type="text" id="home-quick-url" placeholder="https://yourbusiness.in" aria-label="Website URL to check"/>
        <button type="submit" class="btn btn-primary" id="home-quick-btn">Check Website Now</button>
        <a href="/dashboard#scanner" class="btn btn-secondary">Open Full Website Scanner</a>
      </form>
      <div id="home-quick-status" style="margin-top:12px;font-size:13.5px;color:var(--ink-soft);"></div>
      <div id="home-quick-results" class="quick-results-grid" style="display:none;"></div>
    </div>
  </div>
</section>

<!-- SECTION 3: HOW IT WORKS (DISCOVER / ASSESS / MANAGE) -->
<section id="how-it-works" class="section section-alt">
  <div class="container">
    <div class="sec-head center">
      <div class="sec-label">HOW TRUSTAUDIT WORKS</div>
      <h2 class="sec-title">Three Simple Steps to Organise Your Privacy Operations</h2>
      <p class="sec-desc">Designed so clinic administrators, founders, and operations managers can understand everything without reading a law book first.</p>
    </div>
    <div class="grid-3">
      <div class="card">
        <span class="step-tag">DISCOVER</span>
        <h3>Know Where Customer Data Lives</h3>
        <p>Understand what customer data you collect, where it lives and which companies you share it with.</p>
      </div>
      <div class="card">
        <span class="step-tag">ASSESS</span>
        <h3>Find Clear Gaps Early</h3>
        <p>Spot gaps in your website, notices, consent records and vendor agreements.</p>
      </div>
      <div class="card">
        <span class="step-tag">MANAGE</span>
        <h3>Stay Ready for Audits &amp; Requests</h3>
        <p>Track fixes, respond to customer requests and keep evidence ready.</p>
      </div>
    </div>
  </div>
</section>

<!-- SECTION 4: PLAIN-LANGUAGE MODULES -->
<section id="features" class="section">
  <div class="container">
    <div class="sec-head">
      <div class="sec-label">EVERYTHING IN ONE PLACE</div>
      <h2 class="sec-title">Built Around Real Daily Privacy Work — Not Confusing Spreadsheets</h2>
      <p class="sec-desc">Every screen answers three simple questions: What is this? Why does my business need it? What should I do next?</p>
    </div>
    <div class="grid-3">
      <div class="card">
        <h3>Customer Data List</h3>
        <p>Record what names, phone numbers, emails, IDs, bills, or medical records your business collects, where they live, and who handles them.</p>
      </div>
      <div class="card">
        <h3>Website Privacy Check</h3>
        <p>Safely inspect public pages and enquiry forms for missing Privacy Notices, pre-ticked checkboxes, and analytics or tracking scripts.</p>
      </div>
      <div class="card">
        <h3>Privacy Notice Generator</h3>
        <p>Draft, edit, approve, and export an itemised Privacy Notice matching your Customer Data List and Grievance contact details.</p>
      </div>
      <div class="card">
        <h3>Companies You Share Data With</h3>
        <p>Track software tools, cloud hosts, diagnostic labs, and payment gateways — along with contract statuses and renewal dates.</p>
      </div>
      <div class="card">
        <h3>Customer Privacy Requests</h3>
        <p>Handle requests to view, correct, or delete personal information cleanly with verification steps and clear activity records.</p>
      </div>
      <div class="card">
        <h3>Evidence Vault &amp; Reports</h3>
        <p>Store signed contracts, notice screenshots, retention policies, and security proof in one place, and download real PDF or ZIP bundles.</p>
      </div>
    </div>
  </div>
</section>

<!-- SECTION 5: WHO IT IS FOR -->
<section class="section section-alt">
  <div class="container">
    <div class="sec-head center">
      <div class="sec-label">BUILT FOR INDIAN BUSINESSES</div>
      <h2 class="sec-title">Ready-Made Templates for Your Sector</h2>
      <p class="sec-desc">Start fast with guided templates tailored to real Indian workflows.</p>
    </div>
    <div class="grid-4">
      <div class="card"><h3>Clinics &amp; Hospitals</h3><p>Patient intake, appointments, diagnostic test reports, and billing teams.</p></div>
      <div class="card"><h3>SaaS &amp; Software</h3><p>Account signups, API customers, analytics tools, and cloud hosting.</p></div>
      <div class="card"><h3>E-Commerce &amp; D2C</h3><p>Orders, delivery addresses, payment gateways, and marketing consent.</p></div>
      <div class="card"><h3>Schools &amp; EdTech</h3><p>Student enrolment, parent/guardian consent rules, and exam platforms.</p></div>
      <div class="card"><h3>Diagnostic Centres</h3><p>Home sample collection, lab software vendors, and WhatsApp reporting.</p></div>
      <div class="card"><h3>Finance &amp; Advisory</h3><p>KYC records, GST/tax documentation, and legal retention tracking.</p></div>
      <div class="card"><h3>Agencies &amp; Consultants</h3><p>Lead forms, CRM contacts, and client campaign vendor reviews.</p></div>
      <div class="card"><h3>HR &amp; Operations</h3><p>Employee payroll records under Section 7(i) and access control hygiene.</p></div>
    </div>
  </div>
</section>

<!-- SECTION 6: BEFORE VS AFTER -->
<section class="section">
  <div class="container">
    <div class="sec-head">
      <div class="sec-label">WHY TRUSTAUDIT</div>
      <h2 class="sec-title">Scattered Folders vs. One Calm Workspace</h2>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Daily Privacy Challenge</th><th>Spreadsheets &amp; Email Threads</th><th>With TrustAudit</th></tr>
        </thead>
        <tbody>
          <tr><td>Knowing where customer data lives</td><td>Hidden across reception registers, WhatsApp, and Excel files</td><td>Structured Customer Data List with CSV import/export and data flow map</td></tr>
          <tr><td>Vendor contracts &amp; agreements</td><td>Lost inside old inbox attachments</td><td>Companies I Share Data With tracker + linked contracts &amp; expiry dates</td></tr>
          <tr><td>Customer view/delete requests</td><td>Ad-hoc replies with no verification log</td><td>Tracked ticket log with requester verification &amp; outcome history</td></tr>
          <tr><td>Preparing audit proof</td><td>Days spent chasing screenshots &amp; PDFs</td><td>One-click real PDF Readiness Summary + ZIP Evidence Bundle</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</section>

<!-- SECTION 7: DPDP LAW TIMELINE (#timeline) -->
<section id="timeline" class="section section-alt">
  <div class="container">
    <div class="sec-head">
      <div class="sec-label">INDIAN LEGAL COMMENCEMENT TIMELINE</div>
      <h2 class="sec-title">DPDP Act, 2023 Effective Dates (Reference Date: 26 Nov 2026)</h2>
      <p class="sec-desc">Distinguishing what is already in force today from what is scheduled to take effect on 13 May 2027.</p>
    </div>
    <div class="timeline-list">
      <div class="tl-card">
        <span class="tl-status tl-inforce">In Force &bull; 13 Nov 2025</span>
        <h3>Board &amp; Institutional Setup</h3>
        <p style="font-size:13.5px;color:var(--ink-soft);">Sections 1, 2, 18&ndash;26, 33&ndash;35, and 40 commenced (Notification S.O. 4880(E)), establishing the Data Protection Board framework.</p>
      </div>
      <div class="tl-card">
        <span class="tl-status tl-order">Gazette Order &bull; Oct 2026</span>
        <h3>Removal of Difficulties Order</h3>
        <p style="font-size:13.5px;color:var(--ink-soft);">Central Government order aligning statutory text and cross-references for Sections 9 and 10 under the Act.</p>
      </div>
      <div class="tl-card">
        <span class="tl-status tl-inforce">In Force &bull; 13 Nov 2026</span>
        <h3>Consent Manager Provisions</h3>
        <p style="font-size:13.5px;color:var(--ink-soft);">Section 6(9), Section 27(1)(d), and Rule 4 commenced (S.O. 5122(E)) for DPBI-registered Consent Managers.</p>
      </div>
      <div class="tl-card">
        <span class="tl-status tl-sched">Scheduled &bull; 13 May 2027</span>
        <h3>Core Business Duties</h3>
        <p style="font-size:13.5px;color:var(--ink-soft);">Sections 3&ndash;17 &amp; Rules 3, 5&ndash;16, 22&ndash;23 (Notices, Consent, Security Safeguards, Breach Intimation, Retention, Children, Rights) scheduled.</p>
      </div>
    </div>
  </div>
</section>

<!-- SECTION 8: PENALTY SCHEDULE & SECTION 33 FACTORS -->
<section class="section">
  <div class="container">
    <div class="sec-head">
      <div class="sec-label">STATUTORY REFERENCE</div>
      <h2 class="sec-title">DPDP Act Schedule Maximum Ceilings</h2>
      <p class="sec-desc">Statutory maximum ceilings only — not automatic fines. Under Section 33, the Board evaluates 7 factors before determining any penalty.</p>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>DPDP Provision</th><th>Subject Matter</th><th>Schedule Maximum Ceiling</th></tr>
        </thead>
        <tbody>
          <tr><td><strong>Section 8(5)</strong></td><td>Reasonable security safeguards to prevent personal data breach</td><td><strong>Up to ₹250 crore</strong></td></tr>
          <tr><td><strong>Section 8(6)</strong></td><td>Failure to notify Data Protection Board / affected individuals of a breach</td><td><strong>Up to ₹200 crore</strong></td></tr>
          <tr><td><strong>Section 9</strong></td><td>Children's data obligations (parental consent, ban on tracking/targeted ads)</td><td><strong>Up to ₹200 crore</strong></td></tr>
          <tr><td><strong>Section 10</strong></td><td>Additional duties for notified Significant Data Fiduciaries</td><td><strong>Up to ₹150 crore</strong></td></tr>
          <tr><td><strong>Section 15</strong></td><td>Duties of Data Principal (e.g. false or frivolous complaints)</td><td><strong>Up to ₹10,000</strong></td></tr>
          <tr><td><strong>General (Item 6)</strong></td><td>Other provisions of the Act or Rules (Notices, Consent, Vendors, Retention, Rights)</td><td><strong>Up to ₹50 crore</strong></td></tr>
          <tr><td><strong>Section 32</strong></td><td>Failure to comply with an accepted Voluntary Undertaking</td><td><strong>Up to ceiling of underlying breach</strong></td></tr>
        </tbody>
      </table>
    </div>
    <p style="font-size:13px;color:var(--ink-muted);margin-top:12px;">
      Section 33(2) Factors Considered: (a) nature, gravity &amp; duration; (b) type of data affected; (c) repetitive nature; (d) gain realised or loss avoided; (e) mitigation timeliness; (f) proportionate deterrence; (g) likely financial impact.
    </p>
  </div>
</section>

<!-- SECTION 9: TRANSPARENT PRICING -->
<section id="pricing" class="section section-alt">
  <div class="container">
    <div class="sec-head center">
      <div class="sec-label">TRANSPARENT PRICING (INR)</div>
      <h2 class="sec-title">Simple Plans Matching Real Platform Capabilities</h2>
      <p class="sec-desc">Clear limits and genuine tools &mdash; zero inflated claims or hidden fees.</p>
    </div>
    <div class="pricing-grid" id="dynamic-pricing-grid">
      <div class="price-card">
        <div>
          <h3 style="font-size:18px;font-weight:700;">Free Community</h3>
          <div class="price-amount">&#8377;0 <span class="price-period">/ month</span></div>
          <p style="font-size:13px;color:var(--ink-soft);">Try TrustAudit for a single small website or clinic profile.</p>
          <ul class="price-features">
            <li>1 Website Privacy Check</li>
            <li>Up to 5 Customer Data Records</li>
            <li>Up to 5 Vendors Tracked</li>
            <li>1 Team Seat &amp; 10 Evidence Files</li>
            <li>PDF &amp; CSV Summary Export</li>
          </ul>
        </div>
        <a href="/dashboard" class="btn btn-secondary" style="width:100%;">Start Free</a>
      </div>
      <div class="price-card featured">
        <div>
          <span class="step-tag" style="margin-bottom:6px;">Starter Plan</span>
          <h3 style="font-size:18px;font-weight:700;">Starter</h3>
          <div class="price-amount">&#8377;999 <span class="price-period">/ month</span></div>
          <p style="font-size:13px;color:var(--ink-soft);">Built for growing Indian clinics, SMEs, and early teams.</p>
          <ul class="price-features">
            <li>Up to 5 Websites Scanned on Demand</li>
            <li>Up to 25 Customer Data Records</li>
            <li>Up to 25 Vendors &amp; Contracts</li>
            <li>Up to 3 Team Members &amp; 100 Evidence Files</li>
            <li>PDF Report, CSV &amp; ZIP Bundle</li>
          </ul>
        </div>
        <a href="/dashboard" class="btn btn-primary" style="width:100%;">Choose Starter</a>
      </div>
      <div class="price-card">
        <div>
          <h3 style="font-size:18px;font-weight:700;">Growth</h3>
          <div class="price-amount">&#8377;1,999 <span class="price-period">/ month</span></div>
          <p style="font-size:13px;color:var(--ink-soft);">For multi-system SaaS, EdTech, E-commerce &amp; Healthcare.</p>
          <ul class="price-features">
            <li>Up to 15 Websites Scanned on Demand</li>
            <li>Up to 100 Customer Data Records</li>
            <li>Up to 100 Vendors &amp; Contracts</li>
            <li>Up to 10 Team Members &amp; 500 Evidence Files</li>
            <li>Webhook Alerts &amp; 500 AI Queries/mo</li>
          </ul>
        </div>
        <a href="/dashboard" class="btn btn-secondary" style="width:100%;">Choose Growth</a>
      </div>
      <div class="price-card">
        <div>
          <h3 style="font-size:18px;font-weight:700;">Business</h3>
          <div class="price-amount">&#8377;2,999 <span class="price-period">/ month</span></div>
          <p style="font-size:13px;color:var(--ink-soft);">Multi-branch operations needing full audit logs &amp; capacity.</p>
          <ul class="price-features">
            <li>Up to 50 Websites &amp; Branches</li>
            <li>Up to 500 Customer Data Records &amp; Vendors</li>
            <li>Up to 25 Team Members (Admin/Member/Viewer)</li>
            <li>Up to 2,500 Evidence Files &amp; Audit Logs</li>
            <li>Priority Email Support &amp; 2,000 AI Queries/mo</li>
          </ul>
        </div>
        <a href="/dashboard" class="btn btn-secondary" style="width:100%;">Choose Business</a>
      </div>
    </div>
  </div>
</section>

<!-- SECTION 10: TRUST, SECURITY & GRIEVANCE -->
<section class="section">
  <div class="container">
    <div class="grid-2" style="align-items:center;">
      <div>
        <div class="sec-label">TRUST &amp; ACCOUNTABILITY</div>
        <h2 class="sec-title">Honest Security &amp; Privacy Practices</h2>
        <p class="sec-desc" style="margin-bottom:20px;">
          Review how TrustAudit hashes passwords (PBKDF2-HMAC-SHA256, 600,000 iterations), validates uploads, blocks SSRF attacks, and isolates tenant workspaces.
        </p>
        <div style="display:flex;gap:12px;flex-wrap:wrap;">
          <a href="/trust" class="btn btn-secondary">Visit Trust Centre</a>
          <button onclick="document.getElementById('grievance-modal').classList.add('open')" class="btn btn-secondary">Submit Privacy Grievance</button>
          <a href="/demo" class="btn btn-ghost">Try Interactive Demo</a>
        </div>
      </div>
      <div class="card">
        <h3 style="margin-bottom:10px;">Final Call to Action</h3>
        <p style="margin-bottom:18px;">Create an isolated workspace in minutes, walk through our 6-step plain-language onboarding, and download your readiness report whenever you need it.</p>
        <a href="/dashboard" class="btn btn-primary">Start My Free Assessment</a>
      </div>
    </div>
  </div>
</section>

<!-- GRIEVANCE MODAL -->
<div id="grievance-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-label="Submit Privacy Grievance">
  <div class="modal-box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
      <h3 style="font-size:18px;font-weight:700;">Submit a Privacy Grievance or Question</h3>
      <button onclick="document.getElementById('grievance-modal').classList.remove('open')" style="border:none;background:none;font-size:20px;cursor:pointer;">&times;</button>
    </div>
    <form onsubmit="event.preventDefault(); submitPublicGrievance();">
      <div class="form-group"><label>Your Name</label><input id="grv-name" required/></div>
      <div class="form-group"><label>Email</label><input id="grv-email" type="email" required/></div>
      <div class="form-group"><label>Category</label>
        <select id="grv-cat">
          <option>Privacy &amp; Personal Data Inquiry</option>
          <option>Data Correction or Deletion Request</option>
          <option>Security Concern</option>
        </select>
      </div>
      <div class="form-group"><label>Details</label><textarea id="grv-desc" rows="3" required></textarea></div>
      <div id="grv-status" style="font-size:13px;margin-bottom:10px;"></div>
      <button type="submit" class="btn btn-primary" style="width:100%;">Submit Request</button>
    </form>
  </div>
</div>

<footer class="footer">
  <div class="container">
    <div class="footer-grid">
      <div>
        <strong style="color:#fff;font-size:18px;">TrustAudit</strong>
        <p style="font-size:13.5px;color:#94A3B8;margin-top:8px;">DPDP Compliance &amp; Data Operations Platform for Indian Businesses.</p>
      </div>
      <div>
        <div style="color:#fff;font-weight:700;margin-bottom:10px;font-size:14px;">Product</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <a href="#how-it-works">How It Works</a>
          <a href="#website-scanner">Website Scanner</a>
          <a href="#pricing">Pricing</a>
          <a href="/demo">Interactive Demo</a>
        </div>
      </div>
      <div>
        <div style="color:#fff;font-weight:700;margin-bottom:10px;font-size:14px;">Law &amp; Governance</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <a href="#timeline">DPDP Commencement Timeline</a>
          <a href="/trust">Trust Centre</a>
          <a href="/.well-known/security.txt">security.txt</a>
        </div>
      </div>
      <div>
        <div style="color:#fff;font-weight:700;margin-bottom:10px;font-size:14px;">Contacts</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <a href="mailto:grievance@trustaudit.io">grievance@trustaudit.io</a>
          <a href="mailto:security@trustaudit.io">security@trustaudit.io</a>
        </div>
      </div>
    </div>
    <div class="legal-strip">
      <strong>Statutory Disclaimer:</strong> TrustAudit is an operational DPDP readiness and privacy management software tool. It is not a law firm, accredited auditor, government certification body, or registered statutory Consent Manager under Section 6(9). Substantive obligations under Sections 3&ndash;17 of the DPDP Act, 2023 are scheduled to commence on 13 May 2027. Always obtain qualified legal review before regulatory filings.
    </div>
  </div>
</footer>

<script>
  async function runHomeQuickCheck() {
    const input = document.getElementById('home-quick-url');
    const status = document.getElementById('home-quick-status');
    const results = document.getElementById('home-quick-results');
    const btn = document.getElementById('home-quick-btn');
    const url = (input.value || '').trim();
    if (!url) { status.textContent = 'Please enter a website URL first (e.g., https://example.com).'; return; }

    btn.disabled = true;
    status.textContent = 'Running safe public website check...';
    results.style.display = 'none';
    try {
      const res = await fetch('/api/public/quick-check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url})
      });
      const data = await res.json();
      const checks = data.checks || {};
      const items = [
        ['HTTPS Connection', checks.https || 'UNKNOWN'],
        ['TLS Check', checks.tls || 'UNKNOWN'],
        ['HSTS Header', checks.hsts || 'UNKNOWN'],
        ['Privacy Notice Link', checks.privacy_policy || 'UNKNOWN'],
        ['Privacy Contact Email', checks.privacy_contact || 'UNKNOWN']
      ];
      results.innerHTML = items.map(([k, v]) => {
        const good = (v === 'PASS' || v === 'CHECKED' || v === 'FOUND');
        const col = good ? 'var(--emerald)' : (v === 'BLOCKED' ? 'var(--rose)' : 'var(--amber)');
        return '<div class="q-pill"><div class="q-pill-label">' + k + '</div><div class="q-pill-val" style="color:' + col + '">' + v + '</div></div>';
      }).join('');
      results.style.display = 'grid';
      status.textContent = data.message || data.disclaimer || 'Check complete.';
    } catch (e) {
      status.textContent = 'Could not reach quick-check service. Please try again.';
    } finally {
      btn.disabled = false;
    }
  }

  async function submitPublicGrievance() {
    const st = document.getElementById('grv-status');
    st.textContent = 'Submitting...';
    try {
      const res = await fetch('/api/public/grievance/submit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          name: document.getElementById('grv-name').value,
          email: document.getElementById('grv-email').value,
          category: document.getElementById('grv-cat').value,
          description: document.getElementById('grv-desc').value
        })
      });
      const data = await res.json();
      st.style.color = res.ok ? 'var(--emerald)' : 'var(--rose)';
      st.textContent = data.reference_id ? ('Recorded. Reference ID: ' + data.reference_id) : (data.message || 'Submitted.');
    } catch (e) {
      st.style.color = 'var(--rose)';
      st.textContent = 'Error submitting request.';
    }
  }
</script>
</body>
</html>
"""
