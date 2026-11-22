DPDP_LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit | DPDP Compliance & Data Operations Platform for Indian Businesses</title>
    <meta name="description" content="Know where your customer data lives. Identify privacy gaps. Manage consent, vendors, deletion requests and privacy incidents from one platform. Built for the Digital Personal Data Protection Act, 2023.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060912;
            --bg-surface: #0a101f;
            --bg-card: #0f172a;
            --bg-card-hover: #152238;
            --border-subtle: #1e293b;
            --border-highlight: #38bdf8;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-cyan-glow: rgba(6, 182, 212, 0.25);
            --accent-indigo: #6366f1;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --accent-rose: #f43f5e;
            --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--font-sans);
            background: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 20%, rgba(99, 102, 241, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 85% 65%, rgba(6, 182, 212, 0.10) 0%, transparent 50%);
        }

        /* Utility */
        .container { max-width: 1240px; margin: 0 auto; padding: 0 1.5rem; }
        .badge-pill {
            display: inline-flex; align-items: center; gap: 0.5rem;
            padding: 0.35rem 0.95rem; border-radius: 999px;
            font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge-cyan { background: rgba(6, 182, 212, 0.12); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.3); }
        .badge-amber { background: rgba(245, 158, 11, 0.12); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-emerald { background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }

        .section-header { text-align: center; max-width: 780px; margin: 0 auto 3.5rem; }
        .section-eyebrow { font-size: 0.85rem; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.75rem; }
        .section-title { font-size: 2.25rem; font-weight: 800; letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 1rem; color: #ffffff; }
        .section-desc { font-size: 1.05rem; color: var(--text-secondary); line-height: 1.6; }

        /* Top Navigation */
        .header-nav {
            position: sticky; top: 0; z-index: 1000;
            background: rgba(6, 9, 18, 0.85); backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border-subtle);
        }
        .header-wrap {
            display: flex; align-items: center; justify-content: space-between;
            height: 72px;
        }
        .brand-link { display: flex; align-items: center; gap: 0.75rem; text-decoration: none; color: white; font-weight: 800; font-size: 1.25rem; }
        .brand-icon {
            width: 34px; height: 34px; border-radius: 8px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));
            display: flex; align-items: center; justify-content: center;
            color: white; font-weight: 900; box-shadow: 0 0 16px var(--accent-cyan-glow);
        }
        .nav-links { display: flex; align-items: center; gap: 2rem; list-style: none; }
        .nav-links a { color: var(--text-secondary); text-decoration: none; font-size: 0.9rem; font-weight: 600; transition: color 0.2s; }
        .nav-links a:hover { color: var(--text-primary); }
        .header-ctas { display: flex; align-items: center; gap: 1rem; }
        .btn {
            display: inline-flex; align-items: center; justify-content: center;
            padding: 0.6rem 1.25rem; border-radius: var(--radius-sm);
            font-size: 0.9rem; font-weight: 700; text-decoration: none;
            transition: all 0.2s; cursor: pointer;
        }
        .btn-outline { background: transparent; border: 1px solid var(--border-subtle); color: var(--text-primary); }
        .btn-outline:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); }
        .btn-primary {
            background: linear-gradient(135deg, #0ea5e9, #0284c7);
            color: white; border: none; box-shadow: 0 4px 16px rgba(2, 132, 199, 0.35);
        }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(2, 132, 199, 0.5); }

        /* 1. HERO SECTION */
        .hero-section { padding: 5rem 0 4rem; text-align: center; position: relative; }
        .hero-h1 {
            font-size: 3.5rem; font-weight: 800; letter-spacing: -0.03em;
            line-height: 1.15; margin: 1.5rem auto 1.25rem; max-width: 860px;
            background: linear-gradient(180deg, #ffffff 40%, #cbd5e1 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .hero-sub {
            font-size: 1.2rem; color: var(--text-secondary); max-width: 720px;
            margin: 0 auto 2.5rem; line-height: 1.6;
        }
        .hero-ctas { display: flex; align-items: center; justify-content: center; gap: 1.25rem; margin-bottom: 3.5rem; }
        .btn-lg { padding: 0.85rem 2rem; font-size: 1.05rem; border-radius: 10px; }

        /* Animated Dashboard Preview */
        .dashboard-preview {
            max-width: 1060px; margin: 0 auto;
            background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg); padding: 1.5rem;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 40px rgba(6, 182, 212, 0.08);
            position: relative; overflow: hidden;
        }
        .preview-topbar {
            display: flex; align-items: center; justify-content: space-between;
            padding-bottom: 1rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-subtle);
        }
        .preview-dots { display: flex; gap: 0.4rem; }
        .preview-dot { width: 10px; height: 10px; border-radius: 50%; background: #334155; }
        .preview-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.25rem; text-align: left; }
        @media(max-width: 768px) { .preview-grid { grid-template-columns: repeat(2, 1fr); } }
        .preview-card {
            background: var(--bg-card); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md); padding: 1.25rem;
        }
        .preview-kpi-num { font-size: 1.85rem; font-weight: 800; font-family: var(--font-mono); color: white; margin: 0.35rem 0 0.2rem; }
        .preview-kpi-label { font-size: 0.8rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }

        /* 2. CHALLENGES SECTION */
        .challenges-section { padding: 5rem 0; background: rgba(15, 23, 42, 0.25); border-top: 1px solid var(--border-subtle); }
        .challenges-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem; }
        .challenge-card {
            background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md); padding: 1.75rem; text-align: left;
            transition: all 0.2s;
        }
        .challenge-card:hover { border-color: rgba(244, 63, 94, 0.4); transform: translateY(-2px); }
        .challenge-icon { font-size: 1.75rem; margin-bottom: 1rem; }
        .challenge-title { font-size: 1.15rem; font-weight: 700; color: white; margin-bottom: 0.5rem; }
        .challenge-text { font-size: 0.9rem; color: var(--text-secondary); line-height: 1.55; }

        /* 3. PLATFORM OVERVIEW & JOURNEY */
        .journey-section { padding: 5rem 0; }
        .journey-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; }
        @media(max-width: 768px) { .journey-grid { grid-template-columns: 1fr; } }
        .journey-card {
            background: var(--bg-card); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg); padding: 2.25rem; text-align: left;
            position: relative; overflow: hidden;
        }
        .journey-step {
            font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700;
            color: var(--accent-cyan); background: rgba(6, 182, 212, 0.1);
            display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; margin-bottom: 1rem;
        }
        .journey-title { font-size: 1.35rem; font-weight: 800; color: white; margin-bottom: 0.75rem; }
        .journey-desc { font-size: 0.95rem; color: var(--text-secondary); line-height: 1.6; }

        /* 4. WEBSITE SCANNER DEMO */
        .scanner-section { padding: 5rem 0; background: rgba(6, 182, 212, 0.03); border-top: 1px solid var(--border-subtle); border-bottom: 1px solid var(--border-subtle); }
        .scanner-box {
            max-width: 880px; margin: 0 auto; background: var(--bg-card);
            border: 1px solid var(--border-subtle); border-radius: var(--radius-lg);
            padding: 2rem; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
        }
        .scanner-input-wrap {
            display: flex; gap: 0.75rem; margin-top: 1.5rem;
        }
        @media(max-width: 600px) { .scanner-input-wrap { flex-direction: column; } }
        .scanner-input {
            flex: 1; background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-sm); padding: 0.85rem 1.25rem;
            color: white; font-family: var(--font-mono); font-size: 0.95rem;
        }
        .scanner-input:focus { outline: none; border-color: var(--accent-cyan); }

        /* Bento Grid Modules (5 to 11) */
        .modules-section { padding: 5rem 0; }
        .bento-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.75rem; }
        @media(max-width: 900px) { .bento-grid { grid-template-columns: 1fr; } }
        .bento-card {
            background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg); padding: 2rem; text-align: left;
            transition: all 0.2s;
        }
        .bento-card:hover { border-color: rgba(6, 182, 212, 0.4); background: var(--bg-card-hover); }
        .bento-tag { font-size: 0.75rem; font-weight: 700; color: var(--accent-cyan); text-transform: uppercase; margin-bottom: 0.5rem; }
        .bento-title { font-size: 1.25rem; font-weight: 800; color: white; margin-bottom: 0.75rem; }
        .bento-desc { font-size: 0.9rem; color: var(--text-secondary); line-height: 1.6; margin-bottom: 1.25rem; }
        .bento-bullets { list-style: none; display: flex; flex-direction: column; gap: 0.4rem; font-size: 0.85rem; color: #cbd5e1; }
        .bento-bullets li::before { content: "✓ "; color: var(--accent-emerald); font-weight: 800; }

        /* 12. AI DPDP ASSISTANT */
        .assistant-section { padding: 5rem 0; background: rgba(99, 102, 241, 0.04); border-top: 1px solid var(--border-subtle); }
        .assistant-demo-card {
            max-width: 820px; margin: 0 auto; background: var(--bg-surface);
            border: 1px solid var(--border-subtle); border-radius: var(--radius-lg);
            padding: 2rem; text-align: left;
        }
        .chat-bubble-user {
            background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.35);
            border-radius: 12px 12px 2px 12px; padding: 1rem 1.25rem; margin-bottom: 1.25rem;
            max-width: 80%; margin-left: auto; font-size: 0.95rem; color: white;
        }
        .chat-bubble-ai {
            background: var(--bg-card); border: 1px solid var(--border-subtle);
            border-radius: 12px 12px 12px 2px; padding: 1.25rem;
            max-width: 90%; font-size: 0.9rem; color: #e2e8f0; line-height: 1.6;
        }

        /* 13. SECTOR CARDS */
        .sectors-section { padding: 5rem 0; }
        .sectors-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.5rem; }
        .sector-box {
            background: var(--bg-card); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md); padding: 1.75rem; text-align: left;
        }
        .sector-box:hover { border-color: var(--accent-cyan); }
        .sector-title { font-size: 1.15rem; font-weight: 700; color: white; margin-bottom: 0.5rem; }
        .sector-desc { font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; }

        /* 14. PRICING */
        .pricing-section { padding: 5rem 0; background: rgba(15, 23, 42, 0.3); border-top: 1px solid var(--border-subtle); }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; max-width: 1100px; margin: 0 auto; }
        @media(max-width: 850px) { .pricing-grid { grid-template-columns: 1fr; } }
        .pricing-card {
            background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg); padding: 2.5rem 2rem; text-align: left;
            position: relative;
        }
        .pricing-card.featured {
            border-color: var(--accent-cyan); box-shadow: 0 10px 40px rgba(6, 182, 212, 0.15);
        }
        .pricing-plan-name { font-size: 1.25rem; font-weight: 800; color: white; margin-bottom: 0.5rem; }
        .pricing-amount { font-size: 2.75rem; font-weight: 800; font-family: var(--font-mono); color: white; line-height: 1; }
        .pricing-period { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.5rem; }

        /* 15. FAQ */
        .faq-section { padding: 5rem 0; }
        .faq-grid { max-width: 860px; margin: 0 auto; display: flex; flex-direction: column; gap: 1.25rem; }
        .faq-item {
            background: var(--bg-surface); border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md); padding: 1.5rem; text-align: left;
        }
        .faq-q { font-size: 1.1rem; font-weight: 700; color: white; margin-bottom: 0.5rem; }
        .faq-a { font-size: 0.925rem; color: var(--text-secondary); line-height: 1.6; }

        /* 16. FINAL CTA & DISCLAIMER */
        .final-cta-section {
            padding: 5rem 0; text-align: center;
            background: linear-gradient(180deg, transparent, rgba(6, 182, 212, 0.06));
            border-top: 1px solid var(--border-subtle);
        }

        /* Footer */
        .site-footer {
            border-top: 1px solid var(--border-subtle); padding: 4rem 0 2rem;
            background: #04070d; font-size: 0.875rem; color: var(--text-muted);
        }
        .footer-grid { display: grid; grid-template-columns: 2fr repeat(3, 1fr); gap: 3rem; margin-bottom: 3rem; text-align: left; }
        @media(max-width: 768px) { .footer-grid { grid-template-columns: 1fr; } }
        .footer-col-title { font-weight: 700; color: white; margin-bottom: 1rem; }
        .footer-links { list-style: none; display: flex; flex-direction: column; gap: 0.6rem; }
        .footer-links a { color: var(--text-secondary); text-decoration: none; transition: color 0.2s; }
        .footer-links a:hover { color: white; }
        .footer-bottom { border-top: 1px solid #111a28; padding-top: 2rem; text-align: center; font-size: 0.8rem; }
    </style>
</head>
<body>

    <!-- TOP NAVIGATION -->
    <header class="header-nav">
        <div class="container header-wrap">
            <a href="/" class="brand-link">
                <div class="brand-icon">✓</div>
                <span>TrustAudit</span>
            </a>
            <ul class="nav-links">
                <li><a href="#overview">Overview</a></li>
                <li><a href="#scanner">Website Scanner</a></li>
                <li><a href="#features">Platform</a></li>
                <li><a href="#use-cases">Use Cases</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="/demo">60-Sec Demo</a></li>
                <li><a href="/trust">Trust Centre</a></li>
            </ul>
            <div class="header-ctas">
                <a href="/dashboard" class="btn btn-outline">Sign In</a>
                <a href="/dashboard" class="btn btn-primary">Start Free Assessment</a>
            </div>
        </div>
    </header>

    <main>
        <!-- 1. HERO SECTION -->
        <section class="hero-section">
            <div class="container">
                <div class="badge-pill badge-cyan">
                    <span>DPDP COMPLIANCE MANAGEMENT PLATFORM</span>
                </div>
                <h1 class="hero-h1">Take Control of Your Data Privacy.</h1>
                <p class="hero-sub">Understand your DPDP compliance gaps, discover how personal data moves through your business, and manage privacy operations from one platform.</p>
                <div class="hero-ctas">
                    <a href="/dashboard" class="btn btn-primary btn-lg">Start Free Assessment</a>
                    <a href="/demo" class="btn btn-outline btn-lg">Explore Platform</a>
                </div>

                <!-- Animated Dashboard Preview -->
                <div class="dashboard-preview">
                    <div class="preview-topbar">
                        <div class="preview-dots">
                            <div class="preview-dot"></div>
                            <div class="preview-dot"></div>
                            <div class="preview-dot"></div>
                        </div>
                        <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">trustaudit.io/dashboard</span>
                        <span class="badge-pill badge-emerald" style="font-size: 0.7rem;">Live Posture</span>
                    </div>
                    <div class="preview-grid">
                        <div class="preview-card">
                            <div class="preview-kpi-label">Readiness Posture</div>
                            <div class="preview-kpi-num" style="color: var(--accent-cyan);">78%</div>
                            <div style="font-size: 0.75rem; color: var(--accent-emerald);">Forward Target: May 2027</div>
                        </div>
                        <div class="preview-card">
                            <div class="preview-kpi-label">Mapped Data Streams</div>
                            <div class="preview-kpi-num">14</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">RoPA Records in Store</div>
                        </div>
                        <div class="preview-card">
                            <div class="preview-kpi-label">Active Vendors</div>
                            <div class="preview-kpi-num">8</div>
                            <div style="font-size: 0.75rem; color: var(--accent-amber);">2 DPAs Pending Review</div>
                        </div>
                        <div class="preview-card">
                            <div class="preview-kpi-label">Statutory Ceiling</div>
                            <div class="preview-kpi-num" style="color: var(--accent-rose); font-size: 1.5rem;">₹250 Cr</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted);">Sec 8(5) Schedule Max</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- 2. DPDP CHALLENGES FACED BY INDIAN BUSINESSES -->
        <section class="challenges-section">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">The DPDP Compliance Reality</div>
                    <h2 class="section-title">The DPDP Act Changes Everything for Indian Businesses</h2>
                    <p class="section-desc">With substantive business obligations commencing on 13 May 2027, organizations face unprecedented accountability requirements.</p>
                </div>
                <div class="challenges-grid">
                    <div class="challenge-card">
                        <div class="challenge-icon">🔍</div>
                        <h3 class="challenge-title">Unmapped Customer Data Sprawl</h3>
                        <p class="challenge-text">Personal data scattered across web forms, PostgreSQL databases, CRM tools, diagnostic PACS, and third-party SaaS vendors without formal RoPA records.</p>
                    </div>
                    <div class="challenge-card">
                        <div class="challenge-icon">📜</div>
                        <h3 class="challenge-title">Invalid Consent Mechanisms</h3>
                        <p class="challenge-text">Pre-ticked consent boxes, bundled terms, and generic English notices violate Section 6. The Act requires itemised, multilingual plain-language notices.</p>
                    </div>
                    <div class="challenge-card">
                        <div class="challenge-icon">⏱️</div>
                        <h3 class="challenge-title">Strict Breach Intimations</h3>
                        <p class="challenge-text">Section 8(6) mandates notifying the Data Protection Board and affected individuals upon personal data breaches. Missing an incident runbook invites statutory exposure.</p>
                    </div>
                    <div class="challenge-card">
                        <div class="challenge-icon">⚖️</div>
                        <h3 class="challenge-title">Schedule Penalty Ceilings</h3>
                        <p class="challenge-text">Statutory penalty ceilings up to ₹250 crore under the Schedule for failure to observe reasonable security safeguards under Section 8(5).</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- 3. TRUSTAUDIT PLATFORM OVERVIEW & 3-STAGE ROADMAP -->
        <section class="journey-section" id="overview">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Your DPDP Compliance Journey</div>
                    <h2 class="section-title">A Clear, Three-Stage Privacy Lifecycle</h2>
                    <p class="section-desc">From public perimeter discovery to internal operations and board-level governance.</p>
                </div>
                <div class="journey-grid">
                    <div class="journey-card">
                        <span class="journey-step">DISCOVER</span>
                        <h3 class="journey-title">Discover Privacy Gaps</h3>
                        <p class="journey-desc">Scan public-facing websites, intake forms, trackers, and database schemas to uncover observable DPDP gaps and map personal data streams.</p>
                    </div>
                    <div class="journey-card">
                        <span class="journey-step">ASSESS</span>
                        <h3 class="journey-title">Assess Statutory Posture</h3>
                        <p class="journey-desc">Evaluate controls against 15 core statutory requirements across the DPDP Act 2023, Rules 2025, and official commencement timelines.</p>
                    </div>
                    <div class="journey-card">
                        <span class="journey-step">MANAGE</span>
                        <h3 class="journey-title">Manage Privacy Operations</h3>
                        <p class="journey-desc">Execute DPAs with processors, fulfill Data Principal access and erasure requests, track retention limits, and maintain cryptographic evidence.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- 4. WEBSITE DPDP ASSESSMENT DEMONSTRATION -->
        <section class="scanner-section" id="scanner">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">DPDP Website Scanner</div>
                    <h2 class="section-title">Scan Your Website for Observable Privacy Gaps</h2>
                    <p class="section-desc">Instantly test public privacy notice availability, unbundled consent checkboxes, third-party analytics scripts, and Grievance Officer details.</p>
                </div>
                <div class="scanner-box">
                    <div style="font-size: 0.95rem; color: var(--text-secondary); text-align: left;">
                        Enter your website domain to perform a safe, non-invasive DPDP gap assessment:
                    </div>
                    <form class="scanner-input-wrap" onsubmit="event.preventDefault(); window.location.href='/dashboard#scanner';">
                        <input type="url" class="scanner-input" placeholder="https://yourclinic.in or https://yourcompany.com" required>
                        <button type="submit" class="btn btn-primary" style="padding: 0.85rem 1.75rem;">Run Free Website Scan →</button>
                    </form>
                    <div style="font-size: 0.8rem; color: var(--text-muted); text-align: left; margin-top: 1rem;">
                        ⚡ Non-invasive transport & DOM inspection. Adheres strictly to SSRF safeguards. Does not claim to certify internal database or backend processes.
                    </div>
                </div>
            </div>
        </section>

        <!-- BENTO MODULES: 5 TO 11 -->
        <section class="modules-section" id="features">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Core Platform Operations</div>
                    <h2 class="section-title">Built for Real Privacy & Data Operations</h2>
                    <p class="section-desc">Every tool an Indian business needs to transition from uncertainty to audit-ready DPDP governance.</p>
                </div>
                <div class="bento-grid">
                    <!-- 5. Data Inventory -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 01</div>
                        <h3 class="bento-title">Personal Data Inventory & RoPA</h3>
                        <p class="bento-desc">Create and maintain an exhaustive digital Record of Processing Activities (Rule 5(1)) with lawful grounds and storage systems.</p>
                        <ul class="bento-bullets">
                            <li>Pre-configured templates for 7 sectors</li>
                            <li>CSV import and export capabilities</li>
                            <li>Linked storage systems & processors</li>
                        </ul>
                    </div>

                    <!-- 6. Consent Operations -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 02</div>
                        <h3 class="bento-title">Consent & Withdrawal Operations</h3>
                        <p class="bento-desc">Manage purpose-specific consent records under Section 6 and trigger automated withdrawal cascades to all third-party processors.</p>
                        <ul class="bento-bullets">
                            <li>Unbundled affirmative consent logging</li>
                            <li>Bilingual notice linkage (Sec 5)</li>
                            <li>Processor withdrawal cascade tracking</li>
                        </ul>
                    </div>

                    <!-- 7. Vendor Management -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 03</div>
                        <h3 class="bento-title">Vendor & Processor Register</h3>
                        <p class="bento-desc">Govern third-party data processors under Section 8(2) with executed DPA contracts, security reviews, and operational risk ratings.</p>
                        <ul class="bento-bullets">
                            <li>6-status review lifecycle tracking</li>
                            <li>Subprocessor register & DPA repository</li>
                            <li>Configurable operational risk scoring</li>
                        </ul>
                    </div>

                    <!-- 8. Data Principal Requests -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 04</div>
                        <h3 class="bento-title">Data Principal Request Management</h3>
                        <p class="bento-desc">Track and resolve access, correction, erasure, grievance, and nomination requests under Sections 11–14 with audit trails.</p>
                        <ul class="bento-bullets">
                            <li>Identity verification workflows</li>
                            <li>Configurable SLA vs statutory deadlines</li>
                            <li>Comprehensive audit logging</li>
                        </ul>
                    </div>

                    <!-- 9. Retention & Deletion -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 05</div>
                        <h3 class="bento-title">Retention Schedules & Erasure</h3>
                        <p class="bento-desc">Document specific retention periods for all digital personal data categories and execute verified purpose-cessation deletion.</p>
                        <ul class="bento-bullets">
                            <li>Statutory legal exception linkage</li>
                            <li>Manual verification confirmation</li>
                            <li>Proof-of-scrub cryptographic hashes</li>
                        </ul>
                    </div>

                    <!-- 10. Breach Response -->
                    <div class="bento-card">
                        <div class="bento-tag">Module 06</div>
                        <h3 class="bento-title">Dual-Stage Breach Intimation</h3>
                        <p class="bento-desc">Orchestrate Section 8(6) incident response with pre-drafted Form A intimations to the Data Protection Board and plain-language customer notices.</p>
                        <ul class="bento-bullets">
                            <li>Dual-stage regulatory runbooks</li>
                            <li>Incident timeline & containment log</li>
                            <li>Affected Data Principal alerts</li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>

        <!-- 11. EVIDENCE VAULT -->
        <section style="padding: 2rem 0 5rem;">
            <div class="container">
                <div class="bento-card" style="background: linear-gradient(135deg, rgba(6, 182, 212, 0.08), rgba(99, 102, 241, 0.08));">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1.5rem;">
                        <div style="max-width: 680px;">
                            <div class="bento-tag">Module 07 — Compliance Evidence</div>
                            <h3 class="bento-title" style="font-size: 1.75rem;">Evidence Vault with 5-State Verification</h3>
                            <p class="bento-desc" style="font-size: 1rem;">
                                Eliminate self-attestation guesswork. Store cryptographically hashed policies, audit reports, vendor DPAs, and employee training records.
                            </p>
                            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-top: 1rem;">
                                <span class="badge-pill badge-cyan">Uploaded</span>
                                <span class="badge-pill badge-amber">Pending Review</span>
                                <span class="badge-pill badge-emerald">Verified</span>
                                <span class="badge-pill" style="background: rgba(244, 63, 94, 0.1); color: var(--accent-rose);">Rejected</span>
                                <span class="badge-pill" style="background: #1e293b; color: var(--text-muted);">Expired</span>
                            </div>
                        </div>
                        <a href="/dashboard" class="btn btn-primary" style="margin-top: 1rem;">Inspect Evidence Vault →</a>
                    </div>
                </div>
            </div>
        </section>

        <!-- 12. AI DPDP ASSISTANT -->
        <section class="assistant-section">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Statutory Intelligence</div>
                    <h2 class="section-title">Source-Grounded AI DPDP Assistant</h2>
                    <p class="section-desc">Get clear, plain-language guidance directly cited from the DPDP Act 2023, Rules 2025, and official gazette notifications.</p>
                </div>
                <div class="assistant-demo-card">
                    <div class="chat-bubble-user">
                        "What is our statutory penalty exposure if we do not obtain verifiable parental consent for our EdTech students?"
                    </div>
                    <div class="chat-bubble-ai">
                        <strong style="color: var(--accent-cyan);">Statutory Citation: Section 9 (Processing of Personal Data of Children)</strong><br><br>
                        Under Section 9(1), a Data Fiduciary must obtain verifiable consent from the parent or lawful guardian before processing any personal data of an individual under 18 years of age. Section 9(3) strictly prohibits tracking, behavioral monitoring, or targeted advertising directed at children.<br><br>
                        <strong style="color: var(--accent-rose);">Maximum Statutory Penalty Ceiling:</strong> Up to ₹250 crore (Schedule Item 3). Penalties are determined by the Board considering factors under Section 33.<br><br>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">Source: DPDP Act 2023 Section 9 & Schedule Item 3 &bull; Scheduled to commence 13 May 2027</span>
                    </div>
                    <div style="margin-top: 1.5rem; text-align: center;">
                        <a href="/dashboard" class="btn btn-outline">Ask AI Assistant in Dashboard →</a>
                    </div>
                </div>
            </div>
        </section>

        <!-- 13. INDUSTRY USE CASES -->
        <section class="sectors-section" id="use-cases">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Clinics, Diagnostic Centres &amp; Hospitals</div>
                    <h2 class="section-title">Sector-Specific Compliance Baselines</h2>
                    <p class="section-desc">Pre-configured inventory streams, retention periods, and priority controls tailored to your operational reality.</p>
                </div>
                <div class="sectors-grid">
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🏥</div>
                        <h3 class="sector-title">Hospitals & Clinics</h3>
                        <p class="sector-desc">Inpatient EHR, clinical charts, emergency treatment grounds (Sec 7(e)), TPA insurance data sharing, and Clinical Establishments Act retention.</p>
                    </div>
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🔬</div>
                        <h3 class="sector-title">Diagnostic Laboratories</h3>
                        <p class="sector-desc">Pathology reports, PACS radiology images, patient intake barcodes, doctor referral commissions, and 5-year NABL retention schedules.</p>
                    </div>
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">💻</div>
                        <h3 class="sector-title">SaaS & Technology Startups</h3>
                        <p class="sector-desc">User accounts, telemetry logs (180-day CERT-In retention), Stripe/Razorpay billing, and subprocessor registers.</p>
                    </div>
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🛒</div>
                        <h3 class="sector-title">E-Commerce & Retail</h3>
                        <p class="sector-desc">Delivery addresses, unbundled marketing consent, order ledgers, and logistics partner Data Processing Addenda.</p>
                    </div>
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">⚖️</div>
                        <h3 class="sector-title">Professional Services (CA & Legal)</h3>
                        <p class="sector-desc">Client KYC, director PAN details, confidential financial workpapers, and 8-year Income Tax Act retention schedules.</p>
                    </div>
                    <div class="sector-box">
                        <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">🎓</div>
                        <h3 class="sector-title">Education & EdTech</h3>
                        <p class="sector-desc">Minor student profiles, verifiable parental consent workflows under Section 9, campus access logs, and fee ledgers.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- 14. PRICING -->
        <section class="pricing-section" id="pricing">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Transparent Pricing</div>
                    <h2 class="section-title">Simple Subscription Plans for Indian Businesses</h2>
                    <p class="section-desc">Transparent monthly billing in Indian Rupees with zero hidden lock-ins.</p>
                </div>
                <div class="pricing-grid">
                    <!-- Starter Plan -->
                    <div class="pricing-card">
                        <div class="pricing-plan-name">Starter Plan</div>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.25rem;">Ideal for single-location clinics, early startups, and local practices.</p>
                        <div class="pricing-amount">₹999</div>
                        <div class="pricing-period">per month + GST</div>
                        <ul class="bento-bullets" style="margin-bottom: 2rem;">
                            <li>Up to 10 Personal Data Streams</li>
                            <li>Website DPDP Scanner (Monthly)</li>
                            <li>Standard Privacy Notice Generator</li>
                            <li>Grievance Officer Register</li>
                            <li>1 User Seat</li>
                        </ul>
                        <a href="/dashboard" class="btn btn-outline" style="width: 100%;">Select Starter Plan</a>
                    </div>

                    <!-- Growth Plan -->
                    <div class="pricing-card featured">
                        <div class="badge-pill badge-cyan" style="position: absolute; top: -14px; left: 24px;">Most Popular</div>
                        <div class="pricing-plan-name">Growth Plan</div>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.25rem;">For diagnostic centres, growing SaaS, and mid-sized healthcare providers.</p>
                        <div class="pricing-amount">₹1,999</div>
                        <div class="pricing-period">per month + GST</div>
                        <ul class="bento-bullets" style="margin-bottom: 2rem;">
                            <li>Up to 50 Personal Data Streams</li>
                            <li>Weekly Continuous Website Scanner</li>
                            <li>All 8 Statutory Document Generators</li>
                            <li>Vendor & Processor Management</li>
                            <li>Data Principal Rights (DSR) Portal</li>
                            <li>5 User Seats</li>
                        </ul>
                        <a href="/dashboard" class="btn btn-primary" style="width: 100%;">Select Growth Plan</a>
                    </div>

                    <!-- Business Plan -->
                    <div class="pricing-card">
                        <div class="pricing-plan-name">Business Plan</div>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.25rem;">For hospitals, e-commerce marketplaces, and large diagnostic chains.</p>
                        <div class="pricing-amount">₹2,999</div>
                        <div class="pricing-period">per month + GST</div>
                        <ul class="bento-bullets" style="margin-bottom: 2rem;">
                            <li>Unlimited Personal Data Streams</li>
                            <li>Daily Continuous Website Monitoring</li>
                            <li>Dual-Stage Breach Intimation Runbooks</li>
                            <li>Data Discovery & Data Flow Mapping</li>
                            <li>Evidence Vault with 5-State Verification</li>
                            <li>Dedicated Privacy Lead & Unlimited Seats</li>
                        </ul>
                        <a href="/dashboard" class="btn btn-outline" style="width: 100%;">Select Business Plan</a>
                    </div>
                </div>
            </div>
        </section>

        <!-- 15. FAQ -->
        <section class="faq-section" id="faq">
            <div class="container">
                <div class="section-header">
                    <div class="section-eyebrow">Got Questions?</div>
                    <h2 class="section-title">Frequently Asked Questions</h2>
                    <p class="section-desc">Clear answers regarding India's DPDP Act, 2023 and the TrustAudit platform.</p>
                </div>
                <div class="faq-grid">
                    <div class="faq-item">
                        <div class="faq-q">When does the DPDP Act come into full force for Indian businesses?</div>
                        <div class="faq-a">Preliminary institutional provisions commenced on 13 November 2025. Consent Manager registrations commenced on 13 November 2026. The substantive business obligations — including Section 5 notices, Section 6 consent, Section 8 security safeguards, and Section 8(6) breach notifications — are scheduled to commence on 13 May 2027.</div>
                    </div>
                    <div class="faq-item">
                        <div class="faq-q">Is TrustAudit a government certification body or law firm?</div>
                        <div class="faq-a">No. TrustAudit is an independent compliance management and data operations software platform. Neither MeitY nor the Data Protection Board of India certifies SaaS tools. Using TrustAudit does not constitute formal legal counsel or statutory immunity.</div>
                    </div>
                    <div class="faq-item">
                        <div class="faq-q">Are statutory penalties automatic fines?</div>
                        <div class="faq-a">No. Amounts such as ₹250 crore or ₹50 crore are statutory maximum ceilings specified in the Schedule to the DPDP Act. The Data Protection Board of India determines penalties through the statutory inquiry process, taking into account the nature, gravity, duration, repetitive nature of the violation, and mitigation measures under Section 33.</div>
                    </div>
                    <div class="faq-item">
                        <div class="faq-q">Does TrustAudit access or store our patients' raw medical records?</div>
                        <div class="faq-a">Never. TrustAudit operates strictly as a metadata and compliance workflow layer. It processes data inventory stream definitions, policies, vendor records, and proof-of-compliance artifacts. Zero raw patient health data or customer transaction records are stored on our servers.</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- 16. FINAL CTA -->
        <section class="final-cta-section">
            <div class="container">
                <h2 style="font-size: 2.5rem; font-weight: 800; color: white; margin-bottom: 1rem;">Take Control of Your DPDP Compliance Today</h2>
                <p style="font-size: 1.1rem; color: var(--text-secondary); max-width: 640px; margin: 0 auto 2.5rem;">
                    Join Indian clinics, hospitals, diagnostic labs, and SaaS companies building transparent, audit-ready data privacy practices.
                </p>
                <div style="display: flex; justify-content: center; gap: 1rem; flex-wrap: wrap;">
                    <a href="/dashboard" class="btn btn-primary btn-lg">Start Free Assessment</a>
                    <a href="/trust" class="btn btn-outline btn-lg">View Security & Trust Centre</a>
                </div>
            </div>
        </section>
    </main>

    <!-- FOOTER -->
    <footer class="site-footer">
        <div class="container">
            <div class="footer-grid">
                <div>
                    <a href="/" class="brand-link" style="margin-bottom: 1rem; display: inline-flex;">
                        <div class="brand-icon">✓</div>
                        <span>TrustAudit</span>
                    </a>
                    <p style="color: var(--text-secondary); line-height: 1.6; max-width: 320px;">
                        The DPDP Compliance & Data Operations Platform for Indian Startups, Healthcare Providers, and Growing Businesses.
                    </p>
                </div>
                <div>
                    <div class="footer-col-title">Platform</div>
                    <ul class="footer-links">
                        <li><a href="#scanner">DPDP Website Scanner</a></li>
                        <li><a href="#features">Data Inventory & RoPA</a></li>
                        <li><a href="#features">Vendor Management</a></li>
                        <li><a href="#features">Rights & Grievances</a></li>
                        <li><a href="/demo">60-Second Demo</a></li>
                    </ul>
                </div>
                <div>
                    <div class="footer-col-title">Legal & Trust</div>
                    <ul class="footer-links">
                        <li><a href="/trust">Security & Trust Centre</a></li>
                        <li><a href="/trust#statutory">Statutory Disclosures</a></li>
                        <li><a href="/trust#architecture">Zero-Patient-Data Guarantee</a></li>
                        <li><a href="mailto:grievance@trustaudit.io">grievance@trustaudit.io</a></li>
                        <li><a href="mailto:security@trustaudit.io">security@trustaudit.io</a></li>
                    </ul>
                </div>
                <div>
                    <div class="footer-col-title">Statutory Milestones</div>
                    <ul class="footer-links">
                        <li><span style="color: var(--accent-emerald);">●</span> 13 Nov 2025: Board Setup</li>
                        <li><span style="color: var(--accent-emerald);">●</span> 13 Nov 2026: Consent Mgrs</li>
                        <li><span style="color: var(--accent-cyan);">●</span> 13 May 2027: Substantive</li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2026 TrustAudit Technologies. All rights reserved. &bull; Designed strictly for India's Digital Personal Data Protection Act, 2023.</p>
                <p style="margin-top: 0.5rem; font-size: 0.75rem; color: #475569;">
                    Statutory penalty ceilings up to ₹250 crore are maximum amounts specified in the Schedule to the Act determined by the Data Protection Board of India on a case-by-case basis under Section 33. TrustAudit is an independent software tool and does not provide formal legal counsel or statutory certification.
                </p>
            </div>
        </div>
    </footer>

</body>
</html>
"""
