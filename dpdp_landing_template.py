"""
TrustAudit — DPDP Compliance Management Platform Landing Page
============================================================
Premium enterprise SaaS landing page inspired by Certinal, Linear, Stripe, Vanta, and Notion.
Features:
- Headline: "Your DPDP compliance, finally under control."
- Supporting text: "Discover privacy gaps, organise compliance evidence and turn complex DPDP requirements into clear actions your organisation can complete."
- Animated visual: Website → Privacy Assessment → Compliance Gaps → Evidence → Action Plan
- Redesigned interactive #timeline with 6 customer journey steps: Discover, Assess, Identify gaps, Collect evidence, Fix issues, Monitor progress
- 60-second interactive sample report demo (Phase 13)
- 7 Industry Use Cases: Hospitals, Clinics, Diagnostic centres, SaaS, E-commerce, Professional services, Education
- Pricing: Starter Plan (₹999/mo), Growth Plan (₹1,999/mo), Business Plan (₹2,999/mo)
- 8-step guided organisational assessment wizard modal
"""

DPDP_LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit — Your DPDP Compliance, Finally Under Control</title>
    <meta name="description" content="AI-assisted DPDP compliance assessment and management platform for Indian businesses, clinics, hospitals, startups, and e-commerce.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #f8fafc;
            --bg-surface: #ffffff;
            --bg-neutral: #f1f5f9;
            --bg-dark: #0f172a;
            --bg-dark-surface: #1e293b;
            --navy-dark: #0f172a;
            --text-primary: #0f172a;
            --text-secondary: #334155;
            --text-muted: #64748b;
            --text-light: #f8fafc;
            --border-subtle: #e2e8f0;
            --border-strong: #cbd5e1;
            --brand-primary: #1d4ed8;
            --brand-primary-hover: #1e40af;
            --brand-accent: #0284c7;
            --brand-emerald: #059669;
            --brand-amber: #d97706;
            --brand-rose: #dc2626;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 16px;
            --radius-xl: 24px;
            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.06), 0 1px 2px rgba(0, 0, 0, 0.04);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.08), 0 8px 10px -6px rgba(0, 0, 0, 0.04);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body { font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, sans-serif; background: #ffffff; color: var(--text-primary); line-height: 1.6; font-size: 14.5px; overflow-x: hidden; }
        a { color: inherit; text-decoration: none; }
        button { cursor: pointer; border: none; font-family: inherit; }

        .container { max-width: 1240px; margin: 0 auto; padding: 0 24px; width: 100%; }

        /* SITE NAV */
        .site-nav { position: fixed; top: 0; left: 0; right: 0; height: 72px; background: rgba(255, 255, 255, 0.92); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-subtle); z-index: 100; transition: all 0.2s; }
        .nav-inner { height: 100%; display: flex; align-items: center; justify-content: space-between; }
        .logo-wrap { display: flex; align-items: center; gap: 10px; font-weight: 850; font-size: 20px; color: var(--navy-dark); letter-spacing: -0.5px; }
        .logo-badge { font-size: 10px; font-weight: 700; background: #eff6ff; color: var(--brand-primary); padding: 3px 8px; border-radius: 9999px; border: 1px solid #bfdbfe; }
        
        .nav-links { display: flex; align-items: center; gap: 28px; list-style: none; font-size: 14px; font-weight: 600; color: var(--text-secondary); }
        .nav-links a:hover { color: var(--brand-primary); }
        .nav-actions { display: flex; align-items: center; gap: 12px; }

        /* BUTTONS */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 20px; border-radius: var(--radius-sm); font-weight: 600; font-size: 13.5px; transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1); }
        .btn-primary { background: var(--brand-primary); color: #ffffff; box-shadow: 0 2px 4px rgba(29, 78, 216, 0.2); }
        .btn-primary:hover { background: var(--brand-primary-hover); transform: translateY(-1px); box-shadow: 0 4px 8px rgba(29, 78, 216, 0.3); }
        .btn-secondary { background: #ffffff; color: var(--navy-dark); border: 1px solid var(--border-subtle); box-shadow: var(--shadow-sm); }
        .btn-secondary:hover { background: var(--bg-neutral); border-color: var(--border-strong); }
        .btn-magnetic { position: relative; transition: transform 0.15s ease-out; }

        /* HERO SECTION */
        .hero { position: relative; padding: 140px 0 90px 0; background: radial-gradient(circle at 50% 0%, #eff6ff 0%, #ffffff 65%); overflow: hidden; }
        .hero-spotlight { position: absolute; top: -150px; left: 50%; transform: translateX(-50%); width: 700px; height: 500px; background: radial-gradient(circle, rgba(29, 78, 216, 0.12) 0%, transparent 70%); pointer-events: none; z-index: 1; }
        .hero-grid { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 48px; align-items: center; position: relative; z-index: 2; }
        
        .eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: 11.5px; font-weight: 800; color: var(--brand-primary); text-transform: uppercase; letter-spacing: 1.2px; background: #eff6ff; padding: 6px 14px; border-radius: 9999px; border: 1px solid #dbeafe; margin-bottom: 20px; }
        .hero h1 { font-size: 50px; font-weight: 850; line-height: 1.12; color: var(--navy-dark); letter-spacing: -1.5px; margin-bottom: 20px; }
        .gradient-text { background: linear-gradient(135deg, var(--brand-primary) 0%, #0284c7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero-lead { font-size: 18px; color: var(--text-secondary); line-height: 1.55; margin-bottom: 32px; font-weight: 450; max-width: 580px; }
        
        .hero-btns { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 32px; }
        .hero-trust-strip { display: flex; gap: 24px; flex-wrap: wrap; font-size: 12.5px; font-weight: 600; color: var(--text-muted); border-top: 1px solid var(--border-subtle); padding-top: 20px; }
        .hero-trust-item { display: flex; align-items: center; gap: 6px; }

        /* ANIMATED PIPELINE VISUAL (PHASE 2 & 16) */
        .pipeline-flow-box { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 22px; box-shadow: var(--shadow-xl); margin-top: 24px; }
        .pipeline-steps { display: flex; align-items: center; justify-content: space-between; position: relative; }
        .pipeline-step-node { display: flex; flex-direction: column; align-items: center; gap: 6px; z-index: 2; }
        .node-icon-circle { width: 44px; height: 44px; border-radius: 50%; background: #eff6ff; border: 2px solid #bfdbfe; display: flex; align-items: center; justify-content: center; color: var(--brand-primary); transition: all 0.2s; }
        .node-icon-circle:hover { transform: scale(1.08); border-color: var(--brand-primary); }
        .node-label { font-size: 11px; font-weight: 700; color: var(--navy-dark); text-align: center; }
        .pipeline-connecting-line { position: absolute; top: 22px; left: 30px; right: 30px; height: 2px; background: linear-gradient(90deg, #bfdbfe, #38bdf8, #10b981); z-index: 1; }

        /* HERO PREVIEW CARD */
        .hero-mockup-card { background: #0f172a; border-radius: var(--radius-xl); border: 1px solid #1e293b; padding: 26px; box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.25); color: #ffffff; position: relative; overflow: hidden; }
        .mockup-topbar { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; border-bottom: 1px solid #1e293b; margin-bottom: 20px; }
        .mockup-dots { display: flex; gap: 6px; }
        .mockup-dot { width: 10px; height: 10px; border-radius: 50%; }
        .mockup-title { font-size: 12px; font-weight: 600; color: #94a3b8; display: flex; align-items: center; gap: 6px; }
        .mockup-pill { font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 9999px; }
        .pill-emerald { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .mockup-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px; }
        .mockup-box { background: #1e293b; border-radius: var(--radius-md); padding: 14px; }
        .mockup-box-lbl { font-size: 11px; font-weight: 600; color: #94a3b8; text-transform: uppercase; }
        .mockup-box-val { font-size: 22px; font-weight: 800; color: #ffffff; margin-top: 4px; }
        .mockup-action-card { background: #162238; border: 1px solid #1e3a5f; border-radius: var(--radius-md); padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }

        /* SECTIONS COMMON */
        .section-padding { padding: 96px 0; }
        .section-header { text-align: center; max-width: 720px; margin: 0 auto 56px auto; }
        .section-title { font-size: 34px; font-weight: 850; color: var(--navy-dark); letter-spacing: -0.8px; margin-bottom: 14px; }
        .section-subtext { font-size: 16px; color: var(--text-muted); line-height: 1.6; }

        /* HOW IT WORKS 3-STAGE TABS */
        .how-tabs { display: flex; justify-content: center; gap: 12px; margin-bottom: 40px; }
        .how-tab-btn { padding: 12px 28px; border-radius: 9999px; font-weight: 700; font-size: 14px; background: #f1f5f9; color: var(--text-secondary); border: 1px solid var(--border-subtle); transition: all 0.2s; }
        .how-tab-btn.active { background: var(--brand-primary); color: #ffffff; border-color: var(--brand-primary); box-shadow: var(--shadow-sm); }
        .how-panel { display: none; }
        .how-panel.active { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; align-items: center; }

        /* REDESIGNED HORIZONTAL #TIMELINE SECTION (PHASE 2) */
        .timeline-section { padding: 96px 0; background: #0f172a; color: #ffffff; position: relative; overflow: hidden; }
        .eyebrow-dark { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border-color: rgba(56, 189, 248, 0.25); }
        .section-title-dark { color: #ffffff; }
        .section-subtext-dark { color: #94a3b8; }
        
        .timeline-journey-track { display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px; margin: 40px 0; position: relative; }
        @media (max-width: 1024px) { .timeline-journey-track { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 640px) { .timeline-journey-track { grid-template-columns: 1fr; } }

        .t-step-card { background: #1e293b; border: 1px solid #334155; border-radius: var(--radius-lg); padding: 22px; display: flex; flex-direction: column; justify-content: space-between; transition: all 0.2s; position: relative; }
        .t-step-card:hover { border-color: #38bdf8; transform: translateY(-4px); box-shadow: 0 10px 20px rgba(0,0,0,0.3); }
        .t-step-num { font-size: 11px; font-weight: 800; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .t-step-card h4 { font-size: 16px; font-weight: 700; color: #ffffff; margin-bottom: 6px; }
        .t-step-card p { font-size: 12.5px; color: #94a3b8; line-height: 1.5; margin-bottom: 14px; }
        .t-step-deliverable { font-size: 11.5px; font-weight: 600; color: #34d399; background: rgba(16, 185, 129, 0.1); border-radius: var(--radius-sm); padding: 6px 10px; border-left: 3px solid #10b981; }

        /* INTERACTIVE 60-SECOND DEMO SECTION (PHASE 13) */
        .demo-section { padding: 96px 0; background: #ffffff; }
        .demo-box { background: #f8fafc; border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; box-shadow: var(--shadow-lg); }
        .demo-grid { display: grid; grid-template-columns: 1fr 1.3fr; gap: 32px; }
        @media (max-width: 900px) { .demo-grid { grid-template-columns: 1fr; } }
        
        .demo-finding-item { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 14px; margin-bottom: 10px; cursor: pointer; transition: all 0.15s; }
        .demo-finding-item:hover, .demo-finding-item.active { border-color: var(--brand-primary); box-shadow: var(--shadow-sm); transform: translateX(4px); }
        .demo-finding-item.active { border-left: 4px solid var(--brand-primary); }
        .demo-finding-header { display: flex; justify-content: space-between; align-items: center; }

        /* 7 INDUSTRY USE CASES (PHASE 9) */
        .ind-tabs { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; margin-bottom: 36px; }
        .ind-btn { padding: 8px 18px; border-radius: var(--radius-sm); font-size: 13px; font-weight: 600; background: var(--bg-neutral); color: var(--text-secondary); border: 1px solid var(--border-subtle); cursor: pointer; }
        .ind-btn.active { background: var(--navy-dark); color: #ffffff; border-color: var(--navy-dark); }
        .ind-panel { display: none; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 36px; box-shadow: var(--shadow-sm); }
        .ind-panel.active { display: grid; grid-template-columns: 1fr 1fr; gap: 36px; align-items: center; }
        @media (max-width: 768px) { .ind-panel.active { grid-template-columns: 1fr; } }

        /* PRICING PLANS (PHASE 14) */
        .pricing-section { padding: 96px 0; background: var(--bg-neutral); }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 28px; }
        @media (max-width: 900px) { .pricing-grid { grid-template-columns: 1fr; } }
        .pricing-card { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; display: flex; flex-direction: column; transition: all 0.2s; position: relative; }
        .pricing-card.featured { border-color: var(--brand-primary); box-shadow: var(--shadow-xl); transform: scale(1.02); }
        .featured-tag { position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: var(--brand-primary); color: #ffffff; font-size: 11px; font-weight: 700; padding: 4px 14px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px; }
        .plan-price { font-size: 38px; font-weight: 850; color: var(--navy-dark); line-height: 1; margin: 18px 0; }
        .plan-price span { font-size: 13.5px; font-weight: 500; color: var(--text-muted); }
        .plan-features { list-style: none; margin-bottom: 30px; flex-grow: 1; }
        .plan-features li { font-size: 13px; color: var(--text-secondary); margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }

        /* FOOTER */
        footer.site-footer { background: #070b14; border-top: 1px solid #1e293b; color: #94a3b8; padding: 72px 0 36px 0; font-size: 13px; }
        .footer-grid { display: grid; grid-template-columns: 1.5fr repeat(4, 1fr); gap: 36px; margin-bottom: 48px; }
        @media (max-width: 900px) { .footer-grid { grid-template-columns: 1fr 1fr; } }
        .footer-col h5 { font-size: 13.5px; font-weight: 700; color: #ffffff; margin-bottom: 16px; }
        .footer-col ul { list-style: none; }
        .footer-col li { margin-bottom: 10px; }
        .footer-col a:hover { color: #ffffff; }
        .footer-bottom { border-top: 1px solid #1e293b; padding-top: 28px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; font-size: 12px; }

        /* ONBOARDING MODAL (8 STEPS) */
        .modal-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(4px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.open { display: flex; }
        .modal-card { background: #ffffff; border-radius: var(--radius-xl); width: 100%; max-width: 650px; padding: 36px; box-shadow: var(--shadow-xl); position: relative; max-height: 90vh; overflow-y: auto; }
        .wizard-step { display: none; }
        .wizard-step.active { display: block; animation: fadeIn 0.2s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        .form-group { margin-bottom: 18px; }
        .form-label { display: block; font-size: 12.5px; font-weight: 700; color: var(--navy-dark); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 11px 14px; background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); font-size: 13.5px; font-family: inherit; }
        .form-control:focus { outline: none; border-color: var(--brand-primary); }
    </style>
</head>
<body>

    <!-- SITE NAV -->
    <nav class="site-nav">
        <div class="container nav-inner">
            <a href="/" class="logo-wrap">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>TrustAudit</span>
                <span class="logo-badge">DPDP Platform</span>
            </a>
            <ul class="nav-links">
                <li><a href="/dashboard#scanner" style="color: var(--brand-primary); font-weight: 700;">Website Scanner <span style="font-size: 10px; background: #dcfce7; color: #15803d; padding: 2px 6px; border-radius: 9999px;">NEW</span></a></li>
                <li><a href="#how-it-works">How It Works</a></li>
                <li><a href="#timeline">Timeline</a></li>
                <li><a href="#demo">Interactive Demo</a></li>
                <li><a href="#industries">Industries</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="/trust">Trust Centre</a></li>
            </ul>
            <div class="nav-actions">
                <a href="/dashboard" class="btn btn-secondary" style="padding: 8px 18px; font-size: 13.5px;">Sign In</a>
                <button onclick="openOnboardingModal()" class="btn btn-primary btn-magnetic" style="padding: 9px 20px; font-size: 13.5px;">Start Free Assessment</button>
            </div>
        </div>
    </nav>

    <!-- SECTION 1 — HERO SECTION -->
    <header class="hero">
        <div class="hero-spotlight" id="hero-spotlight"></div>
        <div class="container hero-grid">
            <div class="hero-content">
                <div class="eyebrow">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    DPDP COMPLIANCE MANAGEMENT PLATFORM
                </div>
                <h1>Your DPDP compliance, <span class="gradient-text">finally under control.</span></h1>
                <p class="hero-lead">
                    Discover privacy gaps, organise compliance evidence and turn complex DPDP requirements into clear actions your organisation can complete.
                </p>
                <div class="hero-btns">
                    <button onclick="openOnboardingModal()" class="btn btn-primary btn-magnetic">
                        <span>Start Free Assessment</span>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                    </button>
                    <a href="/dashboard#scanner" class="btn btn-secondary btn-magnetic" style="border-color: var(--brand-primary); color: var(--brand-primary); font-weight: 700;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/></svg>
                        <span>Scan Your Website &rarr;</span>
                    </a>
                    <a href="#how-it-works" class="btn btn-secondary">
                        <span>Explore How It Works</span>
                    </a>
                </div>
                <div class="hero-trust-strip">
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>Digital Personal Data Protection Act, 2023</span>
                    </div>
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>Clinics, Diagnostic Centres &amp; Hospitals</span>
                    </div>
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>Your DPDP Compliance Journey</span>
                    </div>
                </div>

                <!-- ANIMATED PIPELINE VISUAL -->
                <div class="pipeline-flow-box">
                    <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 12px; letter-spacing: 0.5px;">End-to-End Compliance Flow</div>
                    <div class="pipeline-steps">
                        <div class="pipeline-connecting-line"></div>
                        <div class="pipeline-step-node">
                            <div class="node-icon-circle">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/></svg>
                            </div>
                            <div class="node-label">Website</div>
                        </div>
                        <div class="pipeline-step-node">
                            <div class="node-icon-circle">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>
                            </div>
                            <div class="node-label">Privacy Assessment</div>
                        </div>
                        <div class="pipeline-step-node">
                            <div class="node-icon-circle">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                            </div>
                            <div class="node-label">Compliance Gaps</div>
                        </div>
                        <div class="pipeline-step-node">
                            <div class="node-icon-circle">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                            </div>
                            <div class="node-label">Evidence</div>
                        </div>
                        <div class="pipeline-step-node">
                            <div class="node-icon-circle">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                            </div>
                            <div class="node-label">Action Plan</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- INTERACTIVE DASHBOARD PREVIEW CARD -->
            <div class="hero-mockup-wrap">
                <div class="hero-mockup-card" id="hero-mockup-card">
                    <div class="mockup-topbar">
                        <div class="mockup-dots">
                            <span class="mockup-dot" style="background: #ef4444;"></span>
                            <span class="mockup-dot" style="background: #f59e0b;"></span>
                            <span class="mockup-dot" style="background: #10b981;"></span>
                        </div>
                        <div class="mockup-title">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>
                            <span>Arogya Diagnostics Clinic &bull; DPDP Command Centre</span>
                        </div>
                        <span class="mockup-pill pill-emerald">Readiness: 82%</span>
                    </div>

                    <div class="mockup-grid">
                        <div class="mockup-box">
                            <div class="mockup-box-lbl">Website Scanner</div>
                            <div class="mockup-box-val" style="color: #38bdf8;">Passed</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">4 Signals Verified &bull; 0 Pre-ticked Boxes</div>
                        </div>
                        <div class="mockup-box">
                            <div class="mockup-box-lbl">Data Streams (RoPA)</div>
                            <div class="mockup-box-val">18</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Patients, Lab Reports &amp; Billing</div>
                        </div>
                    </div>

                    <div class="mockup-action-card">
                        <div>
                            <div style="font-size: 10px; font-weight: 700; color: #f59e0b; text-transform: uppercase;">Top Attention Item</div>
                            <div style="font-weight: 600; font-size: 12.5px; color: #ffffff;">Add privacy notice link to appointment form</div>
                        </div>
                        <span class="btn btn-primary" style="padding: 5px 12px; font-size: 11px;">View and Fix</span>
                    </div>

                    <div class="mockup-action-card" style="margin-top: 8px;">
                        <div>
                            <div style="font-size: 10px; font-weight: 700; color: #34d399; text-transform: uppercase;">Verified Evidence</div>
                            <div style="font-weight: 600; font-size: 12.5px; color: #ffffff;">Clinic Itemised Privacy Notice v1.0 (Sec 5)</div>
                        </div>
                        <span class="mockup-pill pill-emerald">Active</span>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <!-- SECTION 2 — HOW TRUSTAUDIT WORKS (3-STAGE TABS) -->
    <section id="how-it-works" class="section-padding" style="background: #ffffff;">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow">HOW TRUSTAUDIT WORKS</span>
                <h2 class="section-title">From Public Discovery to Verified Governance</h2>
                <p class="section-subtext">A simple, structured three-stage methodology designed for healthcare providers, clinics, and businesses.</p>
            </div>

            <div class="how-tabs">
                <button class="how-tab-btn active" onclick="switchHowTab('discover', this)">1. DISCOVER</button>
                <button class="how-tab-btn" onclick="switchHowTab('assess', this)">2. ASSESS</button>
                <button class="how-tab-btn" onclick="switchHowTab('manage', this)">3. MANAGE</button>
            </div>

            <!-- TAB 1: DISCOVER -->
            <div id="how-discover" class="how-panel active">
                <div>
                    <h3 style="font-size: 26px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Understand What Personal Data Your Business Collects</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 20px;">
                        Our safe, read-only crawler discovers publicly visible intake forms, appointment portals, third-party trackers, and privacy policies. Simultaneously, pre-configured industry templates map your internal data processing activities into a structured Record of Processing Activities (RoPA).
                    </p>
                    <ul style="list-style: none; margin-bottom: 24px;">
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 1-Click passive website scanning (zero code changes)</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Pre-configured RoPA catalogs for 7 Indian industries</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Automated third-party analytics &amp; ad pixel detection</li>
                    </ul>
                    <a href="/dashboard#scanner" class="btn btn-primary">Start Website Discovery &rarr;</a>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px;">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark); margin-bottom: 12px;">Discovered Data Streams (Clinic RoPA)</h4>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Patient Demographics &amp; Phone</span>
                            <span style="font-weight: 700; color: var(--brand-primary);">Section 6 Consent</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Pathology Blood Reports (LIMS)</span>
                            <span style="font-weight: 700; color: var(--brand-emerald);">Section 7(e) Medical</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Billing Invoices &amp; TPA Claims</span>
                            <span style="font-weight: 700; color: var(--brand-accent);">Section 7(c) Legal</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 2: ASSESS -->
            <div id="how-assess" class="how-panel">
                <div>
                    <h3 style="font-size: 26px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Evaluate Statutory DPDP Controls &amp; Identify Gaps</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 20px;">
                        TrustAudit's deterministic rule engine tests your observable posture and internal governance against the DPDP Act 2023, Rules 2025, and official gazette commencement timelines.
                    </p>
                    <ul style="list-style: none; margin-bottom: 24px;">
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 15 evaluated statutory controls across 13 core categories</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Explicit distinction between In Force and Scheduled requirements</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Real-time coverage % and confidence level reporting</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-primary">Start Guided Assessment &rarr;</button>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px;">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark); margin-bottom: 12px;">Controls Status Matrix</h4>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Section 5 Notice in Plain Language</span>
                            <span style="color: var(--brand-amber); font-weight: 700;">Gap Identified</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Section 8(2) Vendor DPA Contracts</span>
                            <span style="color: var(--brand-amber); font-weight: 700;">Awaiting Sign-off</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Section 8(5) Encryption &amp; PBKDF2 MFA</span>
                            <span style="color: var(--brand-emerald); font-weight: 700;">Implemented</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 3: MANAGE -->
            <div id="how-manage" class="how-panel">
                <div>
                    <h3 style="font-size: 26px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Operational Privacy Management &amp; Evidence Vault</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 20px;">
                        Turn gaps into actionable remediation tasks. Generate legally aligned privacy notices, track customer privacy rights requests, cascade consent withdrawals to vendors, and store SHA-256 evidence in an AES-256 vault.
                    </p>
                    <ul style="list-style: none; margin-bottom: 24px;">
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 9 assisted document generation workflows with draft legal disclaimers</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Customer privacy requests desk with 72-hour SLA tracking</li>
                        <li style="display: flex; gap: 8px; margin-bottom: 8px; font-size: 13.5px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Auditor-ready PDF and JSON evidence packages</li>
                    </ul>
                    <a href="/dashboard" class="btn btn-primary">Open Compliance Workspace &rarr;</a>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px;">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark); margin-bottom: 12px;">Evidence &amp; Tasks Repository</h4>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Signed Diagnostic Lab DPA</span>
                            <span style="font-weight: 700; color: var(--brand-emerald);">Verified (SHA-256)</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>Section 5 Multi-Lingual Notice</span>
                            <span style="font-weight: 700; color: var(--brand-emerald);">Verified (SHA-256)</span>
                        </div>
                        <div style="background: #ffffff; padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; font-size: 12.5px;">
                            <span>VAPT Annual Assessment Cert</span>
                            <span style="font-weight: 700; color: var(--brand-emerald);">Verified (SHA-256)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 3 — REDESIGNED HORIZONTAL #TIMELINE SECTION (PHASE 2) -->
    <section id="timeline" class="timeline-section">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow eyebrow-dark">YOUR COMPLIANCE JOURNEY</span>
                <h2 class="section-title section-title-dark">The 6-Step Path to Verified DPDP Posture</h2>
                <p class="section-subtext section-subtext-dark">From initial discovery to continuous compliance monitoring, here is exactly what your organisation achieves.</p>
            </div>

            <div class="timeline-journey-track">
                <!-- Step 1: Discover -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 01 &bull; Discovery</div>
                        <h4>Discover</h4>
                        <p>Scan public website &amp; map all digital personal data collection touchpoints.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> Observable Data Inventory &amp; Tracker Register
                    </div>
                </div>

                <!-- Step 2: Assess -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 02 &bull; Assessment</div>
                        <h4>Assess</h4>
                        <p>Evaluate 15 statutory requirements against DPDP Act 2023 &amp; Rules 2025.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> Statutory Controls Matrix &amp; Readiness %
                    </div>
                </div>

                <!-- Step 3: Identify Gaps -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 03 &bull; Analysis</div>
                        <h4>Identify Gaps</h4>
                        <p>Pinpoint missing privacy notices, pre-ticked consent, and unexecuted vendor DPAs.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> Categorized Gap Report &amp; Priority Actions
                    </div>
                </div>

                <!-- Step 4: Collect Evidence -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 04 &bull; Evidence</div>
                        <h4>Collect Evidence</h4>
                        <p>Upload policies, signed processor contracts, and audit logs to AES-256 vault.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> Cryptographic SHA-256 Proof Repository
                    </div>
                </div>

                <!-- Step 5: Fix Issues -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 05 &bull; Remediation</div>
                        <h4>Fix Issues</h4>
                        <p>Assign tasks, generate legally aligned draft notices, and remediate gaps.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> 1-Click Draft Policies &amp; Task Desk
                    </div>
                </div>

                <!-- Step 6: Monitor Progress -->
                <div class="t-step-card">
                    <div>
                        <div class="t-step-num">Step 06 &bull; Governance</div>
                        <h4>Monitor Progress</h4>
                        <p>Continuous re-testing of web pages, change tracking, and Board exports.</p>
                    </div>
                    <div class="t-step-deliverable">
                        <strong>You Receive:</strong> Audit-Ready Reports &amp; Re-scan Alerts
                    </div>
                </div>
            </div>

            <!-- STATUTORY ROADMAP MINI STRIP -->
            <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: var(--radius-lg); padding: 22px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                <div>
                    <span style="font-size: 11px; font-weight: 700; color: #38bdf8; text-transform: uppercase;">Official Statutory Timeline</span>
                    <h4 style="font-size: 15px; font-weight: 700; color: #ffffff; margin-top: 2px;">DPDP Enforcement Milestones</h4>
                </div>
                <div style="display: flex; gap: 20px; font-size: 12px; color: #94a3b8; flex-wrap: wrap;">
                    <span>&bull; <strong>11 Aug 2023:</strong> Act Enacted</span>
                    <span>&bull; <strong>13 Nov 2025:</strong> Rules &amp; Board Active</span>
                    <span>&bull; <strong>13 Nov 2026:</strong> Consent Managers Commenced</span>
                    <span style="color: #38bdf8;">&bull; <strong>13 May 2027:</strong> General Obligations Scheduled</span>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 4 — INTERACTIVE 60-SECOND DEMO (PHASE 13) -->
    <section id="demo" class="demo-section">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow">INTERACTIVE DEMONSTRATION</span>
                <h2 class="section-title">Explore a 60-Second Sample Assessment</h2>
                <p class="section-subtext">See how TrustAudit uncovers observable privacy gaps and provides 1-click remediation actions on a sample healthcare website.</p>
            </div>

            <div class="demo-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 12px;">
                    <div>
                        <span style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Sample Target Domain</span>
                        <h3 style="font-size: 18px; font-weight: 800; color: var(--navy-dark);">https://arogyaclinic.in &bull; Healthcare Clinic</h3>
                    </div>
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <span style="font-size: 13px; color: var(--text-muted);">Simulated Readiness Posture:</span>
                        <strong style="font-size: 26px; font-weight: 850; color: var(--brand-primary);" id="demo-score">82%</strong>
                    </div>
                </div>

                <div class="demo-grid">
                    <div>
                        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 12px;">Observable Findings (Click to inspect)</div>
                        
                        <div class="demo-finding-item active" onclick="showDemoFinding(1, this)">
                            <div class="demo-finding-header">
                                <strong style="font-size: 13.5px; color: var(--navy-dark);">Missing Section 5 Notice on Patient Form</strong>
                                <span style="font-size: 11px; font-weight: 700; color: var(--brand-amber); background: #fef3c7; padding: 2px 8px; border-radius: 9999px;">HIGH</span>
                            </div>
                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 4px;">Appointment form collects phone &amp; age without notice link.</div>
                        </div>

                        <div class="demo-finding-item" onclick="showDemoFinding(2, this)">
                            <div class="demo-finding-header">
                                <strong style="font-size: 13.5px; color: var(--navy-dark);">Unbundled Consent Checkbox Present</strong>
                                <span style="font-size: 11px; font-weight: 700; color: var(--brand-emerald); background: #ecfdf5; padding: 2px 8px; border-radius: 9999px;">FOUND</span>
                            </div>
                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 4px;">Checkboxes are unticked by default conforming to Section 6.</div>
                        </div>

                        <div class="demo-finding-item" onclick="showDemoFinding(3, this)">
                            <div class="demo-finding-header">
                                <strong style="font-size: 13.5px; color: var(--navy-dark);">Third-Party Analytics Tracking Detected</strong>
                                <span style="font-size: 11px; font-weight: 700; color: var(--brand-accent); background: #eff6ff; padding: 2px 8px; border-radius: 9999px;">INPUT</span>
                            </div>
                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 4px;">Google Tag Manager script active; notice disclosure required.</div>
                        </div>

                        <div class="demo-finding-item" onclick="showDemoFinding(4, this)">
                            <div class="demo-finding-header">
                                <strong style="font-size: 13.5px; color: var(--navy-dark);">Diagnostic Cloud Storage DPA Contract</strong>
                                <span style="font-size: 11px; font-weight: 700; color: #64748b; background: #f1f5f9; padding: 2px 8px; border-radius: 9999px;">INTERNAL</span>
                            </div>
                            <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 4px;">AWS Mumbai hosting active; Section 8(2) DPA upload pending.</div>
                        </div>
                    </div>

                    <!-- FINDING DETAIL CARD -->
                    <div style="background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 24px;" id="demo-detail-card">
                        <span style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Finding Detail &bull; Section 5(1), Rule 3</span>
                        <h4 style="font-size: 18px; font-weight: 800; color: var(--navy-dark); margin: 6px 0 12px 0;" id="demo-detail-title">Missing Section 5 Notice on Appointment Form</h4>
                        
                        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">What Was Observed</div>
                        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;" id="demo-detail-obs">
                            The appointment registration page collects patient phone numbers and age but does not link a Section 5 privacy notice or state the Grievance Officer details.
                        </p>

                        <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Why It Matters</div>
                        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;" id="demo-detail-why">
                            Section 5 mandates that every consent request must be accompanied by an itemised notice in plain language describing processing purposes and rights.
                        </p>

                        <div style="background: #fef2f2; border: 1px solid #fee2e2; border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                            <div style="font-size: 12px; font-weight: 700; color: var(--brand-rose);">Statutory Penalty Exposure Ceiling: Up to ₹50 crore</div>
                            <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">Penalty amounts under the Schedule to the Act are statutory ceilings determined by the Board on a case-by-case basis. Not an automatic fine.</div>
                        </div>

                        <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-subtle); padding-top: 16px;">
                            <span style="font-size: 12px; color: var(--text-muted);">Required Evidence: <strong>Notice Wireframe &amp; Link</strong></span>
                            <button onclick="simulateDemoFix()" id="btn-demo-simulate" class="btn btn-primary btn-sm">
                                <span>Simulate Fix &rarr; Raise Posture to 94%</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 5 — 7 INDUSTRY USE CASES (PHASE 9) -->
    <section id="industries" class="section-padding" style="background: var(--bg-neutral);">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow">TAILORED FOR INDIA</span>
                <h2 class="section-title">Built for 7 Indian Industry Sectors</h2>
                <p class="section-subtext">Pre-configured RoPA data inventories, consent workflows, and vendor registers tailored to your industry.</p>
            </div>

            <div class="ind-tabs">
                <button class="ind-btn active" onclick="switchIndTab('hospitals', this)">Hospitals</button>
                <button class="ind-btn" onclick="switchIndTab('clinics', this)">Clinics</button>
                <button class="ind-btn" onclick="switchIndTab('diagnostic', this)">Diagnostic Centres</button>
                <button class="ind-btn" onclick="switchIndTab('saas', this)">SaaS Startups</button>
                <button class="ind-btn" onclick="switchIndTab('ecommerce', this)">E-Commerce</button>
                <button class="ind-btn" onclick="switchIndTab('prof', this)">Professional Services</button>
                <button class="ind-btn" onclick="switchIndTab('education', this)">Education</button>
            </div>

            <!-- HOSPITALS -->
            <div id="ind-hospitals" class="ind-panel active">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Hospitals &amp; Healthcare Networks</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">Manage inpatient records, surgical charts, emergency admissions under Section 7(e), health insurance TPA claims, and minor pediatric consent workflows.</p>
                    <ul style="list-style: none; font-size: 13px; color: var(--text-secondary);">
                        <li style="margin-bottom: 6px;">&bull; Emergency Medical Care Protocol under Section 7(e)</li>
                        <li style="margin-bottom: 6px;">&bull; Health Insurance TPA Data Processor Agreements</li>
                        <li style="margin-bottom: 6px;">&bull; Zero raw patient clinical charts ingested by TrustAudit</li>
                    </ul>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Inpatient EHR, TPA Claims, Emergency Triage, Minor Consent</div>
                </div>
            </div>

            <!-- CLINICS -->
            <div id="ind-clinics" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Outpatient Clinics &amp; Practices</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">For dental clinics, polyclinics, and doctors handling patient appointments, prescriptions, diagnostic referrals, and SMS reminders.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Patient Intake, Doctor Prescription Advice, SMS Gateways</div>
                </div>
            </div>

            <!-- DIAGNOSTIC -->
            <div id="ind-diagnostic" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Diagnostic Centres &amp; Labs</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">Pathology test orders, PACS imaging, home sample collection phlebotomy, and NABL-compliant retention rules.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Pathology Analyzers, Cloud PACS DICOM Scans, LIMS APIs</div>
                </div>
            </div>

            <!-- SAAS -->
            <div id="ind-saas" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">SaaS &amp; Tech Startups</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">User authentication, cloud subprocessor management (AWS/Render), billing via Stripe/Razorpay, and account deletion workflows.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">App User Accounts, Telemetry Logs, Subprocessor Register</div>
                </div>
            </div>

            <!-- ECOMMERCE -->
            <div id="ind-ecommerce" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">E-Commerce &amp; Retail Stores</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">Customer delivery addresses, checkout unbundled consent, logistics vendor contracts, and marketing opt-out mechanisms.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Checkout Shipping Addresses, Payment Webhooks, Courier DPAs</div>
                </div>
            </div>

            <!-- PROFESSIONAL SERVICES -->
            <div id="ind-prof" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Professional Services (Legal, CA, Advisory)</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">Client PAN/KYC records, tax advisory documents, employee payroll files, and engagement letter privacy addendums.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Client Financial Records, MCA Director KYC, Staff Payroll</div>
                </div>
            </div>

            <!-- EDUCATION -->
            <div id="ind-education" class="ind-panel">
                <div>
                    <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Education &amp; EdTech</h3>
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">Student admissions, verifiable parental consent under Section 9, ban on behavioral ad-tracking, and academic records.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 20px; border-radius: var(--radius-md);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Pre-Configured Streams</div>
                    <div style="font-weight: 700; color: var(--navy-dark); margin-top: 4px;">Minor Student Enrollment, Guardian Consents, School ERP Logs</div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 6 — PRICING PLANS (PHASE 14) -->
    <section id="pricing" class="pricing-section">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow">SIMPLE &amp; TRANSPARENT</span>
                <h2 class="section-title">Subscription Plans for Every Stage</h2>
                <p class="section-subtext">Clear, predictable pricing tailored to Indian startups, clinics, diagnostic chains, and institutions.</p>
            </div>

            <div class="pricing-grid">
                <div class="pricing-card">
                    <h3>Starter Plan</h3>
                    <p style="font-size: 13.5px; color: var(--text-muted);">For standalone clinics &amp; early startups</p>
                    <div class="plan-price">&#8377;999 <span>/ month (billed annually)</span></div>
                    <ul class="plan-features">
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Automated Website DPDP Scanner</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Up to 15 Data Inventory Streams</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Section 5 Privacy Notice Generator</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Customer Request Ticketing Desk</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-secondary">Get Started</button>
                </div>

                <div class="pricing-card featured">
                    <div class="featured-tag">Most Popular</div>
                    <h3>Growth Plan</h3>
                    <p style="font-size: 13.5px; color: var(--text-muted);">For diagnostic chains &amp; growing SaaS</p>
                    <div class="plan-price">&#8377;1,999 <span>/ month (billed annually)</span></div>
                    <ul class="plan-features">
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Everything in Starter, plus:</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Unlimited Data Inventory Streams</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Section 6(4) Consent Withdrawal Cascade</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Vendor &amp; DPA Contract Register</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> AES-256 Evidence Vault Storage</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-primary btn-magnetic">Start 14-Day Free Trial</button>
                </div>

                <div class="pricing-card">
                    <h3>Business Plan</h3>
                    <p style="font-size: 13.5px; color: var(--text-muted);">For hospital networks &amp; large institutions</p>
                    <div class="plan-price">&#8377;2,999 <span>/ month (or Custom Enterprise)</span></div>
                    <ul class="plan-features">
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Multi-Entity &amp; Branch Support</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Significant Data Fiduciary (SDF) Tools</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Dedicated DPO Support Channel</li>
                        <li><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Custom SLA &amp; Auditor Export Bundles</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-secondary">Get Business Plan</button>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 7 — FAQ -->
    <section class="section-padding" style="background: #ffffff;">
        <div class="container" style="max-width: 840px;">
            <div class="section-header">
                <span class="eyebrow">CLEAR ANSWERS</span>
                <h2 class="section-title">Frequently Asked Questions</h2>
            </div>

            <div style="display: flex; flex-direction: column; gap: 14px;">
                <div style="background: var(--bg-neutral); padding: 18px 22px; border-radius: var(--radius-md);">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark);">Does a website scan alone prove full DPDP compliance?</h4>
                    <p style="font-size: 13.5px; color: var(--text-secondary); margin-top: 6px;">No. A public website scan inspects observable indicators (privacy notices, forms, trackers, cookies, and technical headers). Full readiness requires internal RoPA mapping, staff training, and vendor DPAs.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 18px 22px; border-radius: var(--radius-md);">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark);">Does TrustAudit store raw medical or patient health records?</h4>
                    <p style="font-size: 13.5px; color: var(--text-secondary); margin-top: 6px;">Zero raw patient clinical records are ingested. TrustAudit manages compliance metadata, policies, and evidence contracts, never identifiable patient charts.</p>
                </div>
                <div style="background: var(--bg-neutral); padding: 18px 22px; border-radius: var(--radius-md);">
                    <h4 style="font-size: 15px; font-weight: 700; color: var(--navy-dark);">Are the statutory penalties under DPDP automatic fines?</h4>
                    <p style="font-size: 13.5px; color: var(--text-secondary); margin-top: 6px;">No. The Schedule to the Act sets statutory maximum penalty ceilings (up to ₹250 crore) which the Data Protection Board of India decides on a case-by-case basis considering mitigation and severity.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- FINAL CTA -->
    <section style="padding: 80px 0; background: linear-gradient(135deg, var(--navy-dark), #1e293b); color: #ffffff; text-align: center;">
        <div class="container" style="max-width: 720px;">
            <h2 style="font-size: 36px; font-weight: 850; letter-spacing: -1px; margin-bottom: 16px;">Get Your DPDP Compliance Under Control Today</h2>
            <p style="font-size: 16px; color: #94a3b8; margin-bottom: 28px;">Start with a free, safe website assessment or begin your full organisational compliance journey in minutes.</p>
            <div style="display: flex; justify-content: center; gap: 14px; flex-wrap: wrap;">
                <button onclick="openOnboardingModal()" class="btn btn-primary btn-magnetic" style="padding: 12px 28px; font-size: 14.5px;">Start Free Assessment &rarr;</button>
                <a href="/dashboard#scanner" class="btn btn-secondary" style="padding: 12px 28px; font-size: 14.5px;">Scan My Website</a>
            </div>
        </div>
    </section>

    <!-- FOOTER -->
    <footer class="site-footer">
        <div class="container">
            <div class="footer-grid">
                <div class="footer-col">
                    <div style="display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 18px; color: #ffffff; margin-bottom: 12px;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        <span>TrustAudit</span>
                    </div>
                    <p style="font-size: 12.5px; line-height: 1.6; color: #94a3b8;">
                        AI-assisted DPDP compliance assessment and management platform for Indian businesses, clinics, and technology enterprises.
                    </p>
                </div>
                <div class="footer-col">
                    <h5>Platform</h5>
                    <ul>
                        <li><a href="/dashboard#scanner">Website Scanner</a></li>
                        <li><a href="/dashboard#assessment">Statutory Controls</a></li>
                        <li><a href="/dashboard#inventory">Data Inventory (RoPA)</a></li>
                        <li><a href="/dashboard#evidence">Evidence Vault</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h5>Industries</h5>
                    <ul>
                        <li><a href="#industries">Hospitals &amp; Healthcare</a></li>
                        <li><a href="#industries">Clinics &amp; Diagnostics</a></li>
                        <li><a href="#industries">SaaS &amp; Tech Startups</a></li>
                        <li><a href="#industries">E-Commerce &amp; Retail</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h5>Resources</h5>
                    <ul>
                        <li><a href="/trust">Security &amp; Trust Centre</a></li>
                        <li><a href="#timeline">Compliance Timeline</a></li>
                        <li><a href="#how-it-works">How It Works</a></li>
                        <li><a href="#pricing">Pricing Plans</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h5>Legal &amp; Trust</h5>
                    <ul>
                        <li><a href="/trust">Zero Patient Data Policy</a></li>
                        <li><a href="/trust">Multi-Tenant Isolation</a></li>
                        <li><a href="/trust">Grievance Desk (DPO)</a></li>
                        <li><a href="/.well-known/security.txt">security.txt</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <div>&copy; 2026 TrustAudit Technologies. All rights reserved. Built for India DPDP Act 2023 &amp; Rules 2025.</div>
                <div style="font-size: 11.5px; color: #64748b;">Not a government-issued statutory certification. Posture metrics represent self-attested &amp; verified compliance tracking.</div>
            </div>
        </div>
    </footer>

    <!-- 8-STEP GUIDED ONBOARDING MODAL (PHASE 5) -->
    <div id="onboardingModal" class="modal-overlay">
        <div class="modal-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid var(--border-subtle);">
                <div>
                    <span style="font-size: 11px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;" id="wizard-step-label">Step 1 of 3 &bull; Basic Scope</span>
                    <h3 style="font-size: 18px; font-weight: 800; color: var(--navy-dark);" id="wizard-title">Start Your Free DPDP Assessment</h3>
                </div>
                <button onclick="closeOnboardingModal()" style="background: none; font-size: 22px; color: var(--text-muted); cursor: pointer;">&times;</button>
            </div>

            <!-- STEP 1: ORGANISATION PROFILE -->
            <div id="step-1" class="wizard-step active">
                <div class="form-group">
                    <label class="form-label">Business / Clinic Legal Name *</label>
                    <input type="text" id="ob-biz-name" class="form-control" placeholder="e.g. Arogya Diagnostics Clinic Ltd" value="Arogya Diagnostics Clinic">
                </div>
                <div class="form-group">
                    <label class="form-label">Public Website URL *</label>
                    <input type="url" id="ob-biz-url" class="form-control" placeholder="https://yourclinic.in" value="https://arogyaclinic.in">
                </div>
                <div class="form-group">
                    <label class="form-label">Primary Industry Sector *</label>
                    <select id="ob-biz-industry" class="form-control">
                        <option value="hospitals">Hospitals &amp; Healthcare Networks</option>
                        <option value="clinics" selected>Outpatient Clinics &amp; Medical Practices</option>
                        <option value="diagnostic_centres">Diagnostic Centres &amp; Pathology Labs</option>
                        <option value="saas">SaaS &amp; Technology Startups</option>
                        <option value="ecommerce">E-Commerce &amp; Online Retail</option>
                        <option value="professional_services">Professional Services (Legal, CA, Advisory)</option>
                        <option value="education">Education &amp; EdTech</option>
                    </select>
                </div>
                <div style="display: flex; justify-content: flex-end; margin-top: 24px;">
                    <button type="button" onclick="goToStep(2)" class="btn btn-primary">Next: Data Collection &rarr;</button>
                </div>
            </div>

            <!-- STEP 2: DATA COLLECTION SCOPE -->
            <div id="step-2" class="wizard-step">
                <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 14px;">Select the categories of digital personal data your organization collects:</div>
                <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px;">
                    <label style="display: flex; align-items: center; gap: 10px; font-size: 13px; cursor: pointer;">
                        <input type="checkbox" id="ob-col-patients" checked style="accent-color: var(--brand-primary); width: 16px; height: 16px;">
                        <span>Patients / Clients / Customer Records (Names, Phones, Emails, IDs)</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px; font-size: 13px; cursor: pointer;">
                        <input type="checkbox" id="ob-col-clinical" checked style="accent-color: var(--brand-primary); width: 16px; height: 16px;">
                        <span>Clinical Diagnostic Reports / Prescription Records / Financial Invoices</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px; font-size: 13px; cursor: pointer;">
                        <input type="checkbox" id="ob-col-minors" checked style="accent-color: var(--brand-primary); width: 16px; height: 16px;">
                        <span>Children's / Minor Records under 18 (Section 9 Verifiable Consent applies)</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px; font-size: 13px; cursor: pointer;">
                        <input type="checkbox" id="ob-col-employees" checked style="accent-color: var(--brand-primary); width: 16px; height: 16px;">
                        <span>Employee / Doctor / Staff Payroll &amp; Credential Records (Section 7(i))</span>
                    </label>
                </div>
                <div style="display: flex; justify-content: space-between; margin-top: 24px;">
                    <button type="button" onclick="goToStep(1)" class="btn btn-secondary">&larr; Back</button>
                    <button type="button" onclick="goToStep(3)" class="btn btn-primary">Next: Start Assessment &rarr;</button>
                </div>
            </div>

            <!-- STEP 3: READY TO ASSESS -->
            <div id="step-3" class="wizard-step">
                <div style="text-align: center; padding: 20px 0;">
                    <div style="width: 56px; height: 56px; border-radius: 50%; background: #ecfdf5; border: 2px solid #10b981; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px auto; color: #059669;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    </div>
                    <h4 style="font-size: 18px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px;">TrustAudit Is Ready To Assess Your Posture</h4>
                    <p style="font-size: 13.5px; color: var(--text-muted); max-width: 480px; margin: 0 auto 20px auto;">
                        We will initialize your pre-configured industry RoPA inventory, evaluate 15 statutory requirements, and scan your website for observable privacy gaps.
                    </p>
                    <div style="background: var(--bg-neutral); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 24px; font-size: 12px; color: var(--text-secondary);">
                        &bull; Zero code installation required &bull; Read-only passive analysis &bull; Zero raw patient data collection
                    </div>
                    <button type="button" onclick="submitOnboardingAndLaunch()" class="btn btn-primary btn-magnetic" style="padding: 12px 32px; font-size: 14px;">
                        <span>Launch Assessment Workspace &rarr;</span>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- SCRIPT LOGIC -->
    <script>
        // MOUSE-RESPONSIVE MOTION (PHASE 10 & 16)
        const spotlight = document.getElementById('hero-spotlight');
        const heroCard = document.getElementById('hero-mockup-card');

        if (window.matchMedia('(prefers-reduced-motion: no-preference)').matches) {
            window.addEventListener('mousemove', (e) => {
                if (spotlight) {
                    const x = e.clientX;
                    const y = e.clientY + window.scrollY;
                    spotlight.style.transform = `translate(${x - window.innerWidth / 2}px, ${y * 0.2}px)`;
                }
                if (heroCard) {
                    const rect = heroCard.getBoundingClientRect();
                    const cardX = e.clientX - rect.left - rect.width / 2;
                    const cardY = e.clientY - rect.top - rect.height / 2;
                    if (Math.abs(cardX) < 500 && Math.abs(cardY) < 500) {
                        heroCard.style.transform = `perspective(1000px) rotateY(${cardX * 0.02}deg) rotateX(${-cardY * 0.02}deg)`;
                    }
                }
            });
        }

        // 3-STAGE TABS
        function switchHowTab(stage, btn) {
            document.querySelectorAll('.how-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.how-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById('how-' + stage);
            if (target) target.classList.add('active');
        }

        // 7 INDUSTRY TABS
        function switchIndTab(ind, btn) {
            document.querySelectorAll('.ind-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ind-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById('ind-' + ind);
            if (target) target.classList.add('active');
        }

        // DEMO FINDINGS
        const demoData = {
            1: {
                title: "Missing Section 5 Notice on Patient Form",
                citation: "Finding Detail &bull; Section 5(1), Rule 3",
                obs: "The appointment registration page collects patient phone numbers and age but does not link a Section 5 privacy notice or state Grievance Officer details.",
                why: "Section 5 mandates that every consent request must be accompanied by an itemised notice in plain language describing processing purposes and rights.",
                penalty: "Statutory Penalty Exposure Ceiling: Up to ₹50 crore",
                evidence: "Notice Wireframe & Link"
            },
            2: {
                title: "Unbundled Consent Checkbox Present",
                citation: "Finding Detail &bull; Sections 4 & 6, Rule 3",
                obs: "Consent checkboxes for appointment updates are unticked by default and not bundled into Terms of Service.",
                why: "Section 6 mandates that consent must be affirmative, unbundled, free, and specific to be legally valid.",
                penalty: "Statutory Posture: Compliant control implemented",
                evidence: "Wireframe & Checkbox DOM State"
            },
            3: {
                title: "Third-Party Analytics Tracking Detected",
                citation: "Finding Detail &bull; Section 5(1) & Rule 3 Disclosures",
                obs: "Google Tag Manager script active on patient appointment pages without prior disclosure in privacy notice.",
                why: "Under DPDP Section 5, notice must inform Data Principals about all third parties and processors receiving personal data.",
                penalty: "Statutory Penalty Exposure Ceiling: Up to ₹50 crore",
                evidence: "Script Source & Cookie Audit Log"
            },
            4: {
                title: "Diagnostic Cloud Storage DPA Contract",
                citation: "Finding Detail &bull; Section 8(1)-(2), Rule 5",
                obs: "AWS Mumbai cloud storage hosting patient records requires executed Data Processing Agreement with Section 8(2) clauses.",
                why: "The Data Fiduciary remains accountable for all processing by Data Processors and may engage them only under valid contract.",
                penalty: "Statutory Penalty Exposure Ceiling: Up to ₹50 crore",
                evidence: "Executed Vendor DPA Contract"
            }
        };

        function showDemoFinding(id, el) {
            document.querySelectorAll('.demo-finding-item').forEach(i => i.classList.remove('active'));
            el.classList.add('active');
            const d = demoData[id];
            if (!d) return;
            document.getElementById('demo-detail-title').textContent = d.title;
            document.getElementById('demo-detail-obs').textContent = d.obs;
            document.getElementById('demo-detail-why').textContent = d.why;
        }

        function simulateDemoFix() {
            const btn = document.getElementById('btn-demo-simulate');
            btn.innerHTML = '<span>Issue Remediated &bull; Notice Draft Generated &#10003;</span>';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-secondary');
            document.getElementById('demo-score').textContent = '94%';
            document.getElementById('demo-score').style.color = '#059669';
        }

        // ONBOARDING WIZARD MODAL
        function openOnboardingModal() {
            document.getElementById('onboardingModal').classList.add('open');
            goToStep(1);
        }
        function closeOnboardingModal() {
            document.getElementById('onboardingModal').classList.remove('open');
        }
        function goToStep(stepNum) {
            document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
            const target = document.getElementById('step-' + stepNum);
            if (target) target.classList.add('active');
            const lbl = document.getElementById('wizard-step-label');
            if (lbl) lbl.textContent = `Step ${stepNum} of 3 &bull; ` + (stepNum === 1 ? 'Organisation Profile' : (stepNum === 2 ? 'Data Scope' : 'Ready to Launch'));
        }

        async function submitOnboardingAndLaunch() {
            const bizName = document.getElementById('ob-biz-name').value.trim() || 'My Business';
            const bizUrl = document.getElementById('ob-biz-url').value.trim() || 'https://example.com';
            const industry = document.getElementById('ob-biz-industry').value || 'clinics';
            
            try {
                await fetch('/api/dpdp/onboarding', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        business_name: bizName,
                        website_url: bizUrl,
                        industry: industry,
                        children_data_processed: document.getElementById('ob-col-minors').checked
                    })
                });
            } catch (e) {
                console.warn('Onboarding save fallback:', e);
            }
            window.location.href = '/dashboard#scanner';
        }
    </script>
</body>
</html>
"""
