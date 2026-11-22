"""
TrustAudit — DPDP Compliance Management Platform Homepage Template
===================================================================
Premium Certinal-inspired visual storytelling, responsive typography,
mouse-responsive radial spotlight, parallax preview tilt, magnetic CTAs,
and simplified enterprise SaaS presentation.
"""

DPDP_LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit — Understand Your Data. Simplify DPDP Compliance.</title>
    <meta name="description" content="Discover personal data, identify DPDP compliance gaps, manage privacy notices, customer rights, and maintain verified evidence for Indian businesses, clinics, and startups.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #ffffff;
            --bg-neutral: #f8fafc;
            --bg-subtle: #f1f5f9;
            --navy-dark: #090e17;
            --navy-card: #0f172a;
            --navy-subtle: #1e293b;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --text-inverse: #f8fafc;
            --brand-primary: #1d4ed8;
            --brand-primary-hover: #1e40af;
            --brand-accent: #0284c7;
            --brand-emerald: #059669;
            --brand-emerald-subtle: #ecfdf5;
            --brand-amber: #d97706;
            --brand-red: #ef4444;
            --border-subtle: #e2e8f0;
            --border-hover: #cbd5e1;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.07), 0 2px 4px -2px rgb(0 0 0 / 0.07);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.08), 0 4px 6px -4px rgb(0 0 0 / 0.08);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 16px;
            --radius-xl: 24px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; font-family: 'Plus Jakarta Sans', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; color: var(--text-primary); background: var(--bg-body); }
        body { overflow-x: hidden; line-height: 1.6; }

        a { color: inherit; text-decoration: none; }
        button { cursor: pointer; border: none; font-family: inherit; }

        .container { max-width: 1240px; margin: 0 auto; padding: 0 24px; }
        .section-padding { padding: 96px 0; }
        .section-header { text-align: center; max-width: 760px; margin: 0 auto 60px auto; }
        .eyebrow { font-size: 12.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: var(--brand-primary); margin-bottom: 12px; display: inline-flex; align-items: center; gap: 8px; }
        .eyebrow-dark { color: #38bdf8; }
        .section-title { font-size: 38px; font-weight: 800; line-height: 1.2; letter-spacing: -0.8px; margin-bottom: 18px; color: var(--text-primary); }
        .section-title-dark { color: #ffffff; }
        .section-subtext { font-size: 16.5px; color: var(--text-secondary); line-height: 1.6; }
        .section-subtext-dark { color: #94a3b8; }

        /* BUTTONS WITH MAGNETIC TRANSITIONS */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 10px; padding: 13px 26px; border-radius: 9999px; font-weight: 600; font-size: 14.5px; transition: transform 0.18s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s, background 0.2s; will-change: transform; }
        .btn-primary { background: var(--brand-primary); color: #ffffff; box-shadow: 0 4px 14px 0 rgba(29, 78, 216, 0.35); }
        .btn-primary:hover { background: var(--brand-primary-hover); transform: translateY(-2px); box-shadow: 0 8px 24px 0 rgba(29, 78, 216, 0.45); }
        .btn-secondary { background: #ffffff; color: var(--text-primary); border: 1px solid var(--border-subtle); box-shadow: var(--shadow-sm); }
        .btn-secondary:hover { background: var(--bg-neutral); border-color: var(--border-hover); transform: translateY(-1px); }
        .btn-dark { background: #ffffff; color: var(--navy-dark); font-weight: 700; }
        .btn-dark:hover { background: #f1f5f9; transform: translateY(-1px); }

        /* NAV */
        nav.site-nav { position: sticky; top: 0; z-index: 100; background: rgba(255, 255, 255, 0.94); backdrop-filter: blur(14px); border-bottom: 1px solid var(--border-subtle); transition: all 0.2s ease; }
        .nav-inner { display: flex; align-items: center; justify-content: space-between; height: 74px; }
        .logo-wrap { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 21px; color: var(--navy-dark); letter-spacing: -0.5px; }
        .logo-badge { font-size: 10px; font-weight: 700; background: #e0f2fe; color: #0369a1; padding: 3px 8px; border-radius: 6px; letter-spacing: 0.5px; }
        .nav-links { display: flex; align-items: center; gap: 30px; list-style: none; font-size: 14.5px; font-weight: 500; color: var(--text-secondary); }
        .nav-links a:hover { color: var(--brand-primary); }
        .nav-actions { display: flex; align-items: center; gap: 12px; }

        /* HERO SECTION WITH MOUSE SPOTLIGHT */
        .hero { position: relative; padding: 84px 0 96px 0; background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%); overflow: hidden; }
        .hero-spotlight { position: absolute; top: 0; left: 0; width: 600px; height: 600px; border-radius: 50%; background: radial-gradient(circle, rgba(56, 189, 248, 0.12) 0%, rgba(29, 78, 216, 0.04) 40%, transparent 70%); pointer-events: none; transition: opacity 0.3s ease; opacity: 0; will-change: transform; z-index: 1; }
        .hero-grid { display: grid; grid-template-columns: 1.05fr 1fr; gap: 52px; align-items: center; position: relative; z-index: 2; }
        .hero-content h1 { font-size: 52px; font-weight: 850; line-height: 1.15; letter-spacing: -1.5px; margin-bottom: 20px; color: var(--navy-dark); }
        .hero-content h1 span.gradient-text { background: linear-gradient(135deg, #1d4ed8 0%, #0284c7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero-lead { font-size: 18px; line-height: 1.65; color: var(--text-secondary); margin-bottom: 32px; max-width: 540px; }
        .hero-btns { display: flex; gap: 14px; margin-bottom: 32px; flex-wrap: wrap; }
        .hero-trust-strip { display: flex; align-items: center; gap: 22px; font-size: 13px; color: var(--text-muted); font-weight: 500; border-top: 1px solid var(--border-subtle); padding-top: 24px; }
        .hero-trust-item { display: flex; align-items: center; gap: 8px; }

        /* HERO INTERACTIVE DASHBOARD PREVIEW */
        .hero-mockup-wrap { position: relative; perspective: 1200px; }
        .hero-mockup-card { background: #0f172a; border-radius: var(--radius-xl); border: 1px solid #334155; box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.35); padding: 22px; color: #f8fafc; font-size: 13px; position: relative; overflow: hidden; transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s; will-change: transform; }
        .mockup-topbar { display: flex; align-items: center; justify-content: space-between; padding-bottom: 14px; border-bottom: 1px solid #1e293b; margin-bottom: 16px; }
        .mockup-dots { display: flex; gap: 6px; }
        .mockup-dot { width: 9px; height: 9px; border-radius: 50%; }
        .mockup-title { font-size: 12px; font-weight: 600; color: #94a3b8; display: flex; align-items: center; gap: 8px; }
        .mockup-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
        .mockup-box { background: #1e293b; border: 1px solid #334155; border-radius: var(--radius-md); padding: 14px; }
        .mockup-box-val { font-size: 24px; font-weight: 800; color: #ffffff; line-height: 1.2; margin-top: 4px; }
        .mockup-box-lbl { font-size: 10.5px; color: #94a3b8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .mockup-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 9999px; }
        .pill-emerald { background: rgba(5, 150, 105, 0.2); color: #34d399; }
        .pill-amber { background: rgba(217, 119, 6, 0.2); color: #fbbf24; }
        .mockup-action-card { background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: var(--radius-md); padding: 12px 14px; display: flex; align-items: center; justify-content: space-between; margin-top: 10px; }

        /* FLOATING HOTSPOT BADGES */
        .hotspot-badge { position: absolute; background: #ffffff; border-radius: var(--radius-md); padding: 10px 14px; box-shadow: var(--shadow-xl); border: 1px solid var(--border-subtle); color: var(--navy-dark); display: flex; align-items: center; gap: 10px; z-index: 10; font-size: 12px; font-weight: 700; transition: transform 0.2s; }
        .hotspot-badge:hover { transform: scale(1.05); }
        .hotspot-1 { top: -16px; right: -12px; }
        .hotspot-2 { bottom: -18px; left: -16px; }

        /* 3-STAGE STORYTELLING TABS (DISCOVER - ASSESS - MANAGE) */
        .how-section { padding: 96px 0; background: #ffffff; }
        .how-tabs { display: flex; justify-content: center; gap: 12px; margin-bottom: 48px; }
        .how-tab-btn { padding: 12px 28px; border-radius: 9999px; font-weight: 700; font-size: 14px; background: var(--bg-neutral); color: var(--text-secondary); border: 1px solid var(--border-subtle); transition: all 0.2s; }
        .how-tab-btn.active { background: var(--brand-primary); color: #ffffff; border-color: var(--brand-primary); box-shadow: 0 4px 14px rgba(29, 78, 216, 0.25); }
        .how-panel { display: none; }
        .how-panel.active { display: grid; grid-template-columns: 1fr 1fr; gap: 48px; align-items: center; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

        /* ANIMATED PROCESS FLOW SVG */
        .flow-section { padding: 84px 0; background: #090e17; color: #ffffff; text-align: center; }
        .flow-container { max-width: 1000px; margin: 40px auto 0 auto; }
        .flow-steps { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; position: relative; margin-top: 24px; }
        .flow-step-item { background: #1e293b; border: 1px solid #334155; border-radius: var(--radius-md); padding: 16px 12px; text-align: center; font-size: 12.5px; font-weight: 600; color: #e2e8f0; transition: border-color 0.2s, transform 0.2s; }
        .flow-step-item:hover { border-color: #38bdf8; transform: translateY(-3px); }
        .flow-step-num { font-size: 11px; font-weight: 700; color: #38bdf8; margin-bottom: 6px; }

        /* BENTO GRID (CERTINAL STYLE) */
        .bento-section { padding: 96px 0; background: var(--bg-neutral); }
        .bento-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
        .bento-item { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px; display: flex; flex-direction: column; transition: all 0.2s ease; position: relative; overflow: hidden; }
        .bento-item:hover { box-shadow: var(--shadow-lg); border-color: var(--border-hover); transform: translateY(-3px); }
        .bento-icon { width: 42px; height: 42px; border-radius: 10px; background: #eff6ff; color: var(--brand-primary); display: flex; align-items: center; justify-content: center; margin-bottom: 18px; }
        .bento-item h4 { font-size: 18px; font-weight: 700; color: var(--navy-dark); margin-bottom: 8px; }
        .bento-item p { font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 18px; flex-grow: 1; }
        .bento-preview { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; font-size: 11.5px; color: #475569; margin-bottom: 16px; font-family: monospace; }
        .bento-link { font-size: 13px; font-weight: 700; color: var(--brand-primary); display: inline-flex; align-items: center; gap: 6px; }
        .bento-link:hover { gap: 9px; }

        /* INDUSTRY SOLUTIONS */
        .industry-section { padding: 96px 0; background: #ffffff; }
        .ind-nav { display: flex; justify-content: center; gap: 10px; margin-bottom: 40px; flex-wrap: wrap; }
        .ind-btn { padding: 10px 22px; border-radius: 9999px; font-weight: 600; font-size: 13.5px; background: var(--bg-neutral); border: 1px solid var(--border-subtle); color: var(--text-secondary); }
        .ind-btn.active { background: var(--navy-dark); color: #ffffff; border-color: var(--navy-dark); }
        .ind-panel { display: none; }
        .ind-panel.active { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; align-items: center; animation: fadeIn 0.3s ease; }
        .ind-box { background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; }

        /* TIMELINE */
        .timeline-section { padding: 96px 0; background: #090e17; color: #ffffff; }
        .timeline-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 48px; }
        .t-card { background: #0f172a; border: 1px solid #1e293b; border-radius: var(--radius-lg); padding: 24px; position: relative; }
        .t-card h4 { font-size: 15px; font-weight: 700; color: #ffffff; margin-bottom: 8px; }
        .t-card p { font-size: 12.5px; color: #94a3b8; line-height: 1.5; }
        .t-date { font-size: 12px; font-weight: 700; color: #38bdf8; margin-bottom: 8px; }

        /* PRICING */
        .pricing-section { padding: 96px 0; background: var(--bg-neutral); }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 28px; }
        .pricing-card { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; display: flex; flex-direction: column; transition: all 0.2s; position: relative; }
        .pricing-card.featured { border-color: var(--brand-primary); box-shadow: var(--shadow-xl); transform: scale(1.02); }
        .featured-tag { position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: var(--brand-primary); color: #ffffff; font-size: 11px; font-weight: 700; padding: 4px 14px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px; }
        .pricing-card h3 { font-size: 20px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px; }
        .plan-price { font-size: 38px; font-weight: 850; color: var(--navy-dark); line-height: 1; margin: 18px 0; }
        .plan-price span { font-size: 13.5px; font-weight: 500; color: var(--text-muted); }
        .plan-features { list-style: none; margin-bottom: 30px; flex-grow: 1; }
        .plan-features li { font-size: 13px; color: var(--text-secondary); margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }

        /* FAQ */
        .faq-section { padding: 96px 0; background: #ffffff; }
        .faq-item { border-bottom: 1px solid var(--border-subtle); padding: 20px 0; }
        .faq-question { font-size: 16px; font-weight: 700; color: var(--navy-dark); cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .faq-answer { font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-top: 10px; display: none; }
        .faq-item.open .faq-answer { display: block; }
        .faq-item.open .faq-icon { transform: rotate(180deg); }
        .faq-icon { transition: transform 0.2s; }

        /* FINAL CTA */
        .cta-banner { background: linear-gradient(135deg, #090e17 0%, #1e293b 100%); color: #ffffff; border-radius: var(--radius-xl); padding: 64px 40px; text-align: center; margin: 60px 0 96px 0; border: 1px solid #334155; }
        .cta-banner h2 { font-size: 38px; font-weight: 850; margin-bottom: 14px; letter-spacing: -0.8px; }
        .cta-banner p { font-size: 16.5px; color: #94a3b8; max-width: 600px; margin: 0 auto 32px auto; }

        /* FOOTER */
        footer.site-footer { background: #090e17; color: #94a3b8; padding: 64px 0 36px 0; border-top: 1px solid #1e293b; font-size: 13.5px; }
        .footer-grid { display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; gap: 48px; margin-bottom: 48px; }
        .footer-col h5 { font-size: 14px; font-weight: 700; color: #ffffff; margin-bottom: 16px; }
        .footer-col ul { list-style: none; }
        .footer-col ul li { margin-bottom: 10px; }
        .footer-col ul li a:hover { color: #ffffff; }
        .footer-bottom { display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #1e293b; padding-top: 26px; font-size: 12.5px; }

        /* 3-STEP GUIDED ONBOARDING MODAL (PHASE 5) */
        .modal-overlay { position: fixed; inset: 0; background: rgba(9, 14, 23, 0.75); backdrop-filter: blur(6px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.open { display: flex; }
        .modal-card { background: #ffffff; border-radius: var(--radius-xl); width: 100%; max-width: 580px; padding: 36px; box-shadow: var(--shadow-xl); position: relative; max-height: 90vh; overflow-y: auto; }
        .wizard-step-indicator { display: flex; justify-content: space-between; margin-bottom: 28px; position: relative; }
        .wizard-step { flex: 1; text-align: center; font-size: 12px; font-weight: 700; color: var(--text-muted); position: relative; }
        .wizard-step.active { color: var(--brand-primary); }
        .wizard-step.done { color: var(--brand-emerald); }
        .wizard-step::after { content: ''; position: absolute; top: -6px; left: 50%; transform: translateX(-50%); width: 22px; height: 22px; border-radius: 50%; background: #e2e8f0; display: flex; align-items: center; justify-content: center; }
        .wizard-step.active::after { background: var(--brand-primary); }
        .wizard-step.done::after { background: var(--brand-emerald); }
        .wizard-panel { display: none; }
        .wizard-panel.active { display: block; animation: fadeIn 0.2s ease; }
        .form-group { margin-bottom: 16px; }
        .form-label { display: block; font-size: 13px; font-weight: 600; color: var(--navy-dark); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 10px 14px; border: 1px solid var(--border-subtle); border-radius: 8px; font-size: 13.5px; font-family: inherit; }
        .form-control:focus { outline: none; border-color: var(--brand-primary); box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.12); }

        @media (max-width: 992px) {
            .hero-grid { grid-template-columns: 1fr; }
            .bento-grid { grid-template-columns: 1fr; }
            .how-panel.active { grid-template-columns: 1fr; }
            .ind-panel.active { grid-template-columns: 1fr; }
            .timeline-cards { grid-template-columns: 1fr 1fr; }
            .pricing-grid { grid-template-columns: 1fr; }
            .flow-steps { grid-template-columns: repeat(3, 1fr); }
            .footer-grid { grid-template-columns: 1fr 1fr; }
        }
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
                <li><a href="#modules">Platform Modules</a></li>
                <li><a href="#industries">Industries</a></li>
                <li><a href="#timeline">DPDP Timeline</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="/trust">Trust Centre</a></li>
            </ul>
            <div class="nav-actions">
                <a href="/dashboard" class="btn btn-secondary" style="padding: 8px 18px; font-size: 13.5px;">Sign In</a>
                <button onclick="openOnboardingModal()" class="btn btn-primary btn-magnetic" style="padding: 9px 20px; font-size: 13.5px;">Start Free Assessment</button>
            </div>
        </div>
    </nav>

    <!-- SECTION 1 — HERO WITH SPOTLIGHT & PREVIEW -->
    <header class="hero">
        <div class="hero-spotlight" id="hero-spotlight"></div>
        <div class="container hero-grid">
            <div class="hero-content">
                <div class="eyebrow">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    DPDP COMPLIANCE MANAGEMENT PLATFORM
                </div>
                <h1>Your DPDP Compliance Journey, <span class="gradient-text">Made Simple.</span></h1>
                <p class="hero-lead">
                    Discover what personal data your business collects, understand your DPDP requirements, identify compliance gaps and manage everything from one platform.
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
                        <span>Explore TrustAudit</span>
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
                </div>
            </div>

            <!-- INTERACTIVE DASHBOARD PREVIEW -->
            <div class="hero-mockup-wrap">
                <div class="hotspot-badge hotspot-1">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #10b981;"></span>
                    <span>Website Scan: Live Signal Checked</span>
                </div>
                <div class="hotspot-badge hotspot-2">
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #38bdf8;"></span>
                    <span>Evidence Vault: SHA-256 Verified</span>
                </div>

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

    <!-- SECTION 2 — HOW TRUSTAUDIT WORKS (3 STAGES: DISCOVER - ASSESS - MANAGE) -->
    <section id="how-it-works" class="how-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">SIMPLE 3-STAGE OPERATING MODEL</div>
                <h2 class="section-title">How TrustAudit Works</h2>
                <p class="section-subtext">
                    Complex legal rules behind the scenes. A simple, stress-free compliance journey in front of you.
                </p>
            </div>

            <div class="how-tabs">
                <button class="how-tab-btn active" onclick="switchHowTab('discover', this)">1. DISCOVER</button>
                <button class="how-tab-btn" onclick="switchHowTab('assess', this)">2. ASSESS</button>
                <button class="how-tab-btn" onclick="switchHowTab('manage', this)">3. MANAGE</button>
            </div>

            <!-- DISCOVER PANEL -->
            <div id="how-panel-discover" class="how-panel active">
                <div>
                    <span class="eyebrow">STAGE 01 &bull; DATA VISIBILITY</span>
                    <h3 style="font-size: 28px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Understand What Data Your Business Collects</h3>
                    <p style="font-size: 15.5px; color: var(--text-secondary); margin-bottom: 22px;">
                        Gain complete visibility over customer appointments, patient diagnostic charts, employee records, and website enquiries without spreadsheets.
                    </p>
                    <ul style="list-style: none; display: flex; flex-direction: column; gap: 10px; font-size: 14px; font-weight: 600;">
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Automated public website scan for forms &amp; trackers</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Pre-built templates for Healthcare, Diagnostics &amp; SaaS</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Roundtrip CSV Import and Export for internal records</li>
                    </ul>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase; margin-bottom: 12px;">Data Stream Inventory</div>
                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        <div style="background: #ffffff; padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; justify-content: space-between;">
                            <span><strong>Patient Consultation Records</strong> &bull; Health</span>
                            <span class="mockup-pill pill-emerald">Consent Sec 6</span>
                        </div>
                        <div style="background: #ffffff; padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; justify-content: space-between;">
                            <span><strong>Diagnostic Blood Test Reports</strong> &bull; Clinical</span>
                            <span class="mockup-pill pill-emerald">Emergency Sec 7(e)</span>
                        </div>
                        <div style="background: #ffffff; padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; justify-content: space-between;">
                            <span><strong>Website Appointment Bookings</strong> &bull; Digital</span>
                            <span class="mockup-pill pill-emerald">Verified Notice</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ASSESS PANEL -->
            <div id="how-panel-assess" class="how-panel">
                <div>
                    <span class="eyebrow">STAGE 02 &bull; GAP IDENTIFICATION</span>
                    <h3 style="font-size: 28px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Know Exactly What Applies to Your Business</h3>
                    <p style="font-size: 15.5px; color: var(--text-secondary); margin-bottom: 22px;">
                        Stop guessing compliance. TrustAudit dynamically checks your statutory obligations across notice transparency, children's data safeguards, and processor contracts.
                    </p>
                    <ul style="list-style: none; display: flex; flex-direction: column; gap: 10px; font-size: 14px; font-weight: 600;">
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Plain-English questions without legal jargon</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Prioritized compliance gaps with clear next steps</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Accurate statutory penalty ceilings &bull; Zero fake fines</li>
                    </ul>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-amber); text-transform: uppercase; margin-bottom: 12px;">Prioritized Action Item</div>
                    <div style="background: #ffffff; padding: 18px; border-radius: 10px; border: 1px solid var(--border-subtle);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span class="mockup-pill pill-amber">High Attention</span>
                            <span style="font-size: 11px; color: var(--text-muted);">Section 5 Notice</span>
                        </div>
                        <h4 style="font-size: 15px; color: var(--navy-dark); margin-bottom: 6px;">Add Privacy Link to Contact Form</h4>
                        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">Patients booking appointments should see your privacy terms before submitting phone numbers.</p>
                        <a href="/dashboard#remediation" class="btn btn-primary" style="padding: 7px 16px; font-size: 12px;">View and Fix &rarr;</a>
                    </div>
                </div>
            </div>

            <!-- MANAGE PANEL -->
            <div id="how-panel-manage" class="how-panel">
                <div>
                    <span class="eyebrow">STAGE 03 &bull; CONTINUOUS GOVERNANCE</span>
                    <h3 style="font-size: 28px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px;">Manage Everything in One Place</h3>
                    <p style="font-size: 15.5px; color: var(--text-secondary); margin-bottom: 22px;">
                        Handle customer privacy requests, track vendor contracts, schedule data retention, and store verified evidence in an immutable, tenant-isolated vault.
                    </p>
                    <ul style="list-style: none; display: flex; flex-direction: column; gap: 10px; font-size: 14px; font-weight: 600;">
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Customer privacy request desk with SLA countdown</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Automated consent withdrawal instruction cascade</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> AES-256 Evidence Vault with SHA-256 audit trails</li>
                    </ul>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-emerald); text-transform: uppercase; margin-bottom: 12px;">Verified Evidence Vault</div>
                    <div style="display: flex; flex-direction: column; gap: 10px;">
                        <div style="background: #ffffff; padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: 600; font-size: 13px;">Laboratory IT Data Processing Agreement</div>
                                <div style="font-size: 11px; color: var(--text-muted);">Section 8(2) &bull; Verified SHA-256</div>
                            </div>
                            <span class="mockup-pill pill-emerald">Active</span>
                        </div>
                        <div style="background: #ffffff; padding: 12px; border-radius: 8px; border: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: 600; font-size: 13px;">Clinical Establishment Record Retention Schedule</div>
                                <div style="font-size: 11px; color: var(--text-muted);">Rule 8 &bull; 5-Year Medical Rule</div>
                            </div>
                            <span class="mockup-pill pill-emerald">Active</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 3 — ANIMATED PROCESS FLOW -->
    <section class="flow-section">
        <div class="container flow-container">
            <span class="eyebrow eyebrow-dark">END-TO-END FLOW</span>
            <h2 class="section-title section-title-dark" style="font-size: 32px;">A Seamless Compliance Pipeline</h2>
            <p class="section-subtext section-subtext-dark" style="max-width: 620px; margin: 0 auto;">
                From external website discovery to verified audit evidence in an automated continuous cycle.
            </p>

            <div class="flow-steps">
                <div class="flow-step-item">
                    <div class="flow-step-num">01</div>
                    <div>Website</div>
                </div>
                <div class="flow-step-item">
                    <div class="flow-step-num">02</div>
                    <div>Discovery</div>
                </div>
                <div class="flow-step-item">
                    <div class="flow-step-num">03</div>
                    <div>Assessment</div>
                </div>
                <div class="flow-step-item">
                    <div class="flow-step-num">04</div>
                    <div>Findings</div>
                </div>
                <div class="flow-step-item">
                    <div class="flow-step-num">05</div>
                    <div>Remediation</div>
                </div>
                <div class="flow-step-item">
                    <div class="flow-step-num">06</div>
                    <div>Evidence</div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 4 — BENTO GRID OF CORE MODULES -->
    <section id="modules" class="bento-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">ENTERPRISE CAPABILITIES</div>
                <h2 class="section-title">Everything Needed for DPDP Compliance</h2>
                <p class="section-subtext">
                    Engineered to replace scattered spreadsheets and fragmented legal paperwork with a single, intuitive system of record.
                </p>
            </div>

            <div class="bento-grid">
                <!-- 01 WEBSITE SCANNER -->
                <div class="bento-item" style="border-color: #38bdf8; background: linear-gradient(180deg, #ffffff 0%, #f0f9ff 100%);">
                    <div class="bento-icon" style="background: #e0f2fe; color: #0284c7;"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/></svg></div>
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                        <h4 style="margin-bottom: 0;">01. Website Scanner</h4>
                        <span style="font-size: 10px; font-weight: 800; background: #0284c7; color: #ffffff; padding: 2px 7px; border-radius: 9999px;">NEW FEATURE</span>
                    </div>
                    <p>Passive perimeter discovery engine. Inspects public pages, evaluates Section 5 privacy notices, flags pre-ticked consent checkboxes, and audits third-party tracking scripts.</p>
                    <div class="bento-preview">Observation: Notice &bull; Forms &bull; Trackers &bull; Grievance Redressal</div>
                    <a href="/dashboard#scanner" class="bento-link" style="color: #0284c7;">Launch Website Scanner &rarr;</a>
                </div>

                <!-- 02 DATA INVENTORY -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
                    <h4>02. Personal Data Inventory</h4>
                    <p>Catalog all digital personal data, collection sources, legal bases, storage systems, and retention periods with CSV import/export.</p>
                    <div class="bento-preview">Templates: Clinics &bull; Diagnostics &bull; SaaS &bull; E-Commerce</div>
                    <a href="/dashboard#inventory" class="bento-link">Explore Inventory &rarr;</a>
                </div>

                <!-- 03 PRIVACY NOTICES -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>
                    <h4>03. Privacy Notice Builder</h4>
                    <p>Generate itemised notices under Section 5 and Rule 3 with Grievance Officer details and Eighth Schedule Indian language readiness.</p>
                    <div class="bento-preview">Languages: English &bull; Hindi &bull; Regional Translations</div>
                    <a href="/dashboard#privacy" class="bento-link">Manage Notices &rarr;</a>
                </div>

                <!-- 04 CONSENT MANAGEMENT -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg></div>
                    <h4>04. Consent &amp; Withdrawals</h4>
                    <p>Track purpose-specific consent logs and execute Section 6(4) withdrawal workflows that cascade instructions to processors.</p>
                    <div class="bento-preview">Feature: Processor Cease-Processing Protocols</div>
                    <a href="/dashboard#consent" class="bento-link">View Consent Logs &rarr;</a>
                </div>

                <!-- 05 CUSTOMER REQUESTS -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div>
                    <h4>05. Customer Privacy Requests</h4>
                    <p>End-to-end ticketing for statutory access, correction, erasure, grievance, and nomination requests (Sections 11–14).</p>
                    <div class="bento-preview">SLA Tracker: 30-Day Resolution Dashboard</div>
                    <a href="/dashboard#rights" class="bento-link">Open Requests Desk &rarr;</a>
                </div>

                <!-- 06 VENDORS & PROCESSORS -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
                    <h4>06. Vendor &amp; Processor Register</h4>
                    <p>Maintain your Section 8(2) register of third-party software, labs, and cloud hosts with executed DPA contracts and review cycles.</p>
                    <div class="bento-preview">Tracking: Agreement Expiry &bull; India Hosting Verification</div>
                    <a href="/dashboard#vendors" class="bento-link">Manage Vendors &rarr;</a>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 5 — INDUSTRY SOLUTIONS -->
    <section id="industries" class="industry-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">TAILORED INDUSTRY WORKFLOWS</div>
                <h2 class="section-title">Built for Your Sector's Data Realities</h2>
                <p class="section-subtext">Pre-configured inventories, legal grounds, and retention schedules tailored to specific business models.</p>
            </div>

            <div class="ind-nav">
                <button class="ind-btn active" onclick="switchIndustry('health', this)">Healthcare &amp; Clinics</button>
                <button class="ind-btn" onclick="switchIndustry('edu', this)">Education &amp; EdTech</button>
                <button class="ind-btn" onclick="switchIndustry('saas', this)">B2B SaaS</button>
                <button class="ind-btn" onclick="switchIndustry('retail', this)">Retail &amp; E-Commerce</button>
            </div>

            <div id="ind-health" class="ind-panel active">
                <div class="ind-box">
                    <span class="eyebrow">HEALTHCARE EXCELLENCE</span>
                    <h3 style="font-size: 24px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Clinics, Diagnostic Centres &amp; Hospitals</h3>
                    <p style="font-size: 14.5px; color: var(--text-secondary); margin-bottom: 20px;">
                        Harmonize DPDP obligations with the Clinical Establishment Act and National Medical Commission rules. Zero raw patient data ever enters TrustAudit.
                    </p>
                    <ul style="list-style: none; display: flex; flex-direction: column; gap: 8px; font-size: 13.5px; font-weight: 600;">
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 3-5 Year Medical Retention Schedules under Rule 8</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Medical emergency processing grounds (Section 7(e))</li>
                        <li style="display: flex; align-items: center; gap: 8px;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Diagnostic lab &amp; billing vendor contract templates</li>
                    </ul>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px; text-align: center;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-emerald); text-transform: uppercase;">Zero Raw Patient Data Architecture</div>
                    <p style="font-size: 14px; color: var(--text-secondary); margin-top: 8px;">TrustAudit stores strictly metadata, compliance documents, and logs. Clinical medical records remain 100% inside your hospital software.</p>
                </div>
            </div>

            <div id="ind-edu" class="ind-panel">
                <div class="ind-box">
                    <span class="eyebrow">MINOR DATA PROTECTION</span>
                    <h3 style="font-size: 24px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Schools &amp; EdTech Platforms</h3>
                    <p style="font-size: 14.5px; color: var(--text-secondary); margin-bottom: 20px;">
                        Manage Section 9 verifiable parental consent, track minor student data, and enforce prohibitions against behavioral tracking of children.
                    </p>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px; text-align: center;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Parental Consent Workflows</div>
                    <p style="font-size: 14px; color: var(--text-secondary); margin-top: 8px;">Pre-built consent logging for parents and guardians under the October 2026 Removal of Difficulties Order.</p>
                </div>
            </div>

            <div id="ind-saas" class="ind-panel">
                <div class="ind-box">
                    <span class="eyebrow">TECH &amp; SOFTWARE</span>
                    <h3 style="font-size: 24px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">B2B SaaS &amp; Cloud Apps</h3>
                    <p style="font-size: 14.5px; color: var(--text-secondary); margin-bottom: 20px;">
                        Distinguish Data Fiduciary vs Processor roles, execute standard Indian DPAs, and bridge SOC 2/ISO 27001 evidence with DPDP Section 8(5).
                    </p>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px; text-align: center;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-accent); text-transform: uppercase;">Processor DPA Workflows</div>
                    <p style="font-size: 14px; color: var(--text-secondary); margin-top: 8px;">Manage sub-processors, cloud hosting locations, and automated data return agreements.</p>
                </div>
            </div>

            <div id="ind-retail" class="ind-panel">
                <div class="ind-box">
                    <span class="eyebrow">E-COMMERCE &amp; RETAIL</span>
                    <h3 style="font-size: 24px; font-weight: 800; color: var(--navy-dark); margin-bottom: 12px;">Retail Stores &amp; E-Commerce</h3>
                    <p style="font-size: 14.5px; color: var(--text-secondary); margin-bottom: 20px;">
                        Audit tracking scripts, manage checkout consent, and automate customer order data retention without disrupting sales.
                    </p>
                </div>
                <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 32px; text-align: center;">
                    <div style="font-size: 12px; font-weight: 700; color: var(--brand-primary); text-transform: uppercase;">Checkout Transparency</div>
                    <p style="font-size: 14px; color: var(--text-secondary); margin-top: 8px;">Verify un-selected consent checkboxes and clear itemised delivery notices.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 6 — STATUTORY TIMELINE -->
    <section id="timeline" class="timeline-section">
        <div class="container">
            <div class="section-header">
                <span class="eyebrow eyebrow-dark">OFFICIAL ROADMAP</span>
                <h2 class="section-title section-title-dark">DPDP Statutory Timeline</h2>
                <p class="section-subtext section-subtext-dark">Official gazette milestones governing enforcement in India.</p>
            </div>

            <div class="timeline-cards">
                <div class="t-card">
                    <div class="t-date">11 August 2023</div>
                    <h4>DPDP Act Enacted</h4>
                    <p>Published in the Official Gazette as Act No. 22 of 2023 following Presidential assent.</p>
                </div>
                <div class="t-card">
                    <div class="t-date">13 November 2025</div>
                    <h4>Rules In Force</h4>
                    <p>MeitY notified DPDP Rules, 2025; Data Protection Board &amp; institutional framework active.</p>
                </div>
                <div class="t-card">
                    <div class="t-date">13 November 2026</div>
                    <h4>Consent Managers</h4>
                    <p>Section 6(9) &amp; Rule 4 statutory Consent Manager registration regulations commenced.</p>
                </div>
                <div class="t-card" style="border-color: #38bdf8;">
                    <div class="t-date" style="color: #38bdf8;">13 May 2027</div>
                    <h4>Substantive Obligations</h4>
                    <p>General obligations of Data Fiduciaries scheduled for full statutory regulatory effect.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 7 — PRICING -->
    <section id="pricing" class="pricing-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">TRANSPARENT PLANS</div>
                <h2 class="section-title">Affordable Compliance for Every Business</h2>
                <p class="section-subtext">No hidden fees. Scale as your data processing activities grow.</p>
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

    <!-- SECTION 8 — FAQ -->
    <section class="faq-section">
        <div class="container" style="max-width: 840px;">
            <div class="section-header">
                <div class="eyebrow">FREQUENTLY ASKED QUESTIONS</div>
                <h2 class="section-title">Clear Answers to Common DPDP Questions</h2>
            </div>

            <div class="faq-item">
                <div class="faq-question" onclick="toggleFaq(this)">
                    <span>Does DPDP apply to small clinics and local businesses in India?</span>
                    <svg class="faq-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
                <div class="faq-answer">
                    Yes. Under Section 3, the DPDP Act applies to any entity that processes digital personal data within India, including patient names, mobile numbers, and billing records collected digitally or converted to digital format.
                </div>
            </div>

            <div class="faq-item">
                <div class="faq-question" onclick="toggleFaq(this)">
                    <span>Is a cookie banner required on every Indian website?</span>
                    <svg class="faq-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
                <div class="faq-answer">
                    No. The DPDP Act does not mandate generic GDPR-style cookie popups. However, if third-party tracking scripts collect personal data, transparent notice under Section 5 and a valid legal basis under Section 6 or Section 7 are required.
                </div>
            </div>

            <div class="faq-item">
                <div class="faq-question" onclick="toggleFaq(this)">
                    <span>What are the statutory penalty amounts under the DPDP Act?</span>
                    <svg class="faq-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
                <div class="faq-answer">
                    Penalties are statutory maximum ceilings determined on a case-by-case basis by the Data Protection Board: up to &#8377;250 Cr for failing to implement reasonable security safeguards, up to &#8377;200 Cr for breach notification failures or children's data violations, and up to &#8377;50 Cr for general contraventions. They are not automatic fines.
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 9 — FINAL CTA BANNER -->
    <div class="container">
        <div class="cta-banner">
            <h2>Understand Your Data. Simplify DPDP Compliance.</h2>
            <p>Join healthcare clinics, diagnostic centers, and growing Indian businesses managing compliance with clarity and confidence.</p>
            <div style="display: flex; justify-content: center; gap: 14px; flex-wrap: wrap;">
                <button onclick="openOnboardingModal()" class="btn btn-dark btn-magnetic" style="padding: 14px 30px; font-size: 15px;">Start Free Assessment &rarr;</button>
                <a href="/dashboard#scanner" class="btn btn-outline-white" style="padding: 14px 26px; font-size: 15px; border-radius: 9999px;">Scan Your Website</a>
            </div>
        </div>
    </div>

    <!-- SITE FOOTER -->
    <footer class="site-footer">
        <div class="container">
            <div class="footer-grid">
                <div>
                    <div class="logo-wrap" style="color: #ffffff; margin-bottom: 14px;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        <span>TrustAudit</span>
                    </div>
                    <p style="font-size: 13px; line-height: 1.6; max-width: 300px;">Purpose-built DPDP compliance management platform for Indian enterprises, healthcare providers, and high-growth technology companies.</p>
                </div>
                <div class="footer-col">
                    <h5>Platform</h5>
                    <ul>
                        <li><a href="/dashboard#scanner">Website Scanner</a></li>
                        <li><a href="/dashboard#inventory">Data Inventory</a></li>
                        <li><a href="/dashboard#privacy">Privacy Notices</a></li>
                        <li><a href="/dashboard#rights">Customer Requests</a></li>
                        <li><a href="/dashboard#evidence">Evidence Vault</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h5>Resources</h5>
                    <ul>
                        <li><a href="/trust">Security &amp; Trust Centre</a></li>
                        <li><a href="#timeline">DPDP Enforcement Timeline</a></li>
                        <li><a href="#how-it-works">How TrustAudit Works</a></li>
                        <li><a href="#pricing">Pricing Plans</a></li>
                    </ul>
                </div>
                <div class="footer-col">
                    <h5>Legal &amp; Privacy</h5>
                    <ul>
                        <li><a href="/trust">Zero Patient Data Policy</a></li>
                        <li><a href="/trust">Multi-Tenant Isolation</a></li>
                        <li><a href="/trust">DPO Grievance Desk</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <div>&copy; 2026 TrustAudit Technologies. All rights reserved. Built for India DPDP Act 2023 &amp; Rules 2025.</div>
                <div style="font-size: 11.5px; color: #64748b;">Not a government-issued statutory certification. Posture metrics represent self-attested &amp; verified compliance tracking.</div>
            </div>
        </div>
    </footer>

    <!-- 3-STEP GUIDED ONBOARDING MODAL (PHASE 5) -->
    <div id="onboardingModal" class="modal-overlay">
        <div class="modal-card">
            <button onclick="closeOnboardingModal()" style="position: absolute; top: 20px; right: 20px; background: none; font-size: 22px; color: var(--text-muted);">&times;</button>
            
            <div class="wizard-step-indicator">
                <div id="wstep-1" class="wizard-step active">1. Your Business</div>
                <div id="wstep-2" class="wizard-step">2. Business Details</div>
                <div id="wstep-3" class="wizard-step">3. Assessment</div>
            </div>

            <form onsubmit="handleWizardSubmit(event)">
                <!-- STEP 1 -->
                <div id="wpanel-1" class="wizard-panel active">
                    <h3 style="font-size: 18px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px;">Tell Us About Your Business</h3>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">We'll tailor your compliance checks and inventory to your industry.</p>

                    <div class="form-group">
                        <label class="form-label">Business Name *</label>
                        <input type="text" id="ob_name" class="form-control" placeholder="e.g. City Care Diagnostics Clinic" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Website URL *</label>
                        <input type="url" id="ob_website" class="form-control" placeholder="https://citycare.in" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Industry *</label>
                        <select id="ob_industry" class="form-control" required>
                            <option value="Healthcare" selected>Healthcare / Clinic / Diagnostics</option>
                            <option value="Education">Education &amp; EdTech</option>
                            <option value="SaaS">SaaS &amp; Software Products</option>
                            <option value="E-Commerce">E-Commerce &amp; Retail</option>
                            <option value="Other">Other Business</option>
                        </select>
                    </div>
                    <div style="display: flex; justify-content: flex-end; margin-top: 24px;">
                        <button type="button" onclick="nextWizardStep(2)" class="btn btn-primary">Next: Business Details &rarr;</button>
                    </div>
                </div>

                <!-- STEP 2 -->
                <div id="wpanel-2" class="wizard-panel">
                    <h3 style="font-size: 18px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px;">Personal Data Collection</h3>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">Simple questions to determine which DPDP rules apply.</p>

                    <div class="form-group">
                        <label class="form-label">What is your website primarily used for?</label>
                        <input type="text" id="ob_purpose" class="form-control" placeholder="e.g. Patient appointments, consultation bookings, product sales">
                    </div>

                    <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                        <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--navy-dark);">
                            <input type="checkbox" id="ob_collects_data" checked>
                            <span>Collects customer, patient or employee information</span>
                        </label>
                        <div style="font-size: 11.5px; color: var(--text-muted); margin-left: 24px; margin-top: 2px;">Names, phone numbers, email addresses, medical inquiries, or billing details.</div>
                    </div>

                    <div style="background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                        <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; font-weight: 600; color: var(--navy-dark);">
                            <input type="checkbox" id="ob_children_data">
                            <span>Processes children's or minor student records under 18</span>
                        </label>
                        <div style="font-size: 11.5px; color: var(--text-muted); margin-left: 24px; margin-top: 2px;">Requires Section 9 verifiable parental consent workflows.</div>
                    </div>

                    <div style="display: flex; justify-content: space-between; margin-top: 24px;">
                        <button type="button" onclick="nextWizardStep(1)" class="btn btn-secondary">&larr; Back</button>
                        <button type="button" onclick="nextWizardStep(3)" class="btn btn-primary">Next: Ready to Scan &rarr;</button>
                    </div>
                </div>

                <!-- STEP 3 -->
                <div id="wpanel-3" class="wizard-panel">
                    <div style="text-align: center; padding: 12px 0 20px 0;">
                        <div style="width: 54px; height: 54px; border-radius: 50%; background: #ecfdf5; color: #059669; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px auto;">
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        </div>
                        <h3 style="font-size: 20px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px;">TrustAudit is Ready to Assess Your Business</h3>
                        <p style="font-size: 13.5px; color: var(--text-secondary); max-width: 440px; margin: 0 auto;">
                            We will inspect your public website disclosures, pre-fill your sector-specific data inventory, and highlight actionable statutory gaps.
                        </p>
                    </div>

                    <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 12px; color: #0f172a;">
                        <label style="display: flex; align-items: flex-start; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="ob_auth" checked style="margin-top: 2px;">
                            <span>I confirm that I own or represent this business and authorize a non-invasive DPDP readiness check.</span>
                        </label>
                    </div>

                    <div style="display: flex; justify-content: space-between; margin-top: 10px;">
                        <button type="button" onclick="nextWizardStep(2)" class="btn btn-secondary">&larr; Back</button>
                        <button type="submit" class="btn btn-primary btn-magnetic" style="padding: 12px 28px;">
                            <span>Start Website Scan &rarr;</span>
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- JAVASCRIPT FOR MOTION, TABS, WIZARD -->
    <script>
        // MOUSE SPOTLIGHT (PHASE 10.A)
        const hero = document.querySelector('.hero');
        const spotlight = document.getElementById('hero-spotlight');
        if (hero && spotlight && !window.matchMedia('(prefers-reduced-motion: reduce)').matches && window.innerWidth > 768) {
            hero.addEventListener('mousemove', (e) => {
                const rect = hero.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                spotlight.style.transform = `translate(${x - 300}px, ${y - 300}px)`;
                spotlight.style.opacity = '1';
            });
            hero.addEventListener('mouseleave', () => {
                spotlight.style.opacity = '0';
            });
        }

        // PARALLAX 3D TILT ON PRODUCT MOCKUP (PHASE 10.B)
        const mockupCard = document.getElementById('hero-mockup-card');
        if (mockupCard && !window.matchMedia('(prefers-reduced-motion: reduce)').matches && window.innerWidth > 768) {
            mockupCard.addEventListener('mousemove', (e) => {
                const rect = mockupCard.getBoundingClientRect();
                const x = (e.clientX - rect.left) / rect.width - 0.5;
                const y = (e.clientY - rect.top) / rect.height - 0.5;
                const tiltX = -y * 6; // max 6 deg
                const tiltY = x * 6;
                mockupCard.style.transform = `perspective(1000px) rotateX(${tiltX}deg) rotateY(${tiltY}deg) translateY(-4px)`;
            });
            mockupCard.addEventListener('mouseleave', () => {
                mockupCard.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0)';
            });
        }

        // MAGNETIC BUTTON EFFECT (PHASE 10.C)
        document.querySelectorAll('.btn-magnetic').forEach(btn => {
            if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches && window.innerWidth > 768) {
                btn.addEventListener('mousemove', (e) => {
                    const rect = btn.getBoundingClientRect();
                    const x = (e.clientX - rect.left) - rect.width / 2;
                    const y = (e.clientY - rect.top) - rect.height / 2;
                    btn.style.transform = `translate(${x * 0.22}px, ${y * 0.22}px)`;
                });
                btn.addEventListener('mouseleave', () => {
                    btn.style.transform = 'translate(0px, 0px)';
                });
            }
        });

        // 3-STAGE STORYTELLING TABS (PHASE 9)
        function switchHowTab(stage, btn) {
            document.querySelectorAll('.how-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.how-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const panel = document.getElementById('how-panel-' + stage);
            if (panel) panel.classList.add('active');
        }

        // INDUSTRY TABS
        function switchIndustry(ind, btn) {
            document.querySelectorAll('.ind-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ind-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const panel = document.getElementById('ind-' + ind);
            if (panel) panel.classList.add('active');
        }

        // FAQ TOGGLE
        function toggleFaq(el) {
            el.parentElement.classList.toggle('open');
        }

        // 3-STEP ONBOARDING WIZARD MODAL (PHASE 5)
        function openOnboardingModal() {
            document.getElementById('onboardingModal').classList.add('open');
        }
        function closeOnboardingModal() {
            document.getElementById('onboardingModal').classList.remove('open');
        }

        function nextWizardStep(stepNum) {
            document.querySelectorAll('.wizard-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));

            const panel = document.getElementById('wpanel-' + stepNum);
            const step = document.getElementById('wstep-' + stepNum);
            if (panel) panel.classList.add('active');
            if (step) step.classList.add('active');

            // Mark previous steps done
            for (let i = 1; i < stepNum; i++) {
                const prev = document.getElementById('wstep-' + i);
                if (prev) prev.classList.add('done');
            }
        }

        async function handleWizardSubmit(e) {
            e.preventDefault();
            const payload = {
                business_name: document.getElementById('ob_name').value.trim(),
                industry: document.getElementById('ob_industry').value,
                locations: 'India',
                employee_count: '15-50',
                customer_types: ['Customers / Patients'],
                children_data_processed: document.getElementById('ob_children_data').checked
            };

            try {
                await fetch('/api/dpdp/onboarding', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
            } catch (err) {
                console.warn('Onboarding sync note:', err);
            }

            // Redirect smoothly to dashboard website scanner
            window.location.href = '/dashboard#scanner';
        }
    </script>
</body>
</html>
"""
