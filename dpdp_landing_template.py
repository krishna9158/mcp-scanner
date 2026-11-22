"""
TrustAudit — DPDP Compliance Management Platform Homepage Template
===================================================================
Premium Certinal-inspired visual storytelling, responsive typography,
subtle motion, interactive SVG diagrams, and enterprise SaaS presentation.
"""

DPDP_LANDING_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit — DPDP Compliance, Managed in One Place</title>
    <meta name="description" content="Discover personal data, identify DPDP compliance gaps, manage privacy notices, consent withdrawal, Data Principal rights, and evidence collection for Indian businesses.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #ffffff;
            --bg-neutral: #f8fafc;
            --bg-surface: #ffffff;
            --bg-elevated: #ffffff;
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
            --border-subtle: #e2e8f0;
            --border-navy: #1e293b;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.07), 0 2px 4px -2px rgb(0 0 0 / 0.07);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.08), 0 4px 6px -4px rgb(0 0 0 / 0.08);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
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
        .section-header { text-align: center; max-width: 760px; margin: 0 auto 64px auto; }
        .eyebrow { font-size: 12.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: var(--brand-primary); margin-bottom: 12px; display: inline-flex; align-items: center; gap: 8px; }
        .eyebrow-dark { color: #38bdf8; }
        .section-title { font-size: 38px; font-weight: 800; line-height: 1.2; letter-spacing: -0.8px; margin-bottom: 18px; color: var(--text-primary); }
        .section-title-dark { color: #ffffff; }
        .section-subtext { font-size: 17px; color: var(--text-secondary); line-height: 1.6; }
        .section-subtext-dark { color: #94a3b8; }

        /* BUTTONS */
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 10px; padding: 13px 26px; border-radius: 9999px; font-weight: 600; font-size: 15px; transition: all 0.2s ease; }
        .btn-primary { background: var(--brand-primary); color: #ffffff; box-shadow: 0 4px 14px 0 rgba(29, 78, 216, 0.35); }
        .btn-primary:hover { background: var(--brand-primary-hover); transform: translateY(-1px); box-shadow: 0 6px 20px 0 rgba(29, 78, 216, 0.45); }
        .btn-secondary { background: #ffffff; color: var(--text-primary); border: 1px solid var(--border-subtle); box-shadow: var(--shadow-sm); }
        .btn-secondary:hover { background: var(--bg-neutral); border-color: #cbd5e1; }
        .btn-dark { background: #ffffff; color: var(--navy-dark); font-weight: 700; }
        .btn-dark:hover { background: #f1f5f9; }
        .btn-outline-white { background: transparent; color: #ffffff; border: 1px solid rgba(255,255,255,0.25); }
        .btn-outline-white:hover { background: rgba(255,255,255,0.08); border-color: #ffffff; }

        /* NAV */
        nav.site-nav { position: sticky; top: 0; z-index: 100; background: rgba(255, 255, 255, 0.92); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-subtle); }
        .nav-inner { display: flex; align-items: center; justify-content: space-between; height: 76px; }
        .logo-wrap { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 21px; color: var(--navy-dark); letter-spacing: -0.5px; }
        .logo-badge { font-size: 10px; font-weight: 700; background: #e0f2fe; color: #0369a1; padding: 3px 8px; border-radius: 6px; letter-spacing: 0.5px; }
        .nav-links { display: flex; align-items: center; gap: 32px; list-style: none; font-size: 14.5px; font-weight: 500; color: var(--text-secondary); }
        .nav-links a:hover { color: var(--brand-primary); }
        .nav-actions { display: flex; align-items: center; gap: 14px; }

        /* HERO SECTION */
        .hero { position: relative; padding: 90px 0 100px 0; background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%); overflow: hidden; }
        .hero-grid { display: grid; grid-template-columns: 1.05fr 1fr; gap: 56px; align-items: center; }
        .hero-content h1 { font-size: 52px; font-weight: 850; line-height: 1.15; letter-spacing: -1.5px; margin-bottom: 22px; color: var(--navy-dark); }
        .hero-content h1 span.gradient-text { background: linear-gradient(135deg, #1d4ed8 0%, #0284c7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero-lead { font-size: 18.5px; line-height: 1.65; color: var(--text-secondary); margin-bottom: 34px; max-width: 560px; }
        .hero-btns { display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
        .hero-trust-strip { display: flex; align-items: center; gap: 24px; font-size: 13px; color: var(--text-muted); font-weight: 500; border-top: 1px solid var(--border-subtle); padding-top: 24px; }
        .hero-trust-item { display: flex; align-items: center; gap: 8px; }

        /* HERO DASHBOARD MOCKUP */
        .hero-mockup-wrap { position: relative; }
        .hero-mockup-card { background: #0f172a; border-radius: var(--radius-xl); border: 1px solid #334155; box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.25); padding: 22px; color: #f8fafc; font-size: 13px; position: relative; overflow: hidden; }
        .mockup-topbar { display: flex; align-items: center; justify-content: space-between; padding-bottom: 16px; border-bottom: 1px solid #1e293b; margin-bottom: 18px; }
        .mockup-dots { display: flex; gap: 6px; }
        .mockup-dot { width: 10px; height: 10px; border-radius: 50%; }
        .mockup-title { font-size: 12px; font-weight: 600; color: #94a3b8; display: flex; align-items: center; gap: 8px; }
        .mockup-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; }
        .mockup-box { background: #1e293b; border: 1px solid #334155; border-radius: var(--radius-md); padding: 14px; }
        .mockup-box-val { font-size: 26px; font-weight: 800; color: #ffffff; line-height: 1.2; margin-top: 4px; }
        .mockup-box-lbl { font-size: 11px; color: #94a3b8; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
        .mockup-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 9999px; }
        .pill-emerald { background: rgba(5, 150, 105, 0.2); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); }
        .pill-amber { background: rgba(217, 119, 6, 0.2); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); }
        .mockup-row { display: flex; align-items: center; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #1e293b; font-size: 12px; }
        .mockup-row:last-child { border-bottom: none; }

        /* FLOATING BADGES */
        .floating-badge { position: absolute; background: #ffffff; border-radius: var(--radius-md); padding: 12px 18px; box-shadow: var(--shadow-xl); border: 1px solid var(--border-subtle); color: var(--navy-dark); display: flex; align-items: center; gap: 12px; z-index: 10; animation: floatSlow 4s ease-in-out infinite alternate; }
        .badge-1 { top: -20px; right: -15px; }
        .badge-2 { bottom: -20px; left: -20px; animation-delay: 2s; }
        @keyframes floatSlow { 0% { transform: translateY(0); } 100% { transform: translateY(-8px); } }

        /* THE BUSINESS PROBLEM (CERTINAL STYLE SCATTER-TO-ORDER) */
        .problem-section { background: #0f172a; color: #ffffff; padding: 100px 0; position: relative; }
        .problem-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; margin-top: 48px; }
        .problem-card { background: #1e293b; border: 1px solid #334155; border-radius: var(--radius-lg); padding: 28px; transition: transform 0.2s, border-color 0.2s; }
        .problem-card:hover { transform: translateY(-4px); border-color: #38bdf8; }
        .problem-num { font-size: 14px; font-weight: 700; color: #38bdf8; margin-bottom: 12px; }
        .problem-card h3 { font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 10px; }
        .problem-card p { font-size: 14px; color: #94a3b8; line-height: 1.6; }

        /* THREE PILLARS */
        .pillars-section { padding: 100px 0; background: #ffffff; }
        .pillars-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 32px; }
        .pillar-card { background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px 30px; transition: all 0.3s; position: relative; display: flex; flex-direction: column; }
        .pillar-card:hover { background: #ffffff; box-shadow: var(--shadow-xl); border-color: var(--brand-primary); transform: translateY(-4px); }
        .pillar-badge { font-size: 11px; font-weight: 800; letter-spacing: 1px; color: var(--brand-primary); text-transform: uppercase; margin-bottom: 14px; }
        .pillar-card h3 { font-size: 24px; font-weight: 800; color: var(--navy-dark); margin-bottom: 14px; }
        .pillar-card p { font-size: 14.5px; color: var(--text-secondary); line-height: 1.65; margin-bottom: 24px; }
        .pillar-list { list-style: none; margin-top: auto; border-top: 1px solid var(--border-subtle); padding-top: 20px; }
        .pillar-list li { font-size: 13.5px; color: var(--text-primary); font-weight: 600; display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
        .pillar-list li svg { color: var(--brand-emerald); flex-shrink: 0; }

        /* ASYMMETRIC BENTO GRID (12 MODULES) */
        .bento-section { padding: 100px 0; background: var(--bg-neutral); }
        .bento-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; }
        .bento-item { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px; display: flex; flex-direction: column; transition: all 0.2s ease; }
        .bento-item:hover { box-shadow: var(--shadow-lg); border-color: #cbd5e1; transform: translateY(-2px); }
        .bento-icon { width: 44px; height: 44px; border-radius: 10px; background: #eff6ff; color: var(--brand-primary); display: flex; align-items: center; justify-content: center; margin-bottom: 18px; }
        .bento-item h4 { font-size: 18px; font-weight: 700; color: var(--navy-dark); margin-bottom: 8px; }
        .bento-item p { font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 18px; flex-grow: 1; }
        .bento-preview { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; font-size: 11.5px; color: #475569; margin-bottom: 16px; font-family: monospace; }
        .bento-link { font-size: 13px; font-weight: 700; color: var(--brand-primary); display: inline-flex; align-items: center; gap: 6px; }
        .bento-link:hover { gap: 9px; }

        /* INDUSTRY SOLUTIONS SECTION */
        .industry-section { padding: 100px 0; background: #ffffff; }
        .industry-tabs-nav { display: flex; justify-content: center; gap: 12px; margin-bottom: 48px; flex-wrap: wrap; }
        .ind-tab-btn { padding: 12px 24px; border-radius: 9999px; background: var(--bg-neutral); border: 1px solid var(--border-subtle); font-size: 14.5px; font-weight: 600; color: var(--text-secondary); transition: all 0.2s; }
        .ind-tab-btn.active { background: var(--navy-dark); color: #ffffff; border-color: var(--navy-dark); box-shadow: var(--shadow-md); }
        .ind-panel { display: none; background: #0f172a; border-radius: var(--radius-xl); color: #ffffff; padding: 48px; border: 1px solid #1e293b; }
        .ind-panel.active { display: grid; grid-template-columns: 1fr 1fr; gap: 48px; align-items: center; }
        .ind-panel h3 { font-size: 28px; font-weight: 800; margin-bottom: 16px; color: #ffffff; }
        .ind-panel p.ind-desc { font-size: 15.5px; color: #94a3b8; line-height: 1.65; margin-bottom: 24px; }
        .ind-flow-list { list-style: none; }
        .ind-flow-item { padding: 10px 0; border-bottom: 1px solid #1e293b; font-size: 13.5px; display: flex; align-items: center; gap: 12px; color: #e2e8f0; }
        .ind-flow-item:last-child { border-bottom: none; }
        .ind-flow-tag { font-size: 10.5px; font-weight: 700; background: #1e293b; color: #38bdf8; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }

        /* 7-STEP COMPLIANCE JOURNEY */
        .journey-section { padding: 100px 0; background: var(--bg-neutral); }
        .journey-list { display: grid; grid-template-columns: repeat(7, 1fr); gap: 14px; margin-top: 48px; }
        .journey-step { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 22px 16px; text-align: center; position: relative; transition: all 0.2s; }
        .journey-step:hover { border-color: var(--brand-primary); transform: translateY(-4px); box-shadow: var(--shadow-md); }
        .step-circle { width: 36px; height: 36px; border-radius: 50%; background: #eff6ff; color: var(--brand-primary); font-weight: 800; font-size: 14px; display: flex; align-items: center; justify-content: center; margin: 0 auto 14px auto; }
        .journey-step h5 { font-size: 13.5px; font-weight: 700; color: var(--navy-dark); margin-bottom: 6px; }
        .journey-step p { font-size: 11.5px; color: var(--text-muted); line-height: 1.5; }

        /* PRODUCT EXPERIENCE TABS */
        .experience-section { padding: 100px 0; background: #ffffff; }
        .exp-tabs-nav { display: flex; justify-content: center; gap: 8px; margin-bottom: 36px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px; }
        .exp-tab-btn { padding: 10px 20px; font-size: 14px; font-weight: 600; color: var(--text-muted); background: transparent; border-bottom: 2px solid transparent; border-radius: 6px; transition: all 0.2s; }
        .exp-tab-btn.active { color: var(--brand-primary); border-bottom-color: var(--brand-primary); background: #eff6ff; }
        .exp-preview-frame { background: #0f172a; border-radius: var(--radius-xl); border: 1px solid #334155; padding: 32px; color: #f8fafc; box-shadow: var(--shadow-xl); }
        .exp-content-box { display: none; }
        .exp-content-box.active { display: block; }

        /* STATUTORY TIMELINE */
        .timeline-section { padding: 100px 0; background: #090e17; color: #ffffff; }
        .timeline-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 48px; }
        .timeline-card { background: #0f172a; border: 1px solid #1e293b; border-radius: var(--radius-lg); padding: 24px; position: relative; }
        .timeline-date { font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 8px; }
        .timeline-card h4 { font-size: 16px; font-weight: 700; margin-bottom: 8px; color: #ffffff; }
        .timeline-card p { font-size: 13px; color: #94a3b8; line-height: 1.55; margin-bottom: 16px; }
        .timeline-badge { font-size: 10.5px; font-weight: 700; padding: 3px 8px; border-radius: 4px; display: inline-block; }
        .tbadge-done { background: rgba(5, 150, 105, 0.2); color: #34d399; }
        .tbadge-scheduled { background: rgba(2, 132, 199, 0.2); color: #38bdf8; }

        /* INTEGRATIONS & TRUST */
        .integrations-section { padding: 90px 0; background: #ffffff; text-align: center; }
        .integrations-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 18px; margin-top: 40px; }
        .int-card { background: var(--bg-neutral); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 20px; text-align: left; display: flex; align-items: center; justify-content: space-between; }
        .int-card h5 { font-size: 14px; font-weight: 700; color: var(--navy-dark); }
        .int-pill { font-size: 10.5px; font-weight: 700; padding: 3px 8px; border-radius: 4px; }
        .int-avail { background: #dcfce7; color: #15803d; }
        .int-soon { background: #f1f5f9; color: #64748b; }

        /* PRICING */
        .pricing-section { padding: 100px 0; background: var(--bg-neutral); }
        .pricing-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 28px; }
        .pricing-card { background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; display: flex; flex-direction: column; transition: all 0.2s; position: relative; }
        .pricing-card.featured { border-color: var(--brand-primary); box-shadow: var(--shadow-xl); transform: scale(1.02); }
        .featured-tag { position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: var(--brand-primary); color: #ffffff; font-size: 11px; font-weight: 700; padding: 4px 14px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px; }
        .pricing-card h3 { font-size: 20px; font-weight: 800; color: var(--navy-dark); margin-bottom: 6px; }
        .pricing-card p.plan-sub { font-size: 13.5px; color: var(--text-muted); margin-bottom: 20px; }
        .plan-price { font-size: 42px; font-weight: 850; color: var(--navy-dark); line-height: 1; margin-bottom: 24px; }
        .plan-price span { font-size: 14px; font-weight: 500; color: var(--text-muted); }
        .plan-features { list-style: none; margin-bottom: 32px; flex-grow: 1; }
        .plan-features li { font-size: 13.5px; color: var(--text-secondary); margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }
        .plan-features li svg { color: var(--brand-emerald); flex-shrink: 0; }

        /* FAQ */
        .faq-section { padding: 100px 0; background: #ffffff; }
        .faq-accordion { max-width: 800px; margin: 0 auto; }
        .faq-item { border-bottom: 1px solid var(--border-subtle); padding: 22px 0; }
        .faq-question { font-size: 16.5px; font-weight: 700; color: var(--navy-dark); cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .faq-answer { font-size: 14.5px; color: var(--text-secondary); line-height: 1.65; margin-top: 12px; display: none; }
        .faq-item.open .faq-answer { display: block; }
        .faq-item.open .faq-icon { transform: rotate(180deg); }
        .faq-icon { transition: transform 0.2s; }

        /* FINAL CTA */
        .cta-banner { background: linear-gradient(135deg, #090e17 0%, #1e293b 100%); color: #ffffff; border-radius: var(--radius-xl); padding: 72px 48px; text-align: center; margin: 60px 0 100px 0; position: relative; overflow: hidden; border: 1px solid #334155; }
        .cta-banner h2 { font-size: 40px; font-weight: 850; margin-bottom: 16px; letter-spacing: -1px; }
        .cta-banner p { font-size: 17.5px; color: #94a3b8; max-width: 620px; margin: 0 auto 36px auto; }

        /* FOOTER */
        footer.site-footer { background: #090e17; color: #94a3b8; padding: 64px 0 36px 0; border-top: 1px solid #1e293b; font-size: 13.5px; }
        .footer-grid { display: grid; grid-template-columns: 1.5fr 1fr 1fr 1fr; gap: 48px; margin-bottom: 48px; }
        .footer-col h5 { font-size: 14px; font-weight: 700; color: #ffffff; margin-bottom: 18px; }
        .footer-col ul { list-style: none; }
        .footer-col ul li { margin-bottom: 10px; }
        .footer-col ul li a:hover { color: #ffffff; }
        .footer-bottom { display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #1e293b; padding-top: 28px; font-size: 12.5px; }

        /* ONBOARDING MODAL */
        .modal-overlay { position: fixed; inset: 0; background: rgba(9, 14, 23, 0.75); backdrop-filter: blur(4px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px; }
        .modal-overlay.open { display: flex; }
        .modal-card { background: #ffffff; border-radius: var(--radius-lg); width: 100%; max-width: 580px; padding: 32px; box-shadow: var(--shadow-xl); position: relative; max-height: 90vh; overflow-y: auto; }
        .modal-close { position: absolute; top: 20px; right: 20px; background: none; font-size: 20px; color: var(--text-muted); }
        .form-group { margin-bottom: 18px; text-align: left; }
        .form-label { display: block; font-size: 13px; font-weight: 600; color: var(--navy-dark); margin-bottom: 6px; }
        .form-control { width: 100%; padding: 11px 14px; border: 1px solid var(--border-subtle); border-radius: 8px; font-size: 14px; font-family: inherit; }
        .form-control:focus { outline: none; border-color: var(--brand-primary); box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.15); }
        .form-select { width: 100%; padding: 11px 14px; border: 1px solid var(--border-subtle); border-radius: 8px; font-size: 14px; font-family: inherit; background: #ffffff; }

        @media (max-width: 992px) {
            .hero-grid { grid-template-columns: 1fr; }
            .pillars-grid { grid-template-columns: 1fr; }
            .bento-grid { grid-template-columns: 1fr; }
            .ind-panel.active { grid-template-columns: 1fr; }
            .journey-list { grid-template-columns: 1fr; }
            .timeline-cards { grid-template-columns: 1fr; }
            .pricing-grid { grid-template-columns: 1fr; }
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
                <li><a href="#pillars">Core Pillars</a></li>
                <li><a href="#modules">Product Modules</a></li>
                <li><a href="#industries">Industries</a></li>
                <li><a href="#timeline">DPDP Timeline</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="/trust">Trust Centre</a></li>
            </ul>
            <div class="nav-actions">
                <a href="/dashboard" class="btn btn-secondary" style="padding: 9px 18px; font-size: 14px;">Sign In</a>
                <button onclick="openOnboardingModal()" class="btn btn-primary" style="padding: 9px 20px; font-size: 14px;">Start Assessment</button>
            </div>
        </div>
    </nav>

    <!-- SECTION 1 — HERO -->
    <header class="hero">
        <div class="container hero-grid">
            <div class="hero-content">
                <div class="eyebrow">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    DPDP COMPLIANCE MANAGEMENT PLATFORM
                </div>
                <h1>Your DPDP Compliance Journey, <span class="gradient-text">Simplified.</span></h1>
                <p class="hero-lead">
                    Know what personal data you collect, understand which DPDP requirements apply, close compliance gaps, manage Data Principal rights, and maintain verified evidence — all in one place.
                </p>
                <div class="hero-btns">
                    <button onclick="openOnboardingModal()" class="btn btn-primary">
                        <span>Start Free Assessment</span>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                    </button>
                    <a href="/dashboard#scanner" class="btn btn-secondary" style="border-color: var(--brand-primary); color: var(--brand-primary); font-weight: 700;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/></svg>
                        <span>Scan Your Website &rarr;</span>
                    </a>
                    <a href="#experience" class="btn btn-secondary">
                        <span>Explore Platform</span>
                    </a>
                </div>
                <div class="hero-trust-strip">
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>India DPDP Act 2023 & Rules 2025</span>
                    </div>
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>Clinics, Diagnostic & SME Ready</span>
                    </div>
                    <div class="hero-trust-item">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        <span>Zero Raw Patient Data Collection</span>
                    </div>
                </div>
            </div>

            <!-- HERO DASHBOARD MOCKUP -->
            <div class="hero-mockup-wrap">
                <div class="hero-mockup-card">
                    <div class="mockup-topbar">
                        <div class="mockup-dots">
                            <div class="mockup-dot" style="background: #ef4444;"></div>
                            <div class="mockup-dot" style="background: #f59e0b;"></div>
                            <div class="mockup-dot" style="background: #10b981;"></div>
                        </div>
                        <div class="mockup-title">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <span>TrustAudit DPDP Command Center &bull; Healthcare Workspace</span>
                        </div>
                        <span class="mockup-pill pill-emerald">Live Demo</span>
                    </div>

                    <div class="mockup-grid">
                        <div class="mockup-box">
                            <div class="mockup-box-lbl">DPDP Readiness Status</div>
                            <div class="mockup-box-val" style="color: #38bdf8;">82%</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">15 Controls Assessed &bull; 3 Gaps</div>
                        </div>
                        <div class="mockup-box">
                            <div class="mockup-box-lbl">Personal Data Inventory</div>
                            <div class="mockup-box-val" style="color: #34d399;">18 Entries</div>
                            <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Reception, OPD, Diagnostics, HR</div>
                        </div>
                    </div>

                    <div class="mockup-box" style="margin-bottom: 12px; padding: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span style="font-size: 11px; font-weight: 700; color: #cbd5e1;">ACTIVE WORKFLOWS &amp; STATUTORY GATES</span>
                            <span class="mockup-pill pill-amber">May 2027 Scheduled</span>
                        </div>
                        <div class="mockup-row">
                            <span>Itemised Privacy Notice (Sec 5 / Rule 3)</span>
                            <span style="color: #34d399; font-weight: 600;">Drafted &bull; English + Hindi</span>
                        </div>
                        <div class="mockup-row">
                            <span>Consent Withdrawal Mechanism (Sec 6(4))</span>
                            <span style="color: #34d399; font-weight: 600;">Active &bull; Processor Cascaded</span>
                        </div>
                        <div class="mockup-row">
                            <span>Data Principal Access Request (Sec 11)</span>
                            <span style="color: #38bdf8; font-weight: 600;">2 Tickets In Progress</span>
                        </div>
                        <div class="mockup-row">
                            <span>Diagnostic Lab DPA Contracts (Sec 8(2))</span>
                            <span style="color: #fbbf24; font-weight: 600;">1 Vendor Review Pending</span>
                        </div>
                    </div>
                </div>

                <!-- Floating Badges -->
                <div class="floating-badge badge-1">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    <div>
                        <div style="font-size: 13px; font-weight: 700;">Section 6(4) Ready</div>
                        <div style="font-size: 11px; color: var(--text-muted);">Easy Consent Withdrawal</div>
                    </div>
                </div>

                <div class="floating-badge badge-2">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#1d4ed8" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <div>
                        <div style="font-size: 13px; font-weight: 700;">Evidence Vault</div>
                        <div style="font-size: 11px; color: var(--text-muted);">SHA-256 Audit Records</div>
                    </div>
                </div>
            </div>
        </div>
    </header>

    <!-- SECTION 2 — THE BUSINESS PROBLEM -->
    <section class="problem-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow eyebrow-dark">THE DPDP REALITY</div>
                <h2 class="section-title section-title-dark">Your Business Handles Personal Data Every Day.<br>Can You Account for It?</h2>
                <p class="section-subtext section-subtext-dark">
                    Under India's Digital Personal Data Protection Act, 2023, personal data scattered across spreadsheets, billing software, and third-party SaaS creates significant legal exposure.
                </p>
            </div>

            <div class="problem-grid">
                <div class="problem-card">
                    <div class="problem-num">01 / DISPERSION</div>
                    <h3>Data is Scattered Across Silos</h3>
                    <p>Patient and customer records sit across reception computers, WhatsApp messages, paper intake forms, pathology machines, and multiple cloud drives.</p>
                </div>
                <div class="problem-card">
                    <div class="problem-num">02 / UNCERTAINTY</div>
                    <h3>Unclear Statutory Applicability</h3>
                    <p>Businesses struggle to determine which specific provisions apply now versus those scheduled for May 2027, leading to compliance confusion.</p>
                </div>
                <div class="problem-card">
                    <div class="problem-num">03 / CONSENT DEFICIT</div>
                    <h3>Inconsistent Notices &amp; Consent</h3>
                    <p>Privacy policies are often generic website copy rather than the legally mandated Section 5 itemised notice in Eighth Schedule languages.</p>
                </div>
                <div class="problem-card">
                    <div class="problem-num">04 / VENDOR BLINDSPOTS</div>
                    <h3>Untracked Data Processors</h3>
                    <p>Hospitals and startups share sensitive personal data with IT vendors and diagnostic labs without valid Section 8(2) Data Processing Agreements.</p>
                </div>
                <div class="problem-card">
                    <div class="problem-num">05 / MANUAL RIGHTS</div>
                    <h3>No Workflow for Rights Requests</h3>
                    <p>When an individual requests data correction, erasure, or consent withdrawal, teams scramble manually without audit logs or statutory tracking.</p>
                </div>
                <div class="problem-card">
                    <div class="problem-num">06 / EVIDENCE VOID</div>
                    <h3>Scattered Compliance Proofs</h3>
                    <p>When auditors or regulators inquire, compliance proofs are lost across emails and desktop folders rather than organized in an immutable vault.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 3 — THREE MAIN PILLARS -->
    <section id="pillars" class="pillars-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">A COMPLETE COMPLIANCE OPERATING MODEL</div>
                <h2 class="section-title">From Data Discovery to Continuous Compliance.</h2>
                <p class="section-subtext">
                    TrustAudit structures your compliance journey around three foundational pillars designed for healthcare providers, SaaS businesses, and growing enterprises.
                </p>
            </div>

            <div class="pillars-grid">
                <!-- PILLAR 1 -->
                <div class="pillar-card">
                    <div class="pillar-badge">PILLAR 01</div>
                    <h3>DISCOVER</h3>
                    <p>Gain absolute clarity over the personal data your organisation collects, stores, processes, and shares.</p>
                    <ul class="pillar-list">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Centralized Personal Data Inventory</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Processing Activities by Department</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Sources, Systems &amp; Third-Party Flow</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Section 6 &amp; 7 Purpose Mapping</li>
                    </ul>
                </div>

                <!-- PILLAR 2 -->
                <div class="pillar-card" style="border-color: #cbd5e1; box-shadow: var(--shadow-md);">
                    <div class="pillar-badge" style="color: var(--brand-accent);">PILLAR 02</div>
                    <h3>ASSESS</h3>
                    <p>Evaluate your operational controls against the DPDP Act 2023, Rules 2025, and statutory timelines.</p>
                    <ul class="pillar-list">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Dynamic DPDP Questionnaire Engine</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Notice &amp; Consent Architecture Review</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Security Safeguards (Rule 6) Evaluation</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Automated Compliance Gap Analysis</li>
                    </ul>
                </div>

                <!-- PILLAR 3 -->
                <div class="pillar-card">
                    <div class="pillar-badge" style="color: var(--brand-emerald);">PILLAR 03</div>
                    <h3>MANAGE</h3>
                    <p>Operate, maintain, and prove continuous compliance with built-in workflows and evidence tracking.</p>
                    <ul class="pillar-list">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Itemised Notice &amp; Consent Workflows</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Data Principal Rights Ticketing System</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Rule 8 Retention Schedules &amp; Purging</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Dual-Stage Breach Intimation Generator</li>
                    </ul>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 4 — PRODUCT MODULES (BENTO GRID) -->
    <section id="modules" class="bento-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">ENTERPRISE FUNCTIONALITY</div>
                <h2 class="section-title">Everything Your Organisation Needs to Manage DPDP.</h2>
                <p class="section-subtext">
                    Twelve purpose-built modules designed to guide you through discovery, assessment, operational workflows, and audit-grade record keeping.
                </p>
            </div>

            <div class="bento-grid">
                <!-- 00 WEBSITE SCANNER -->
                <div class="bento-item" style="border-color: #38bdf8; background: linear-gradient(180deg, #ffffff 0%, #f0f9ff 100%);">
                    <div class="bento-icon" style="background: #e0f2fe; color: #0284c7;"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg></div>
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                        <h4 style="margin-bottom: 0;">01. DPDP Website Scanner</h4>
                        <span style="font-size: 10px; font-weight: 800; background: #0284c7; color: #ffffff; padding: 2px 7px; border-radius: 9999px;">NEW FEATURE</span>
                    </div>
                    <p>Passive perimeter discovery engine. Inspects public pages, evaluates Section 5 privacy notices, flags pre-ticked consent checkboxes, and audits third-party tracking scripts.</p>
                    <div class="bento-preview">Observation: Notice &bull; Forms &bull; Trackers &bull; Grievance Redressal</div>
                    <a href="/dashboard#scanner" class="bento-link" style="color: #0284c7;">Launch Website Scanner &rarr;</a>
                </div>

                <!-- 01 ASSESSMENT -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
                    <h4>01. DPDP Assessment Engine</h4>
                    <p>Dynamic questionnaires tailored to your business activities, evaluating readiness against statutory requirements.</p>
                    <div class="bento-preview">Status: 15 Requirements Evaluated &bull; Branching Questions</div>
                    <a href="/dashboard?section=assessment" class="bento-link">Launch Engine &rarr;</a>
                </div>

                <!-- 02 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
                    <h4>02. Personal Data Inventory</h4>
                    <p>Catalog all digital personal data, collection sources, legal bases, storage systems, and retention periods with CSV import/export.</p>
                    <div class="bento-preview">Templates: Clinics &bull; Diagnostics &bull; SaaS &bull; E-Commerce</div>
                    <a href="/dashboard?section=inventory" class="bento-link">Explore Inventory &rarr;</a>
                </div>

                <!-- 03 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></div>
                    <h4>03. Privacy Notice Management</h4>
                    <p>Generate itemised notices under Section 5 and Rule 3 with Grievance Officer details and Eighth Schedule language readiness.</p>
                    <div class="bento-preview">Languages: English &bull; Hindi &bull; Regional Translations</div>
                    <a href="/dashboard?section=privacy" class="bento-link">Manage Notices &rarr;</a>
                </div>

                <!-- 04 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg></div>
                    <h4>04. Consent Records &amp; Withdrawal</h4>
                    <p>Track purpose-specific consent logs and execute Section 6(4) withdrawal workflows that cascade instructions to processors.</p>
                    <div class="bento-preview">Feature: Processor Cease-Processing Protocols</div>
                    <a href="/dashboard?section=consent" class="bento-link">View Consent Logs &rarr;</a>
                </div>

                <!-- 05 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div>
                    <h4>05. Data Principal Rights Management</h4>
                    <p>End-to-end ticketing for statutory access, correction, erasure, grievance, and nomination requests (Sections 11–14).</p>
                    <div class="bento-preview">SLA Tracker: 30-Day Resolution Dashboard</div>
                    <a href="/dashboard?section=rights" class="bento-link">Open Rights Desk &rarr;</a>
                </div>

                <!-- 06 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
                    <h4>06. Vendor &amp; Processor Register</h4>
                    <p>Maintain your Section 8(2) register of third-party software, labs, and cloud hosts with executed DPA contracts and review cycles.</p>
                    <div class="bento-preview">Tracking: Agreement Expiry &bull; India Hosting Verification</div>
                    <a href="/dashboard?section=vendors" class="bento-link">Manage Vendors &rarr;</a>
                </div>

                <!-- 07 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
                    <h4>07. Retention &amp; Erasure Schedules</h4>
                    <p>Configure purpose-specific retention rules under Rule 8 and harmonize medical or tax laws with automated purging alerts.</p>
                    <div class="bento-preview">Schedules: Clinical 3-5 Yrs &bull; Accounting 8 Yrs</div>
                    <a href="/dashboard?section=retention" class="bento-link">Configure Retention &rarr;</a>
                </div>

                <!-- 08 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
                    <h4>08. Personal Data Breach Centre</h4>
                    <p>Manage security incident workflows under Section 8(6) and Rule 7 with dual-stage drafts for Board and Data Principal intimations.</p>
                    <div class="bento-preview">Templates: Immediate Preliminary &bull; 72h Forensic Form</div>
                    <a href="/dashboard?section=breach" class="bento-link">Incident Desk &rarr;</a>
                </div>

                <!-- 09 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
                    <h4>09. Evidence Vault</h4>
                    <p>Centralized, tenant-isolated repository for policies, DPAs, consent forms, training logs, and deletion certificates with SHA-256 integrity.</p>
                    <div class="bento-preview">Security: AES-256 at Rest &bull; Zero Cross-Tenant Access</div>
                    <a href="/dashboard?section=evidence" class="bento-link">Access Vault &rarr;</a>
                </div>

                <!-- 10 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg></div>
                    <h4>10. Compliance Remediation Centre</h4>
                    <p>Actionable remediation tasks linked directly to identified gaps with statutory explanations, templates, owners, and deadlines.</p>
                    <div class="bento-preview">Tracking: Priority &bull; SLA &bull; Verification Status</div>
                    <a href="/dashboard?section=remediation" class="bento-link">View Remediation &rarr;</a>
                </div>

                <!-- 11 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                    <h4>11. Children's Data Assessment</h4>
                    <p>Verifiable parental consent workflows and profiling restriction audits under Section 9 and the October 2026 Removal of Difficulties Order.</p>
                    <div class="bento-preview">Safeguards: No Behavioral Profiling &bull; Minor Age Check</div>
                    <a href="/dashboard?section=assessment" class="bento-link">Assess Child Data &rarr;</a>
                </div>

                <!-- 12 -->
                <div class="bento-item">
                    <div class="bento-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div>
                    <h4>12. Significant Data Fiduciary Assessment</h4>
                    <p>Evaluate whether your organisation crosses notified processing thresholds requiring resident DPO appointment and independent DPIA audits.</p>
                    <div class="bento-preview">Governance: Section 10 Threshold Analysis</div>
                    <a href="/dashboard?section=assessment" class="bento-link">Evaluate SDF &rarr;</a>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 5 — INDUSTRY SOLUTIONS -->
    <section id="industries" class="industry-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">TAILORED COMPLIANCE WORKFLOWS</div>
                <h2 class="section-title">DPDP Workflows Designed Around Your Business.</h2>
                <p class="section-subtext">
                    Healthcare establishments, schools, SaaS providers, and retailers process fundamentally different types of personal data. TrustAudit pre-configures workflows for your sector.
                </p>
            </div>

            <div class="industry-tabs-nav">
                <button class="ind-tab-btn active" onclick="switchIndustry('healthcare', this)">Healthcare &amp; Clinics</button>
                <button class="ind-tab-btn" onclick="switchIndustry('education', this)">Education &amp; Schools</button>
                <button class="ind-tab-btn" onclick="switchIndustry('saas', this)">SaaS &amp; Tech Startups</button>
                <button class="ind-tab-btn" onclick="switchIndustry('ecommerce', this)">E-Commerce &amp; Retail</button>
            </div>

            <!-- HEALTHCARE PANEL -->
            <div id="ind-panel-healthcare" class="ind-panel active">
                <div>
                    <div class="eyebrow eyebrow-dark">PRIMARY FOCUS</div>
                    <h3>Clinics, Diagnostic Centres &amp; Hospitals</h3>
                    <p class="ind-desc">
                        Medical clinics handle sensitive patient health records, diagnostic imaging, and insurance data daily. TrustAudit maps out registration desk forms, pathology lab software, and medical retention rules without touching raw patient data.
                    </p>
                    <ul class="ind-flow-list">
                        <li class="ind-flow-item"><span class="ind-flow-tag">RECEPTION</span> Patient registration, contact details &amp; appointment booking</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">OPD</span> Consultation records, clinical history &amp; follow-up advice</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">LABORATORY</span> Diagnostic pathology reports, blood tests &amp; LIMS systems</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">BILLING</span> Invoices, payment receipts &amp; insurance TPA claim data</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">VENDORS</span> Hospital management software, diagnostic cloud &amp; SMS gateways</li>
                    </ul>
                    <div style="margin-top: 24px;">
                        <button onclick="openOnboardingModal('healthcare')" class="btn btn-dark">Deploy Healthcare Template</button>
                    </div>
                </div>
                <div style="background: #1e293b; border-radius: var(--radius-lg); padding: 24px; border: 1px solid #334155;">
                    <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 12px;">PRE-SEEDED HEALTHCARE TEMPLATES INCLUDED</div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 10px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Patient Privacy Notice (English &amp; Hindi)</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Itemised notice covering consultation, diagnostics, and rights.</div>
                    </div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 10px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Clinical Records Retention Schedule</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Aligned with State Clinical Establishments Acts (3-5 years).</div>
                    </div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Minor Patient Parental Consent Form</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Verifiable consent under Section 9 &amp; October 2026 Order.</div>
                    </div>
                </div>
            </div>

            <!-- EDUCATION PANEL -->
            <div id="ind-panel-education" class="ind-panel">
                <div>
                    <div class="eyebrow eyebrow-dark">ACADEMIC SECTOR</div>
                    <h3>Schools, Colleges &amp; EdTech</h3>
                    <p class="ind-desc">
                        Educational institutions manage minor student records, parent communications, and admission records requiring strict compliance with Section 9 parental consent provisions.
                    </p>
                    <ul class="ind-flow-list">
                        <li class="ind-flow-item"><span class="ind-flow-tag">ADMISSIONS</span> Student registration, guardian identity &amp; contact logs</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">SECTION 9</span> Verifiable parental consent &amp; age-verification workflows</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">ACADEMIC</span> Exam scorecards, certificates &amp; school ERP storage</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">EDTECH</span> Learning software vendor oversight &amp; data privacy clauses</li>
                    </ul>
                    <div style="margin-top: 24px;">
                        <button onclick="openOnboardingModal('education')" class="btn btn-dark">Deploy Education Template</button>
                    </div>
                </div>
                <div style="background: #1e293b; border-radius: var(--radius-lg); padding: 24px; border: 1px solid #334155;">
                    <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 12px;">KEY EDUCATIONAL CONTROLS</div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 10px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Parental Guardian Verification Workflow</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Meets Section 9 verifiable parental consent requirements.</div>
                    </div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Zero Student Behavioral Tracking Policy</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Ensures educational apps do not profile minors.</div>
                    </div>
                </div>
            </div>

            <!-- SAAS PANEL -->
            <div id="ind-panel-saas" class="ind-panel">
                <div>
                    <div class="eyebrow eyebrow-dark">TECH STARTUPS</div>
                    <h3>SaaS &amp; Technology Companies</h3>
                    <p class="ind-desc">
                        Manage user accounts, telemetry collection, billing info, and cloud subprocessors with automated privacy notices and Section 17 startup exemption analysis.
                    </p>
                    <ul class="ind-flow-list">
                        <li class="ind-flow-item"><span class="ind-flow-tag">ACCOUNTS</span> Signup authentication, user profile &amp; billing records</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">PROCESSORS</span> Cloud hosting (AWS, Render), email gateways &amp; analytics</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">RIGHTS</span> Self-service account deletion &amp; data export workflows</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">CROSS-BORDER</span> Cloud region verification &amp; transfer compliance</li>
                    </ul>
                    <div style="margin-top: 24px;">
                        <button onclick="openOnboardingModal('saas')" class="btn btn-dark">Deploy SaaS Template</button>
                    </div>
                </div>
                <div style="background: #1e293b; border-radius: var(--radius-lg); padding: 24px; border: 1px solid #334155;">
                    <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 12px;">KEY SAAS CONTROLS</div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 10px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Subprocessor Register &amp; DPA Registry</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Section 8(2) compliance for tech supply chains.</div>
                    </div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Rule 13 Startup Exemption Evaluator</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Determines qualifying eligibility for DPIA exemptions.</div>
                    </div>
                </div>
            </div>

            <!-- ECOMMERCE PANEL -->
            <div id="ind-panel-ecommerce" class="ind-panel">
                <div>
                    <div class="eyebrow eyebrow-dark">DIGITAL COMMERCE</div>
                    <h3>E-Commerce &amp; Retail Businesses</h3>
                    <p class="ind-desc">
                        Catalog customer delivery addresses, order histories, payment gateway tokens, and marketing consent with unbundled opt-ins and courier DPAs.
                    </p>
                    <ul class="ind-flow-list">
                        <li class="ind-flow-item"><span class="ind-flow-tag">CHECKOUT</span> Customer shipping address &amp; mobile contact logs</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">LOGISTICS</span> Courier partners, delivery aggregators &amp; tracking APIs</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">CONSENT</span> Separate unbundled marketing opt-in checkboxes</li>
                        <li class="ind-flow-item"><span class="ind-flow-tag">RETENTION</span> Order data retention for GST/accounting reconciliation</li>
                    </ul>
                    <div style="margin-top: 24px;">
                        <button onclick="openOnboardingModal('ecommerce')" class="btn btn-dark">Deploy Retail Template</button>
                    </div>
                </div>
                <div style="background: #1e293b; border-radius: var(--radius-lg); padding: 24px; border: 1px solid #334155;">
                    <div style="font-size: 13px; font-weight: 700; color: #38bdf8; margin-bottom: 12px;">KEY E-COMMERCE CONTROLS</div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; margin-bottom: 10px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Unbundled Checkout Consent Matrix</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Separates delivery fulfillment from marketing updates.</div>
                    </div>
                    <div style="background: #0f172a; padding: 14px; border-radius: 8px; font-size: 13px;">
                        <div style="font-weight: 600; color: #ffffff;">Logistics Partner Data Agreement</div>
                        <div style="color: #94a3b8; font-size: 11.5px; margin-top: 4px;">Restricts address usage solely to shipping completion.</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 6 — HOW TRUSTAUDIT WORKS -->
    <section class="journey-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">STEP-BY-STEP WORKFLOW</div>
                <h2 class="section-title">How TrustAudit Works.</h2>
                <p class="section-subtext">
                    A structured seven-step journey taking your organisation from initial data mapping to continuous, verifiable compliance.
                </p>
            </div>

            <div class="journey-list">
                <div class="journey-step">
                    <div class="step-circle">01</div>
                    <h5>Profile Setup</h5>
                    <p>Enter business scope, entity type &amp; locations.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">02</div>
                    <h5>Select Industry</h5>
                    <p>Choose healthcare, SaaS, or retail template.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">03</div>
                    <h5>Discover Data</h5>
                    <p>Map departments, sources, and data categories.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">04</div>
                    <h5>Run Assessment</h5>
                    <p>Answer dynamic DPDP requirements checks.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">05</div>
                    <h5>Identify Gaps</h5>
                    <p>Surface missing notices, DPAs, and workflows.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">06</div>
                    <h5>Remediate</h5>
                    <p>Generate notices, collect evidence, fix gaps.</p>
                </div>
                <div class="journey-step">
                    <div class="step-circle">07</div>
                    <h5>Monitor</h5>
                    <p>Maintain continuous audit readiness &amp; logs.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 7 — PRODUCT EXPERIENCE -->
    <section id="experience" class="experience-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">INTERACTIVE PREVIEW</div>
                <h2 class="section-title">The TrustAudit Product Experience.</h2>
                <p class="section-subtext">
                    Switch between tabs below to preview the actual compliance workspace configured for an Indian healthcare establishment.
                </p>
            </div>

            <div class="exp-tabs-nav">
                <button class="exp-tab-btn active" onclick="switchExpTab('overview', this)">Overview</button>
                <button class="exp-tab-btn" onclick="switchExpTab('assessment', this)">DPDP Assessment</button>
                <button class="exp-tab-btn" onclick="switchExpTab('inventory', this)">Data Inventory</button>
                <button class="exp-tab-btn" onclick="switchExpTab('evidence', this)">Evidence Vault</button>
                <button class="exp-tab-btn" onclick="switchExpTab('remediation', this)">Remediation</button>
            </div>

            <div class="exp-preview-frame">
                <!-- TAB 1: OVERVIEW -->
                <div id="exp-tab-overview" class="exp-content-box active">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <div>
                            <h3 style="font-size: 20px; font-weight: 700; color: #ffffff;">Arogya Diagnostics &amp; Clinic &bull; DPDP Command Center</h3>
                            <div style="font-size: 12.5px; color: #94a3b8;">Bengaluru Clinic Branch &bull; Healthcare Sector &bull; <span style="color: #38bdf8;">DEMO PREVIEW</span></div>
                        </div>
                        <span class="mockup-pill pill-emerald">Readiness: 82%</span>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px;">
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-size: 11px; color: #94a3b8;">APPLICABLE REQUIREMENTS</div>
                            <div style="font-size: 24px; font-weight: 800; color: #ffffff; margin-top: 4px;">15</div>
                            <div style="font-size: 11px; color: #34d399;">12 Addressed</div>
                        </div>
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-size: 11px; color: #94a3b8;">DATA INVENTORY</div>
                            <div style="font-size: 24px; font-weight: 800; color: #ffffff; margin-top: 4px;">18 Categories</div>
                            <div style="font-size: 11px; color: #38bdf8;">6 Departments</div>
                        </div>
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-size: 11px; color: #94a3b8;">ACTIVE GAPS</div>
                            <div style="font-size: 24px; font-weight: 800; color: #fbbf24; margin-top: 4px;">3 Identified</div>
                            <div style="font-size: 11px; color: #94a3b8;">Remediation in progress</div>
                        </div>
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-size: 11px; color: #94a3b8;">EVIDENCE VAULT</div>
                            <div style="font-size: 24px; font-weight: 800; color: #ffffff; margin-top: 4px;">14 Artifacts</div>
                            <div style="font-size: 11px; color: #34d399;">SHA-256 Verified</div>
                        </div>
                    </div>
                </div>

                <!-- TAB 2: ASSESSMENT -->
                <div id="exp-tab-assessment" class="exp-content-box">
                    <h3 style="font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 12px;">DPDP Requirements Assessment Matrix</h3>
                    <div style="background: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; font-size: 13px;">
                        <div style="display: grid; grid-template-columns: 1.2fr 2fr 1fr 1fr; padding: 12px 16px; background: #0f172a; font-weight: 700; color: #94a3b8; border-bottom: 1px solid #334155;">
                            <div>SECTION</div>
                            <div>STATUTORY TITLE</div>
                            <div>TIMELINE</div>
                            <div>STATUS</div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.2fr 2fr 1fr 1fr; padding: 12px 16px; border-bottom: 1px solid #334155;">
                            <div style="color: #38bdf8; font-weight: 600;">Section 5 / Rule 3</div>
                            <div>Itemised Notice in Eighth Schedule Languages</div>
                            <div>13 May 2027</div>
                            <div><span class="mockup-pill pill-amber">Gap: Multi-lingual Missing</span></div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.2fr 2fr 1fr 1fr; padding: 12px 16px; border-bottom: 1px solid #334155;">
                            <div style="color: #38bdf8; font-weight: 600;">Section 6(4)-(6)</div>
                            <div>Consent Withdrawal &amp; Processor Cascading</div>
                            <div>13 May 2027</div>
                            <div><span class="mockup-pill pill-emerald">Implemented</span></div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.2fr 2fr 1fr 1fr; padding: 12px 16px;">
                            <div style="color: #38bdf8; font-weight: 600;">Section 8(2)</div>
                            <div>Valid DPA Contracts with Data Processors</div>
                            <div>13 May 2027</div>
                            <div><span class="mockup-pill pill-amber">Gap: Lab Contract Review</span></div>
                        </div>
                    </div>
                </div>

                <!-- TAB 3: INVENTORY -->
                <div id="exp-tab-inventory" class="exp-content-box">
                    <h3 style="font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 12px;">Healthcare Personal Data Inventory (Sample Entries)</h3>
                    <div style="background: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; font-size: 12.5px;">
                        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1.5fr 1fr 1fr; padding: 12px 16px; background: #0f172a; font-weight: 700; color: #94a3b8; border-bottom: 1px solid #334155;">
                            <div>DATA CATEGORY</div>
                            <div>PRINCIPAL</div>
                            <div>PURPOSE &amp; LEGAL BASIS</div>
                            <div>STORAGE</div>
                            <div>RETENTION</div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1.5fr 1fr 1fr; padding: 12px 16px; border-bottom: 1px solid #334155;">
                            <div style="font-weight: 600; color: #ffffff;">Patient Demographics &amp; Phone</div>
                            <div>Patients</div>
                            <div>Consultation / Sec 6 Consent</div>
                            <div>Local HMS + Cloud</div>
                            <div>3 Years</div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1.5fr 1fr 1fr; padding: 12px 16px; border-bottom: 1px solid #334155;">
                            <div style="font-weight: 600; color: #ffffff;">Diagnostic Pathology Reports</div>
                            <div>Patients</div>
                            <div>Diagnosis / Sec 7(e) Emergency</div>
                            <div>LIMS Cloud (India)</div>
                            <div>5 Years</div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1.5fr 1fr 1.5fr 1fr 1fr; padding: 12px 16px;">
                            <div style="font-weight: 600; color: #ffffff;">Medical Billing &amp; Invoices</div>
                            <div>Patients</div>
                            <div>Billing / Sec 7(c) Tax Law</div>
                            <div>Accounting ERP</div>
                            <div>8 Years</div>
                        </div>
                    </div>
                </div>

                <!-- TAB 4: EVIDENCE -->
                <div id="exp-tab-evidence" class="exp-content-box">
                    <h3 style="font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 12px;">Evidence Vault (Tenant-Isolated Cryptographic Proofs)</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-weight: 700; color: #ffffff;">Patient_Privacy_Notice_v1.0.pdf</div>
                            <div style="font-size: 11.5px; color: #94a3b8; margin: 4px 0;">Mapped to: Section 5 (Notice) &bull; Verified Review</div>
                            <div style="font-size: 11px; font-family: monospace; color: #38bdf8;">SHA-256: 7f83b1657ff1fc53b92dc18148a1...</div>
                        </div>
                        <div style="background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155;">
                            <div style="font-weight: 700; color: #ffffff;">Diagnostic_Lab_DPA_Executed.pdf</div>
                            <div style="font-size: 11.5px; color: #94a3b8; margin: 4px 0;">Mapped to: Section 8(2) (Processor Contract) &bull; Active</div>
                            <div style="font-size: 11px; font-family: monospace; color: #38bdf8;">SHA-256: 3c9909afec25354d551dae2159...</div>
                        </div>
                    </div>
                </div>

                <!-- TAB 5: REMEDIATION -->
                <div id="exp-tab-remediation" class="exp-content-box">
                    <h3 style="font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 12px;">Active Compliance Remediation Tasks</h3>
                    <div style="background: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 16px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 10px;">
                            <div>
                                <div style="font-weight: 700; color: #ffffff;">Translate Clinic Notice to Hindi &amp; Kannada (Rule 3)</div>
                                <div style="font-size: 12px; color: #94a3b8;">Owner: Clinic Frontdesk Lead &bull; Deadline: 2027-04-30</div>
                            </div>
                            <span class="mockup-pill pill-amber">Open &bull; Priority High</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: 700; color: #ffffff;">Execute DPA Addendum with SMS Gateway Provider</div>
                                <div style="font-size: 12px; color: #94a3b8;">Owner: IT Administrator &bull; Deadline: 2027-05-10</div>
                            </div>
                            <span class="mockup-pill pill-amber">Open &bull; Priority Medium</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 8 — DPDP DEADLINES AND LEGAL FRAMEWORK -->
    <section id="timeline" class="timeline-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow eyebrow-dark">OFFICIAL STATUTORY TIMELINE</div>
                <h2 class="section-title section-title-dark">Stay Prepared for the Applicable DPDP Requirements.</h2>
                <p class="section-subtext section-subtext-dark">
                    The DPDP Act is being implemented in phased stages. TrustAudit distinguishes requirements that are currently in force from those scheduled for commencement.
                </p>
            </div>

            <div class="timeline-cards">
                <div class="timeline-card">
                    <div class="timeline-date">11 AUGUST 2023</div>
                    <h4>DPDP Act Enacted</h4>
                    <p>Passed by Parliament and published in Gazette as Act No. 22 of 2023.</p>
                    <span class="timeline-badge tbadge-done">Statutory Enactment</span>
                </div>
                <div class="timeline-card">
                    <div class="timeline-date">13 NOVEMBER 2025</div>
                    <h4>Rules Notified &bull; Phase 1</h4>
                    <p>DPDP Rules, 2025 notified; Data Protection Board institutional framework commenced.</p>
                    <span class="timeline-badge tbadge-done">In Force</span>
                </div>
                <div class="timeline-card">
                    <div class="timeline-date">13 NOVEMBER 2026</div>
                    <h4>Consent Managers Operative</h4>
                    <p>Section 6(9) and Rule 4 provisions governing Consent Managers become legally effective.</p>
                    <span class="timeline-badge tbadge-done">In Force</span>
                </div>
                <div class="timeline-card" style="border-color: #38bdf8;">
                    <div class="timeline-date" style="color: #38bdf8;">13 MAY 2027</div>
                    <h4>Substantive Fiduciary Obligations</h4>
                    <p>General obligations (notices, safeguards, breach intimation, rights, retention) scheduled to commence.</p>
                    <span class="timeline-badge tbadge-scheduled">Scheduled Commencement</span>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 9 — WHY TRUSTAUDIT -->
    <section class="pillars-section" style="background: var(--bg-neutral);">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">THE TRUSTAUDIT ADVANTAGE</div>
                <h2 class="section-title">More Than a Compliance Checklist.</h2>
                <p class="section-subtext">
                    Generic templates leave your business vulnerable. TrustAudit provides structured workflows built around Indian operating environments and clinical realities.
                </p>
            </div>

            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px;">
                <div style="background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 32px;">
                    <div style="font-size: 28px; margin-bottom: 12px;">🏥</div>
                    <h4 style="font-size: 18px; font-weight: 700; color: var(--navy-dark); margin-bottom: 8px;">Industry-Specific Guidance</h4>
                    <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.6;">Pre-mapped workflows for clinics, diagnostics, and SaaS rather than one-size-fits-all generic spreadsheets.</p>
                </div>
                <div style="background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 32px;">
                    <div style="font-size: 28px; margin-bottom: 12px;">🔒</div>
                    <h4 style="font-size: 18px; font-weight: 700; color: var(--navy-dark); margin-bottom: 8px;">Zero Raw Patient Data Stored</h4>
                    <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.6;">TrustAudit catalogs data flow metadata and policies; we never ingest or store your patients' raw medical records.</p>
                </div>
                <div style="background: #ffffff; border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 32px;">
                    <div style="font-size: 28px; margin-bottom: 12px;">📑</div>
                    <h4 style="font-size: 18px; font-weight: 700; color: var(--navy-dark); margin-bottom: 8px;">Audit-Grade Evidence Vault</h4>
                    <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.6;">Maintain immutable SHA-256 evidence records proving notice delivery, consent withdrawal, and vendor DPA execution.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 10 — INTEGRATIONS -->
    <section class="integrations-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">ECOSYSTEM COMPATIBILITY</div>
                <h2 class="section-title">Designed to Connect With Your Tools.</h2>
                <p class="section-subtext">
                    TrustAudit manages compliance metadata alongside the systems your organization uses every day.
                </p>
            </div>

            <div class="integrations-grid">
                <div class="int-card">
                    <h5>Hospital Management Systems (HMS)</h5>
                    <span class="int-pill int-avail">Available</span>
                </div>
                <div class="int-card">
                    <h5>Google Workspace</h5>
                    <span class="int-pill int-soon">Roadmap</span>
                </div>
                <div class="int-card">
                    <h5>Microsoft 365</h5>
                    <span class="int-pill int-soon">Roadmap</span>
                </div>
                <div class="int-card">
                    <h5>Zoho / Tally Billing</h5>
                    <span class="int-pill int-avail">Available</span>
                </div>
                <div class="int-card">
                    <h5>AWS / Cloud Storage (Mumbai)</h5>
                    <span class="int-pill int-avail">Available</span>
                </div>
                <div class="int-card">
                    <h5>HRMS &amp; Payroll Software</h5>
                    <span class="int-pill int-soon">Roadmap</span>
                </div>
                <div class="int-card">
                    <h5>SMS &amp; WhatsApp Gateways</h5>
                    <span class="int-pill int-avail">Available</span>
                </div>
                <div class="int-card">
                    <h5>Diagnostic LIMS Systems</h5>
                    <span class="int-pill int-avail">Available</span>
                </div>
            </div>
        </div>
    </section>

    <!-- SECTION 11 — PRICING -->
    <section id="pricing" class="pricing-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">TRANSPARENT SUBSCRIPTION TIERS</div>
                <h2 class="section-title">Affordable DPDP Compliance for Every Business.</h2>
                <p class="section-subtext">
                    Simple monthly plans designed for single clinics, multi-specialty centres, and scaling software companies.
                </p>
            </div>

            <div class="pricing-grid">
                <!-- STARTER -->
                <div class="pricing-card">
                    <h3>Starter Plan</h3>
                    <p class="plan-sub">Ideal for individual clinics, diagnostic centers &amp; small practices.</p>
                    <div class="plan-price">&#8377;999 <span>/ month</span></div>
                    <ul class="plan-features">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>1 Clinic / Branch Location</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Up to 25 Data Inventory Entries</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Patient Privacy Notice Generator</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Consent Withdrawal Workflow</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>500 MB Secure Evidence Vault</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>AI DPDP Assistant Access</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-secondary" style="width: 100%;">Select Starter</button>
                </div>

                <!-- GROWTH -->
                <div class="pricing-card featured">
                    <div class="featured-tag">MOST POPULAR</div>
                    <h3>Growth Plan</h3>
                    <p class="plan-sub">For multi-doctor clinics, hospitals &amp; growing SaaS startups.</p>
                    <div class="plan-price">&#8377;1,999 <span>/ month</span></div>
                    <ul class="plan-features">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Up to 5 Clinic Branches / Accounts</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Unlimited Data Inventory Entries</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Eighth Schedule Multilingual Notices</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Vendor &amp; DPA Processor Register</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Data Principal Rights Ticketing Portal</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>5 GB Secure Evidence Vault</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Dual-Stage Breach Intimation Drafts</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-primary" style="width: 100%;">Start Free Assessment</button>
                </div>

                <!-- BUSINESS -->
                <div class="pricing-card">
                    <h3>Business Plan</h3>
                    <p class="plan-sub">For hospital networks, healthcare groups &amp; large SaaS.</p>
                    <div class="plan-price">&#8377;2,999 <span>/ month</span></div>
                    <ul class="plan-features">
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Unlimited Branches &amp; Users</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Custom DPA &amp; Policy Workflows</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Significant Data Fiduciary (SDF) Tools</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>25 GB Evidence Vault &amp; Audit Logs</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Dedicated Implementation Support</li>
                        <li><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>Executive Compliance PDF Reports</li>
                    </ul>
                    <button onclick="openOnboardingModal()" class="btn btn-secondary" style="width: 100%;">Select Business</button>
                </div>
            </div>
            <div style="text-align: center; font-size: 12.5px; color: var(--text-muted); margin-top: 24px;">
                * Proposed SaaS pricing. Software subscription provides compliance automation tools and does not constitute a government-issued certification or formal legal counsel.
            </div>
        </div>
    </section>

    <!-- SECTION 12 — FAQ & FINAL CTA -->
    <section class="faq-section">
        <div class="container">
            <div class="section-header">
                <div class="eyebrow">COMMON QUESTIONS</div>
                <h2 class="section-title">Frequently Asked Questions.</h2>
                <p class="section-subtext">Clear, plain-language answers regarding the DPDP Act, applicability, and TrustAudit capabilities.</p>
            </div>

            <div class="faq-accordion">
                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>What is DPDP compliance?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        The Digital Personal Data Protection Act, 2023 (DPDP) is India's principal privacy law governing how businesses collect, store, and process digital personal data. It mandates notice transparency, valid affirmative consent, security safeguards, breach notification, and individual rights.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Does every clinic or small business need to comply?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        Yes. Under Section 3, any organisation processing personal data in digital form or converting physical forms into digital records (such as patient names, phone numbers, or diagnostic reports) qualifies as a Data Fiduciary and must comply with applicable provisions.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Is having a website privacy policy enough?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        No. Section 5 requires an itemised notice provided before or at the time of seeking consent, specifying exact data categories, specific purposes, rights procedures, and Grievance Officer contacts, prepared for availability in Eighth Schedule languages.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>Does TrustAudit issue a statutory government certificate?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        No. The Central Government and Data Protection Board of India do not issue generic statutory compliance certificates. TrustAudit is a compliance management and evidence collection platform that helps you operationalize and document compliance.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>How does TrustAudit handle patient data privacy?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        TrustAudit operates on a zero raw patient data model. You catalog data flow metadata (e.g. data category, purpose, retention rule, storage system). You never upload patient medical records or identifiable clinical databases to TrustAudit.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>What is the difference between a Data Fiduciary and Data Processor?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        The Data Fiduciary (e.g., your clinic or company) determines the purpose and means of processing personal data. A Data Processor (e.g., your diagnostic lab software or cloud host) processes personal data on your behalf under a contract (DPA).
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>What happens if an individual withdraws consent?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        Under Section 6(4)-(6), the Data Fiduciary and its Data Processors must cease processing the individual's personal data unless retention is mandated by another statutory law, such as medical record retention rules or tax legislation.
                    </div>
                </div>

                <div class="faq-item">
                    <div class="faq-question" onclick="toggleFaq(this)">
                        <span>What are the breach intimation timelines under Section 8(6)?</span>
                        <span class="faq-icon">&darr;</span>
                    </div>
                    <div class="faq-answer">
                        Under Rule 7 of the DPDP Rules, 2025, an initial preliminary intimation must be submitted to the Data Protection Board without delay, followed by a detailed report within 72 hours, with direct notifications sent to affected Data Principals.
                    </div>
                </div>
            </div>

            <!-- FINAL CTA BANNER -->
            <div class="cta-banner">
                <div class="eyebrow eyebrow-dark">START YOUR JOURNEY TODAY</div>
                <h2>Start Understanding Your DPDP Obligations.</h2>
                <p>
                    Set up your organization's personal data inventory, identify compliance gaps, and organize audit-ready evidence in minutes.
                </p>
                <button onclick="openOnboardingModal()" class="btn btn-dark" style="font-size: 16px; padding: 15px 36px;">
                    Start Your Free DPDP Assessment &rarr;
                </button>
            </div>
        </div>
    </section>

    <!-- FOOTER -->
    <footer class="site-footer">
        <div class="container footer-grid">
            <div class="footer-col">
                <div class="logo-wrap" style="color: #ffffff; margin-bottom: 14px;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>TrustAudit</span>
                </div>
                <p style="color: #94a3b8; font-size: 13px; line-height: 1.6; max-width: 320px;">
                    The DPDP Compliance Management Platform for Indian businesses, clinics, diagnostic centres, and startups.
                </p>
            </div>
            <div class="footer-col">
                <h5>Product</h5>
                <ul>
                    <li><a href="#pillars">Core Pillars</a></li>
                    <li><a href="#modules">Product Modules</a></li>
                    <li><a href="#experience">Product Preview</a></li>
                    <li><a href="#pricing">Pricing Plans</a></li>
                    <li><a href="/dashboard">Dashboard Login</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h5>Industries</h5>
                <ul>
                    <li><a href="#industries">Healthcare &amp; Clinics</a></li>
                    <li><a href="#industries">Diagnostic Centres</a></li>
                    <li><a href="#industries">Education &amp; Schools</a></li>
                    <li><a href="#industries">SaaS &amp; Technology</a></li>
                    <li><a href="#industries">E-Commerce</a></li>
                </ul>
            </div>
            <div class="footer-col">
                <h5>Trust &amp; Governance</h5>
                <ul>
                    <li><a href="/trust">Trust Centre</a></li>
                    <li><a href="/.well-known/security.txt">Security Disclosure</a></li>
                    <li><a href="mailto:grievance@trustaudit.io">Grievance Redressal</a></li>
                    <li><a href="mailto:security@trustaudit.io">Security Contact</a></li>
                </ul>
            </div>
        </div>
        <div class="container footer-bottom">
            <div>&copy; 2026 TrustAudit Technologies. All rights reserved. DPDP Compliance Management Platform.</div>
            <div style="color: #64748b;">Not a government certification body. Compliance software and audit documentation platform.</div>
        </div>
    </footer>

    <!-- ONBOARDING MODAL -->
    <div id="onboardingModal" class="modal-overlay">
        <div class="modal-card">
            <button class="modal-close" onclick="closeOnboardingModal()">&times;</button>
            <div class="eyebrow">GET STARTED</div>
            <h3 style="font-size: 22px; font-weight: 800; color: var(--navy-dark); margin-bottom: 8px;">Start Your DPDP Assessment</h3>
            <p style="font-size: 13.5px; color: var(--text-secondary); margin-bottom: 24px;">
                Configure your organisation profile and deploy tailored industry data flows in under 2 minutes.
            </p>

            <form id="onboardingForm" onsubmit="handleOnboardingSubmit(event)">
                <div class="form-group">
                    <label class="form-label">Organisation / Clinic Legal Name *</label>
                    <input type="text" id="ob_name" class="form-control" placeholder="e.g. Arogya Diagnostics &amp; Clinic Ltd" required>
                </div>

                <div class="form-group">
                    <label class="form-label">Industry Sector *</label>
                    <select id="ob_industry" class="form-select" required>
                        <option value="healthcare" selected>Healthcare (Clinics, Diagnostic Centres, Hospitals)</option>
                        <option value="education">Education (Schools, Colleges, EdTech)</option>
                        <option value="saas">SaaS &amp; Technology Startups</option>
                        <option value="ecommerce">E-Commerce &amp; Retail</option>
                        <option value="other">Other Indian SME</option>
                    </select>
                </div>

                <div class="form-group">
                    <label class="form-label">Clinic / Business Locations</label>
                    <input type="text" id="ob_locations" class="form-control" placeholder="e.g. Bengaluru, Karnataka">
                </div>

                <div class="form-group">
                    <label class="form-label">Work Email Address *</label>
                    <input type="email" id="ob_email" class="form-control" placeholder="admin@organisation.com" required>
                </div>

                <div class="form-group">
                    <label class="form-label">Password *</label>
                    <input type="password" id="ob_password" class="form-control" placeholder="Create a secure password" minlength="8" required>
                </div>

                <div style="margin-top: 24px;">
                    <button type="submit" id="ob_btn" class="btn btn-primary" style="width: 100%; border-radius: 8px; padding: 13px;">
                        Create Profile &amp; Launch Assessment &rarr;
                    </button>
                </div>
                <div style="font-size: 11.5px; color: var(--text-muted); text-align: center; margin-top: 12px;">
                    Zero raw patient records are collected. By continuing, you agree to our <a href="/trust" style="text-decoration: underline;">Privacy Policy</a>.
                </div>
            </form>
        </div>
    </div>

    <!-- JAVASCRIPT INTERACTIONS -->
    <script>
        function toggleFaq(btn) {
            const item = btn.closest('.faq-item');
            item.classList.toggle('open');
        }

        function switchIndustry(industry, btn) {
            document.querySelectorAll('.ind-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ind-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const panel = document.getElementById('ind-panel-' + industry);
            if (panel) panel.classList.add('active');
        }

        function switchExpTab(tab, btn) {
            document.querySelectorAll('.exp-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.exp-content-box').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById('exp-tab-' + tab);
            if (target) target.classList.add('active');
        }

        function openOnboardingModal(industry = 'healthcare') {
            const modal = document.getElementById('onboardingModal');
            const select = document.getElementById('ob_industry');
            if (select && industry) select.value = industry;
            modal.classList.add('open');
        }

        function closeOnboardingModal() {
            document.getElementById('onboardingModal').classList.remove('open');
        }

        async function handleOnboardingSubmit(e) {
            e.preventDefault();
            const btn = document.getElementById('ob_btn');
            btn.disabled = true;
            btn.innerText = 'Creating Profile...';

            const name = document.getElementById('ob_name').value.trim();
            const industry = document.getElementById('ob_industry').value;
            const locations = document.getElementById('ob_locations').value.trim();
            const email = document.getElementById('ob_email').value.trim();
            const password = document.getElementById('ob_password').value;

            try {
                // 1. Register Account via /api/auth/register
                const regRes = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: email,
                        password: password,
                        name: name,
                        org_name: name,
                        industry: industry
                    })
                });
                const regData = await regRes.json();
                
                // 2. Save Onboarding Profile & Prepopulate Inventory via /api/dpdp/onboarding
                if (regRes.ok || regData.status === 'success') {
                    await fetch('/api/dpdp/onboarding', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            business_name: name,
                            industry: industry,
                            locations: locations,
                            email: email
                        })
                    });
                    window.location.href = '/dashboard';
                } else if (regData.message && regData.message.includes('already registered')) {
                    // Log in directly
                    const loginRes = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email, password: password })
                    });
                    if (loginRes.ok) {
                        window.location.href = '/dashboard';
                    } else {
                        alert(regData.message || 'Registration error');
                        btn.disabled = false;
                        btn.innerText = 'Create Profile & Launch Assessment →';
                    }
                } else {
                    alert(regData.message || 'Could not complete registration');
                    btn.disabled = false;
                    btn.innerText = 'Create Profile & Launch Assessment →';
                }
            } catch (err) {
                console.error(err);
                // Fallback direct redirect to dashboard
                window.location.href = '/dashboard';
            }
        }
    </script>
</body>
</html>
"""
