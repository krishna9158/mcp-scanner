"""
TrustAudit - 60-Second Interactive DPDP Compliance Assessment Demo.
Phase 16 - No-signup, frictionless interactive preview of TrustAudit's DPDP assessment and readiness scoring.
"""

DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>60-Second Interactive Demo | TrustAudit DPDP Compliance Platform</title>
    <meta name="description" content="Experience TrustAudit's DPDP compliance assessment, gap detection, and statutory readiness scoring in 60 seconds without creating an account.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060913;
            --bg-surface: #0b1120;
            --bg-card: #0f172a;
            --bg-card-hover: #152238;
            --border-subtle: #1e293b;
            --border-active: #38bdf8;
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
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: var(--font-sans);
            background: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 20% 15%, rgba(99, 102, 241, 0.12) 0%, transparent 40%),
                radial-gradient(circle at 80% 60%, rgba(6, 182, 212, 0.10) 0%, transparent 45%);
        }

        /* Top Bar */
        .top-nav {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1.1rem 2.5rem;
            border-bottom: 1px solid var(--border-subtle);
            background: rgba(6, 9, 19, 0.85);
            backdrop-filter: blur(12px);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .nav-brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            text-decoration: none;
            color: var(--text-primary);
            font-weight: 800;
            font-size: 1.25rem;
            letter-spacing: -0.02em;
        }
        .nav-brand-icon {
            width: 34px;
            height: 34px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-indigo));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.1rem;
            box-shadow: 0 0 16px var(--accent-cyan-glow);
        }
        .demo-badge {
            background: rgba(6, 182, 212, 0.15);
            border: 1px solid rgba(6, 182, 212, 0.4);
            color: var(--accent-cyan);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.25rem 0.65rem;
            border-radius: 999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .nav-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .btn-outline {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 0.55rem 1.15rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.2s;
        }
        .btn-outline:hover {
            border-color: var(--text-primary);
            color: var(--text-primary);
        }
        .btn-primary {
            background: linear-gradient(135deg, #0ea5e9, #0284c7);
            color: white;
            padding: 0.55rem 1.25rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 700;
            text-decoration: none;
            transition: all 0.2s;
            box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35);
        }
        .btn-primary:hover {
            box-shadow: 0 6px 20px rgba(2, 132, 199, 0.5);
            transform: translateY(-1px);
        }

        /* Container */
        .container {
            max-width: 1240px;
            margin: 0 auto;
            padding: 2.5rem 1.5rem 5rem;
        }

        /* Hero */
        .demo-hero {
            text-align: center;
            max-width: 780px;
            margin: 0 auto 3rem;
        }
        .demo-pill {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.35rem 0.95rem;
            background: rgba(99, 102, 241, 0.12);
            border: 1px solid rgba(99, 102, 241, 0.35);
            border-radius: 999px;
            color: #a5b4fc;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
        }
        .demo-hero h1 {
            font-size: 2.75rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.15;
            margin-bottom: 1rem;
            background: linear-gradient(180deg, #ffffff 30%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .demo-hero p {
            font-size: 1.1rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        /* Industry Selector */
        .industry-selector {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 1.25rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 2.5rem;
            flex-wrap: wrap;
        }
        .industry-label {
            font-weight: 700;
            font-size: 0.9rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .industry-tabs {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        .ind-tab {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .ind-tab:hover {
            border-color: var(--accent-cyan);
            color: var(--text-primary);
        }
        .ind-tab.active {
            background: rgba(6, 182, 212, 0.15);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }

        /* Demo Grid */
        .demo-grid {
            display: grid;
            grid-template-columns: 380px 1fr;
            gap: 2rem;
            align-items: start;
        }
        @media (max-width: 960px) {
            .demo-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Readiness Gauge Card */
        .score-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
        }
        .score-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        .score-title {
            font-size: 1rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .gauge-wrap {
            position: relative;
            width: 200px;
            height: 200px;
            margin: 0 auto 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .gauge-svg {
            transform: rotate(-90deg);
            width: 200px;
            height: 200px;
        }
        .gauge-bg {
            fill: none;
            stroke: #1e293b;
            stroke-width: 16;
        }
        .gauge-fill {
            fill: none;
            stroke: url(#cyan-grad);
            stroke-width: 16;
            stroke-linecap: round;
            stroke-dasharray: 502;
            stroke-dashoffset: 210;
            transition: stroke-dashoffset 0.8s ease;
        }
        .gauge-center {
            position: absolute;
            text-align: center;
        }
        .gauge-num {
            font-size: 3rem;
            font-weight: 800;
            line-height: 1;
            color: #ffffff;
            font-family: var(--font-mono);
        }
        .gauge-denom {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
        }
        .gauge-band {
            display: inline-block;
            margin-top: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            background: rgba(245, 158, 11, 0.15);
            border: 1px solid rgba(245, 158, 11, 0.4);
            color: var(--accent-amber);
            text-transform: uppercase;
        }

        .category-breakdown {
            margin-top: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        .cat-item {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }
        .cat-header {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
        }
        .cat-name {
            font-weight: 600;
            color: var(--text-secondary);
        }
        .cat-score {
            font-family: var(--font-mono);
            font-weight: 700;
            color: var(--text-primary);
        }
        .cat-bar-bg {
            height: 6px;
            background: #1e293b;
            border-radius: 999px;
            overflow: hidden;
        }
        .cat-bar-fill {
            height: 100%;
            background: var(--accent-cyan);
            border-radius: 999px;
            transition: width 0.6s ease;
        }

        /* Assessment Steps & Gaps Panel */
        .main-panel {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        .steps-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 2rem;
        }
        .steps-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
        }
        .steps-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .steps-subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
        }

        .step-accordion {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .step-row {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 1rem 1.25rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .step-row:hover {
            border-color: rgba(6, 182, 212, 0.4);
            background: var(--bg-card-hover);
        }
        .step-row.open {
            border-color: var(--accent-cyan);
        }
        .step-row-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .step-num-title {
            display: flex;
            align-items: center;
            gap: 0.85rem;
        }
        .step-number {
            width: 26px;
            height: 26px;
            border-radius: 6px;
            background: rgba(6, 182, 212, 0.15);
            color: var(--accent-cyan);
            font-size: 0.8rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-mono);
        }
        .step-name {
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .step-status-badge {
            font-size: 0.75rem;
            padding: 0.2rem 0.65rem;
            border-radius: 999px;
            font-weight: 600;
        }
        .badge-verified {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.35);
        }
        .badge-gap {
            background: rgba(244, 63, 94, 0.15);
            color: var(--accent-rose);
            border: 1px solid rgba(244, 63, 94, 0.35);
        }
        .badge-partial {
            background: rgba(245, 158, 11, 0.15);
            color: var(--accent-amber);
            border: 1px solid rgba(245, 158, 11, 0.35);
        }
        .step-details {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-subtle);
            font-size: 0.875rem;
            color: var(--text-secondary);
            display: none;
        }
        .step-row.open .step-details {
            display: block;
        }
        .step-question-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            margin-top: 0.75rem;
        }
        .step-q {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 0.75rem;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }
        .step-q-text {
            color: #e2e8f0;
        }
        .toggle-btn {
            background: #1e293b;
            border: 1px solid #334155;
            color: #94a3b8;
            padding: 0.25rem 0.65rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .toggle-btn.yes {
            background: rgba(16, 185, 129, 0.2);
            border-color: var(--accent-emerald);
            color: var(--accent-emerald);
        }
        .toggle-btn.no {
            background: rgba(244, 63, 94, 0.2);
            border-color: var(--accent-rose);
            color: var(--accent-rose);
        }

        /* Gaps List */
        .gaps-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 2rem;
        }
        .gaps-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
        }
        .gaps-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        .gap-item {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-left: 4px solid var(--accent-rose);
            border-radius: 8px;
            padding: 1.15rem;
            margin-bottom: 1rem;
        }
        .gap-item.amber {
            border-left-color: var(--accent-amber);
        }
        .gap-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.5rem;
        }
        .gap-title {
            font-weight: 700;
            font-size: 0.95rem;
            color: #ffffff;
        }
        .gap-ref {
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.1);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }
        .gap-desc {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }
        .gap-action {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.825rem;
            color: #a7f3d0;
            background: rgba(16, 185, 129, 0.08);
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
        }

        /* Bottom CTA Banner */
        .cta-banner {
            margin-top: 3.5rem;
            background: linear-gradient(135deg, rgba(14, 165, 233, 0.15), rgba(99, 102, 241, 0.15));
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 18px;
            padding: 2.75rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .cta-banner h2 {
            font-size: 2rem;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 0.75rem;
            letter-spacing: -0.02em;
        }
        .cta-banner p {
            font-size: 1.05rem;
            color: var(--text-secondary);
            max-width: 640px;
            margin: 0 auto 1.75rem;
        }
        .cta-btns {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .btn-large-primary {
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: white;
            font-weight: 700;
            font-size: 1rem;
            padding: 0.85rem 2rem;
            border-radius: 10px;
            text-decoration: none;
            box-shadow: 0 4px 20px rgba(2, 132, 199, 0.4);
            transition: all 0.2s;
        }
        .btn-large-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 24px rgba(2, 132, 199, 0.6);
        }
        .btn-large-secondary {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            font-weight: 600;
            font-size: 1rem;
            padding: 0.85rem 1.75rem;
            border-radius: 10px;
            text-decoration: none;
            transition: all 0.2s;
        }
        .btn-large-secondary:hover {
            border-color: var(--text-primary);
        }

        /* Footer */
        .demo-footer {
            margin-top: 4rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border-subtle);
            padding-top: 2rem;
        }
    </style>
</head>
<body>
    <svg style="position: absolute; width: 0; height: 0;" aria-hidden="true">
        <defs>
            <linearGradient id="cyan-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#06b6d4" />
                <stop offset="100%" stop-color="#3b82f6" />
            </linearGradient>
        </defs>
    </svg>

    <header class="top-nav">
        <a href="/" class="nav-brand">
            <div class="nav-brand-icon">✓</div>
            <span>TrustAudit</span>
            <span class="demo-badge">Interactive Demo</span>
        </a>
        <div class="nav-actions">
            <a href="/" class="btn-outline">Back to Home</a>
            <a href="/dashboard" class="btn-primary">Open Live Dashboard</a>
        </div>
    </header>

    <main class="container">
        <div class="demo-hero">
            <div class="demo-pill">
                <span>⚡ 60-Second Guided Assessment</span>
            </div>
            <h1>Experience DPDP Compliance Readiness in Action</h1>
            <p>Test TrustAudit's statutory gap analysis, evidence mapping, and readiness scoring live. Select an industry to load realistic baseline workflows.</p>
        </div>

        <div class="industry-selector">
            <div class="industry-label">
                <span>🏢 Select Industry Persona:</span>
            </div>
            <div class="industry-tabs">
                <button class="ind-tab active" onclick="selectDemoIndustry('hospitals')">🏥 Hospital / Multispecialty</button>
                <button class="ind-tab" onclick="selectDemoIndustry('clinics')">🩺 Clinic & Diagnostics</button>
                <button class="ind-tab" onclick="selectDemoIndustry('saas')">💻 SaaS / Cloud Software</button>
                <button class="ind-tab" onclick="selectDemoIndustry('ecommerce')">🛒 E-Commerce & Retail</button>
                <button class="ind-tab" onclick="selectDemoIndustry('professional_services')">⚖️ Professional Services</button>
            </div>
        </div>

        <div class="demo-grid">
            <!-- Left: Live Score Gauge -->
            <div class="score-card">
                <div class="score-header">
                    <span class="score-title">DPDP Readiness Score</span>
                    <span class="demo-badge" id="demo-entity-tag">Hospital Baseline</span>
                </div>

                <div class="gauge-wrap">
                    <svg class="gauge-svg" viewBox="0 0 200 200">
                        <circle class="gauge-bg" cx="100" cy="100" r="80" />
                        <circle class="gauge-fill" id="demo-gauge-fill" cx="100" cy="100" r="80" />
                    </svg>
                    <div class="gauge-center">
                        <div class="gauge-num" id="demo-score-num">58</div>
                        <div class="gauge-denom">/ 100 PTS</div>
                        <div class="gauge-band" id="demo-score-band">Substantial Gaps</div>
                    </div>
                </div>

                <div style="font-size: 0.78rem; font-weight: 700; color: #b45309; background: #fef3c7; border: 1px solid #fde68a; border-radius: 6px; padding: 6px 10px; margin-bottom: 1rem; text-align: center;">
                    DEMO DATA &mdash; Example information for demonstration only.
                </div>
                <div style="font-size: 0.8rem; color: var(--text-muted); text-align: center; margin-bottom: 1.5rem;">
                    Evaluated against DPDP Act, 2023, DPDP Rules, 2025, and Phased Commencement Timelines.
                </div>

                <div class="category-breakdown">
                    <div class="cat-item">
                        <div class="cat-header">
                            <span class="cat-name">Notice & Consent (Sec 5 & 6)</span>
                            <span class="cat-score" id="score-notice">50%</span>
                        </div>
                        <div class="cat-bar-bg">
                            <div class="cat-bar-fill" id="bar-notice" style="width: 50%;"></div>
                        </div>
                    </div>
                    <div class="cat-item">
                        <div class="cat-header">
                            <span class="cat-name">Data List & Scope (Sec 4 & 5)</span>
                            <span class="cat-score" id="score-ropa">75%</span>
                        </div>
                        <div class="cat-bar-bg">
                            <div class="cat-bar-fill" id="bar-ropa" style="width: 75%;"></div>
                        </div>
                    </div>
                    <div class="cat-item">
                        <div class="cat-header">
                            <span class="cat-name">Principal Rights (Sec 11-14)</span>
                            <span class="cat-score" id="score-rights">40%</span>
                        </div>
                        <div class="cat-bar-bg">
                            <div class="cat-bar-fill" id="bar-rights" style="width: 40%;"></div>
                        </div>
                    </div>
                    <div class="cat-item">
                        <div class="cat-header">
                            <span class="cat-name">Security Safeguards (Sec 8(5))</span>
                            <span class="cat-score" id="score-sec">80%</span>
                        </div>
                        <div class="cat-bar-bg">
                            <div class="cat-bar-fill" id="bar-sec" style="width: 80%;"></div>
                        </div>
                    </div>
                    <div class="cat-item">
                        <div class="cat-header">
                            <span class="cat-name">Breach Response (Sec 8(6))</span>
                            <span class="cat-score" id="score-breach">45%</span>
                        </div>
                        <div class="cat-bar-bg">
                            <div class="cat-bar-fill" id="bar-breach" style="width: 45%;"></div>
                        </div>
                    </div>
                </div>

                <div style="margin-top: 2rem;">
                    <a href="/dashboard" class="btn-primary" style="display: block; text-align: center; padding: 0.75rem;">Launch Full Assessment →</a>
                </div>
            </div>

            <!-- Right: Assessment Steps & Gaps -->
            <div class="main-panel">
                <div class="steps-card">
                    <div class="steps-header">
                        <div class="steps-title">8-Step Guided Assessment Matrix</div>
                        <span style="font-size: 0.8rem; color: var(--accent-cyan); font-weight: 600;">Interactive: Click rows to inspect</span>
                    </div>
                    <p class="steps-subtitle">Each step evaluates your statutory readiness and maps required compliance evidence.</p>

                    <div class="step-accordion" id="demo-step-list">
                        <!-- Populated by JS -->
                    </div>
                </div>

                <div class="gaps-card">
                    <div class="gaps-header">
                        <div class="gaps-title">Priority Statutory Gaps & Action Items</div>
                        <span class="badge-pill badge-gap" id="demo-gaps-count">3 Gaps Identified</span>
                    </div>

                    <div id="demo-gaps-list">
                        <!-- Populated by JS -->
                    </div>
                </div>
            </div>
        </div>

        <!-- CTA Banner -->
        <div class="cta-banner">
            <h2>Ready to Assess Your Own Organization?</h2>
            <p>Deploy TrustAudit to evaluate your websites, patient data workflows, and vendor agreements with automated gap detection and 1-click policy generation.</p>
            <div class="cta-btns">
                <a href="/dashboard" class="btn-large-primary">Start Free Assessment</a>
                <a href="/trust" class="btn-large-secondary">View Security & Trust Center</a>
            </div>
        </div>

        <footer class="demo-footer">
            <p>© 2026 TrustAudit Technologies. Designed for the Digital Personal Data Protection Act, 2023. Not legal advice or statutory certification.</p>
        </footer>
    </main>

    <script>
        const INDUSTRY_PRESETS = {
            hospitals: {
                label: "Multispecialty Hospital",
                score: 58,
                band: "Substantial Gaps",
                scores: { notice: 50, ropa: 75, rights: 40, sec: 80, breach: 45 },
                steps: [
                    { num: 1, title: "Entity Classification & SDO Status", status: "verified", badge: "Verified", desc: "Significant Data Fiduciary (SDO) threshold evaluated under Section 10." },
                    { num: 2, title: "Notice & Itemised Consent (Sec 5 & 6)", status: "gap", badge: "Gap Identified", desc: "Bilingual notice in English and Hindi missing itemised doctor consultation purpose." },
                    { num: 3, title: "Processing Grounds & Data List (Sec 4 & 5)", status: "verified", badge: "Verified", desc: "4 data streams mapped: OPD registration, IPD EHR records, diagnostic labs, billing." },
                    { num: 4, title: "Data Principal Rights SOP (Sec 11-14)", status: "partial", badge: "In Progress", desc: "Patient access and erasure workflow partially configured without Grievance escalation." },
                    { num: 5, title: "Reasonable Security Safeguards (Sec 8(5))", status: "verified", badge: "Verified", desc: "EHR database protected with encryption at rest, HTTPS in transit, and role-based access." },
                    { num: 6, title: "Dual-Stage Breach Protocol (Sec 8(6))", status: "gap", badge: "Gap Identified", desc: "No documented 72-hour CERT-In / DPBI intimation dual-stage runbook." },
                    { num: 7, title: "Retention & Automated Erasure (Sec 8(7))", status: "partial", badge: "In Progress", desc: "Retention period set to 3 years per Clinical Establishments Act; auto-erasure unverified." },
                    { num: 8, title: "Vendor & Processor Agreements (Sec 8(2))", status: "verified", badge: "Verified", desc: "Pathology lab and cloud PACS vendor contracts executed with DPA terms." }
                ],
                gaps: [
                    { ref: "DPDP Sec 5 / Rule 3", title: "Itemised Multilingual Privacy Notice Missing", sev: "rose", desc: "Patients are not provided an itemised choice before collecting health parameters and Aadhaar metadata.", action: "Generate bilingual English/Hindi notice via TrustAudit Document Generator." },
                    { ref: "DPDP Sec 8(6)", title: "Dual-Stage Breach Intimation Procedure Missing", sev: "rose", desc: "Absence of a documented protocol to notify DPBI and affected patients within statutory hours.", action: "Download DPBI breach notification SOP template and assign incident commander." },
                    { ref: "DPDP Sec 12 & 13", title: "Patient Erasure and Grievance Escalation SOP", sev: "amber", desc: "Patients lack a clear documented workflow to request deletion of non-clinical billing data.", action: "Configure Customer Privacy Requests portal with clear verification and response timeline." }
                ]
            },
            clinics: {
                label: "Outpatient Clinic & Diagnostics",
                score: 64,
                band: "Moderate Readiness",
                scores: { notice: 60, ropa: 70, rights: 55, sec: 75, breach: 60 },
                steps: [
                    { num: 1, title: "Entity Classification", status: "verified", badge: "Standard Fiduciary", desc: "Classified as non-SDO Data Fiduciary handling health data." },
                    { num: 2, title: "Consent Architecture", status: "verified", badge: "Verified", desc: "Physical consent and SMS token consent captured for lab samples." },
                    { num: 3, title: "Data Inventory", status: "verified", badge: "Verified", desc: "Patient demographic, blood work results, and doctor prescriptions documented." },
                    { num: 4, title: "Principal Rights", status: "partial", badge: "In Progress", desc: "Manual phone-based correction workflow; needs online grievance channel." },
                    { num: 5, title: "Technical Security", status: "verified", badge: "Verified", desc: "Role-based access control enabled on clinic management software." },
                    { num: 6, title: "Breach Protocol", status: "gap", badge: "Gap Identified", desc: "No documented response plan if diagnostic report portal is breached." },
                    { num: 7, title: "Retention Policy", status: "verified", badge: "Verified", desc: "Lab reports retained for 5 years per NABL guidelines." },
                    { num: 8, title: "Processor Management", status: "partial", badge: "In Progress", desc: "SMS gateway provider agreement missing statutory processor clauses." }
                ],
                gaps: [
                    { ref: "DPDP Sec 8(2)", title: "Processor Clauses Missing in SMS Gateway DPA", sev: "amber", desc: "Vendor sending patient OTPs and test results lacks explicit DPDP data processing addendum.", action: "Execute TrustAudit Standard Data Processor Addendum with SMS vendor." },
                    { ref: "DPDP Sec 8(6)", title: "Diagnostic Portal Incident Response Runbook", sev: "rose", desc: "Absence of emergency steps if web-based report download credentials leak.", action: "Generate breach containment workflow with DPBI reporting templates." }
                ]
            },
            saas: {
                label: "B2B SaaS Platform",
                score: 82,
                band: "High Readiness",
                scores: { notice: 90, ropa: 85, rights: 80, sec: 95, breach: 70 },
                steps: [
                    { num: 1, title: "Entity Classification", status: "verified", badge: "Data Processor / Fiduciary", desc: "B2B SaaS handling enterprise user telemetry and customer personal data." },
                    { num: 2, title: "Privacy Notice & Cookies", status: "verified", badge: "Verified", desc: "Website cookie consent banner active and itemised privacy notice published." },
                    { num: 3, title: "RoPA & Data Flow Mapping", status: "verified", badge: "Verified", desc: "Complete data flows mapped across AWS Mumbai, Stripe, and Sendgrid." },
                    { num: 4, title: "Data Subject Rights (DSR)", status: "verified", badge: "Verified", desc: "Automated user data export and account deletion self-service in dashboard." },
                    { num: 5, title: "Cloud Security & KMS", status: "verified", badge: "Verified", desc: "AWS KMS envelope encryption, SOC 2 Type II audit, mTLS internally." },
                    { num: 6, title: "Breach Notification", status: "partial", badge: "In Progress", desc: "Security playbook exists; dual CERT-In and DPBI regulatory notice template needed." },
                    { num: 7, title: "Retention Automation", status: "verified", badge: "Verified", desc: "Automated DynamoDB TTL and S3 lifecycle rules configured for 90-day purge." },
                    { num: 8, title: "Sub-processor Register", status: "verified", badge: "Verified", desc: "Public sub-processor directory with 30-day change notification mechanism." }
                ],
                gaps: [
                    { ref: "DPDP Sec 8(6)", title: "DPBI-Specific Regulatory Escalation Runbook", sev: "amber", desc: "Existing SOC 2 incident plan references US/EU regulators but lacks DPDP Schedule 2 reporting timelines.", action: "Adopt TrustAudit India Dual-Stage Breach Notification Procedure." }
                ]
            },
            ecommerce: {
                label: "E-Commerce & Retail",
                score: 52,
                band: "High Risk",
                scores: { notice: 45, ropa: 60, rights: 35, sec: 70, breach: 50 },
                steps: [
                    { num: 1, title: "Entity Classification", status: "verified", badge: "Data Fiduciary", desc: "Consumer marketplace processing retail transactions and address data." },
                    { num: 2, title: "Notice & Marketing Consent", status: "gap", badge: "Gap Identified", desc: "Pre-ticked marketing checkboxes detected; violates Section 6 unconditional consent." },
                    { num: 3, title: "RoPA Mapping", status: "partial", badge: "In Progress", desc: "Checkout inventory mapped; delivery logistics partner data sharing undocumented." },
                    { num: 4, title: "Principal Rights", status: "gap", badge: "Gap Identified", desc: "Customers cannot withdraw consent or delete delivery address history." },
                    { num: 5, title: "Payment Security", status: "verified", badge: "Verified", desc: "PCI-DSS Level 1 compliant payment gateway integration with tokenization." },
                    { num: 6, title: "Incident Response", status: "partial", badge: "In Progress", desc: "Internal IT escalation exists; external customer notification protocol missing." },
                    { num: 7, title: "Retention Schedules", status: "gap", badge: "Gap Identified", desc: "Abandoned cart cookies and browse history retained indefinitely without schedule." },
                    { num: 8, title: "Logistics Partner DPAs", status: "partial", badge: "In Progress", desc: "Courier partner contracts lack explicit erasure clauses upon order delivery." }
                ],
                gaps: [
                    { ref: "DPDP Sec 6", title: "Pre-ticked Marketing Consent Boxes Must Be Removed", sev: "rose", desc: "Under Section 6, consent must be free, specific, informed, and unconditional.", action: "Uncheck promotional opt-ins by default and record itemised affirmative consent." },
                    { ref: "DPDP Sec 12", title: "Customer Account Deletion Mechanism Missing", sev: "rose", desc: "Customers lack an in-app option to erase saved addresses and past cart history.", action: "Implement customer deletion workflow with automated merchant ledger retention." }
                ]
            },
            professional_services: {
                label: "Law Firm / CA Practice",
                score: 68,
                band: "Moderate Readiness",
                scores: { notice: 65, ropa: 75, rights: 60, sec: 75, breach: 65 },
                steps: [
                    { num: 1, title: "Entity Classification", status: "verified", badge: "Data Fiduciary", desc: "Professional advisory handling confidential corporate and individual filings." },
                    { num: 2, title: "Client Privacy Notice", status: "verified", badge: "Verified", desc: "Client engagement letters incorporate DPDP purpose limitation clauses." },
                    { num: 3, title: "RoPA & Tax Records", status: "verified", badge: "Verified", desc: "Client KYC, ITR drafts, and GST filings categorized with statutory grounds." },
                    { num: 4, title: "Client Rights", status: "partial", badge: "In Progress", desc: "Ad-hoc email request fulfillment; formalized tracking ledger recommended." },
                    { num: 5, title: "Access Controls & Cloud Drive", status: "verified", badge: "Verified", desc: "Google Workspace / M365 enforced with 2FA and confidential labeling." },
                    { num: 6, title: "Breach Protocol", status: "partial", badge: "In Progress", desc: "Security awareness in place; formal notification runbook missing." },
                    { num: 7, title: "Statutory Retention", status: "verified", badge: "Verified", desc: "Audit and tax documentation retained for 8 years under Income Tax Act Section 44AB." },
                    { num: 8, title: "Cloud Accounting Vendor", status: "verified", badge: "Verified", desc: "Cloud accounting SaaS contract reviewed for Indian data sovereignty alignment." }
                ],
                gaps: [
                    { ref: "DPDP Sec 8(6)", title: "Formalized Client Confidentiality Breach Plan", sev: "amber", desc: "Need a documented protocol in case client financial or PAN records are accidentally leaked.", action: "Adopt TrustAudit Professional Services Data Incident SOP." }
                ]
            }
        };

        function selectDemoIndustry(key) {
            document.querySelectorAll('.ind-tab').forEach(t => t.classList.remove('active'));
            const clicked = event.target;
            clicked.classList.add('active');

            const preset = INDUSTRY_PRESETS[key] || INDUSTRY_PRESETS.hospitals;

            // Update Header & Score
            document.getElementById('demo-entity-tag').innerText = preset.label;
            document.getElementById('demo-score-num').innerText = preset.score;
            document.getElementById('demo-score-band').innerText = preset.band;

            // Adjust Gauge Arc (Circumference ~ 502)
            const circumference = 502;
            const offset = circumference - (circumference * preset.score / 100);
            document.getElementById('demo-gauge-fill').style.strokeDashoffset = offset;

            // Update Category Bars
            document.getElementById('score-notice').innerText = preset.scores.notice + '%';
            document.getElementById('bar-notice').style.width = preset.scores.notice + '%';

            document.getElementById('score-ropa').innerText = preset.scores.ropa + '%';
            document.getElementById('bar-ropa').style.width = preset.scores.ropa + '%';

            document.getElementById('score-rights').innerText = preset.scores.rights + '%';
            document.getElementById('bar-rights').style.width = preset.scores.rights + '%';

            document.getElementById('score-sec').innerText = preset.scores.sec + '%';
            document.getElementById('bar-sec').style.width = preset.scores.sec + '%';

            document.getElementById('score-breach').innerText = preset.scores.breach + '%';
            document.getElementById('bar-breach').style.width = preset.scores.breach + '%';

            // Render Steps
            const stepsContainer = document.getElementById('demo-step-list');
            stepsContainer.innerHTML = preset.steps.map((s, idx) => `
                <div class="step-row ${idx === 1 ? 'open' : ''}" onclick="this.classList.toggle('open')">
                    <div class="step-row-top">
                        <div class="step-num-title">
                            <div class="step-number">${s.num}</div>
                            <div class="step-name">${s.title}</div>
                        </div>
                        <span class="step-status-badge ${s.status === 'verified' ? 'badge-verified' : (s.status === 'gap' ? 'badge-gap' : 'badge-partial')}">
                            ${s.badge}
                        </span>
                    </div>
                    <div class="step-details">
                        <p>${s.desc}</p>
                        <div class="step-question-list">
                            <div class="step-q">
                                <span class="step-q-text">Is evidence uploaded and verified?</span>
                                <button class="toggle-btn ${s.status === 'verified' ? 'yes' : 'no'}" onclick="event.stopPropagation();">${s.status === 'verified' ? 'Verified ✓' : 'Pending ✗'}</button>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');

            // Render Gaps
            document.getElementById('demo-gaps-count').innerText = preset.gaps.length + ' Gaps Identified';
            const gapsContainer = document.getElementById('demo-gaps-list');
            gapsContainer.innerHTML = preset.gaps.map(g => `
                <div class="gap-item ${g.sev}">
                    <div class="gap-top">
                        <span class="gap-title">${g.title}</span>
                        <span class="gap-ref">${g.ref}</span>
                    </div>
                    <div class="gap-desc">${g.desc}</div>
                    <div class="gap-action">
                        <span>⚡ Recommended Action:</span>
                        <span>${g.action}</span>
                    </div>
                </div>
            `).join('');
        }

        // Initialize with hospitals on page load
        window.addEventListener('DOMContentLoaded', () => {
            selectDemoIndustry('hospitals');
        });
    </script>
</body>
</html>
"""
