"""
TrustAudit Interactive Enterprise Security & Compliance Command Centre Template.

Design Standard:
- Enterprise command-centre visual identity (comparable to Linear, Wiz, Vanta, Aikido)
- Dark technical cybersecurity theme (#070b12, #0f172a, #162032, #1e293b, #0284c7, #38bdf8, #10b981, #6366f1)
- 100% Lucide 18px stroke icons in subtle containers (zero system emojis)
- Mouse-following Bento spotlight with CSS variables (touch-safe, prefers-reduced-motion)
- Segmented Pre-Launch vs Post-Launch toggle in Framework Explorer
- 4 Deep Frameworks (DPDP Act 2023 & Rules 2025, SOC 2 Criteria, ISO/IEC 27001:2022, GDPR)
- 4 High-Fidelity Illustrative Remediation Modals (DPDP Sec 6(4)-(6), SOC 2 CC8.1/CC6.1, ISO A.8.28/A.8.8, GDPR Art 32-34)
- Animated SVG Architecture Pipeline (Ephemeral Scan Workspace, amber cleanup transition, node inspector)
- Client-Side Secret Redaction Sandbox (100% in-browser, textContent XSS protection, live entropy scoring)
- Enterprise Security Questionnaire Simulator (3 questions, 150ms typewriter animation, honest labels)
- Live CISA KEV Telemetry Card (count-up animation, rotating refresh, live API polling)
- Quick Perimeter & Privacy Check Widget (SSRF-protected, non-invasive transport/privacy checks, CTA)
- Governance & India Hosting Section (AWS ap-south-1 Planned disclosure, Privacy & Grievance contact, Grievance modal)
- Enterprise Trust Pack Builder (custom-styled checkboxes, radio buttons, ZIP & Markdown downloads)
- RFC 9116 security.txt link and comprehensive legal disclaimers
"""

TRUST_CENTRE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit Security, Compliance & Trust Center</title>
    <meta name="description" content="Explore how TrustAudit protects source code, detects vulnerabilities, maps DPDP Act 2023, SOC 2, and ISO 27001 compliance, and enforces multi-tenant isolation.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #070b12;
            --bg-surface: #0f172a;
            --bg-elevated: #162032;
            --bg-subtle: #1e293b;
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(56, 189, 248, 0.35);
            --primary: #0284c7;
            --primary-light: #38bdf8;
            --primary-glow: rgba(2, 132, 199, 0.15);
            --accent: #6366f1;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --font-sans: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: var(--font-sans);
            font-size: 15px;
            line-height: 1.6;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }

        /* SVG Icon Helpers */
        .icon-svg {
            display: inline-block;
            width: 18px;
            height: 18px;
            stroke-width: 2;
            stroke: currentColor;
            fill: none;
            stroke-linecap: round;
            stroke-linejoin: round;
            vertical-align: middle;
        }
        .icon-box {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 36px;
            height: 36px;
            border-radius: 8px;
            background: rgba(56, 189, 248, 0.08);
            border: 1px solid rgba(56, 189, 248, 0.2);
            color: var(--primary-light);
            margin-bottom: 12px;
        }
        .icon-box.green {
            background: rgba(16, 185, 129, 0.08);
            border-color: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        .icon-box.purple {
            background: rgba(99, 102, 241, 0.08);
            border-color: rgba(99, 102, 241, 0.2);
            color: var(--accent);
        }
        .icon-box.amber {
            background: rgba(245, 158, 11, 0.08);
            border-color: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }

        /* Top Progress Bar */
        #scroll-progress {
            position: fixed;
            top: 0;
            left: 0;
            height: 3px;
            background: linear-gradient(90deg, #38bdf8, #6366f1, #10b981);
            z-index: 1000;
            width: 0%;
            transition: width 0.1s ease-out;
        }

        /* Glass Navbar */
        .navbar {
            position: sticky;
            top: 0;
            z-index: 999;
            background: rgba(7, 11, 18, 0.82);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border-bottom: 1px solid var(--border);
            padding: 12px 0;
        }
        .nav-inner {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            color: #fff;
            font-weight: 800;
            font-size: 18px;
            letter-spacing: -0.02em;
        }
        .brand-logo-shield {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: linear-gradient(135deg, #0284c7, #6366f1);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            box-shadow: 0 0 14px rgba(2, 132, 199, 0.4);
        }
        .nav-menu {
            display: flex;
            align-items: center;
            gap: 20px;
            list-style: none;
        }
        .nav-link {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 13.5px;
            font-weight: 500;
            transition: color 0.2s;
            position: relative;
            padding: 4px 0;
        }
        .nav-link:hover, .nav-link.active {
            color: #fff;
        }
        .nav-link.active::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 100%;
            height: 2px;
            background: var(--primary-light);
            border-radius: 2px;
        }
        .nav-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .btn-pack-nav {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: var(--primary-light);
            padding: 7px 14px;
            border-radius: 7px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-pack-nav:hover {
            background: rgba(56, 189, 248, 0.22);
            border-color: var(--primary-light);
            transform: translateY(-1px);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
        }

        /* Hero Section */
        .hero {
            padding: 70px 0 35px;
            text-align: center;
        }
        .eyebrow-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--primary-glow);
            color: var(--primary-light);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 6px 16px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 24px;
        }
        .eyebrow-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
        }
        .hero h1 {
            font-size: clamp(34px, 5.5vw, 56px);
            font-weight: 800;
            line-height: 1.15;
            letter-spacing: -0.03em;
            margin-bottom: 20px;
            color: #fff;
        }
        .hero h1 span.gradient-text {
            background: linear-gradient(135deg, #38bdf8 20%, #818cf8 60%, #c084fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .hero p.subtitle {
            max-width: 780px;
            margin: 0 auto 34px;
            color: var(--text-muted);
            font-size: 17px;
            line-height: 1.6;
        }
        .hero-ctas {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 45px;
        }
        .btn-primary-lg {
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14.5px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
            box-shadow: 0 4px 18px rgba(2, 132, 199, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .btn-primary-lg:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 24px rgba(2, 132, 199, 0.45);
        }
        .btn-secondary-lg {
            background: var(--bg-elevated);
            color: #fff;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 14.5px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid var(--border);
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-secondary-lg:hover {
            border-color: rgba(56, 189, 248, 0.4);
            transform: translateY(-2px);
        }

        /* Status Strip */
        .status-strip {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 24px;
            margin-bottom: 60px;
        }
        .status-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
            text-align: left;
        }
        .status-item-label {
            font-size: 11.5px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
        }
        .status-item-val {
            font-family: var(--font-mono);
            font-size: 13px;
            color: #fff;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .status-indicator-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 6px var(--success);
        }

        /* Section Headers */
        .section-header {
            text-align: center;
            max-width: 740px;
            margin: 0 auto 40px;
        }
        .section-tag {
            display: inline-block;
            font-size: 11.5px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--primary-light);
            margin-bottom: 10px;
        }
        .section-header h2 {
            font-size: 30px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #fff;
            margin-bottom: 12px;
        }
        .section-header p {
            color: var(--text-muted);
            font-size: 15px;
        }

        /* Bento Grid */
        .bento-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 18px;
            margin-bottom: 80px;
            position: relative;
        }
        .bento-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            position: relative;
            overflow: hidden;
            transition: border-color 0.25s, transform 0.2s;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .bento-card:hover {
            border-color: var(--border-hover);
            transform: translateY(-3px);
        }
        .bento-card.col-span-2 { grid-column: span 2; }
        .bento-card h3 {
            font-size: 17px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
        }
        .bento-card p {
            color: var(--text-muted);
            font-size: 13.5px;
            line-height: 1.55;
            margin-bottom: 16px;
        }
        .card-footer-meta {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11.5px;
            color: var(--text-dim);
            padding-top: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            margin-top: auto;
        }

        /* Status Pills */
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            padding: 3px 9px;
            border-radius: 9999px;
            width: fit-content;
        }
        .status-verified {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.25);
        }
        .status-provider {
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }
        .status-operational {
            background: rgba(99, 102, 241, 0.12);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.25);
        }
        .status-roadmap {
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.25);
        }

        /* Framework Segmented Toggle */
        .framework-segment-wrapper {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
        }
        .segment-container {
            display: inline-flex;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            padding: 4px;
            border-radius: 10px;
            gap: 4px;
        }
        .segment-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 8px 20px;
            font-size: 13.5px;
            font-weight: 600;
            border-radius: 7px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .segment-btn.active {
            background: var(--bg-elevated);
            color: #fff;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(56, 189, 248, 0.2);
        }

        /* Framework Controls */
        .explorer-controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }
        .filter-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .filter-btn {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: 7px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover {
            color: #fff;
            border-color: rgba(56, 189, 248, 0.3);
        }
        .filter-btn.active {
            background: var(--primary-glow);
            color: var(--primary-light);
            border-color: rgba(56, 189, 248, 0.4);
            font-weight: 600;
        }
        .search-box {
            position: relative;
            min-width: 260px;
        }
        .search-input {
            width: 100%;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 7px;
            padding: 8px 14px 8px 36px;
            color: #fff;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }
        .search-input:focus {
            border-color: var(--primary-light);
        }
        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-dim);
            pointer-events: none;
        }

        /* Accordion Cards */
        .controls-list {
            display: flex;
            flex-direction: column;
            gap: 14px;
            margin-bottom: 80px;
        }
        .ctrl-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: border-color 0.2s;
        }
        .ctrl-card:hover {
            border-color: rgba(56, 189, 248, 0.25);
        }
        .ctrl-header {
            padding: 18px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            gap: 16px;
            user-select: none;
        }
        .ctrl-header-left {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .ctrl-id-badge {
            font-family: var(--font-mono);
            font-size: 11.5px;
            font-weight: 700;
            background: var(--bg-elevated);
            color: var(--primary-light);
            border: 1px solid rgba(56, 189, 248, 0.2);
            padding: 3px 8px;
            border-radius: 6px;
        }
        .ctrl-title {
            font-size: 15px;
            font-weight: 600;
            color: #fff;
        }
        .ctrl-chevron {
            color: var(--text-dim);
            transition: transform 0.25s;
        }
        .ctrl-card.open .ctrl-chevron {
            transform: rotate(180deg);
        }
        .ctrl-body {
            display: none;
            padding: 0 24px 24px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(15, 23, 42, 0.4);
        }
        .ctrl-card.open .ctrl-body {
            display: block;
        }
        .ctrl-grid-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .detail-block h4 {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            margin-bottom: 6px;
        }
        .detail-block p {
            font-size: 13.5px;
            color: var(--text-muted);
            line-height: 1.5;
        }
        .ctrl-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .btn-action-sm {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            color: #fff;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }
        .btn-action-sm:hover {
            border-color: var(--primary-light);
            color: var(--primary-light);
        }

        /* SVG Architecture Pipeline */
        .pipeline-wrapper {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 30px 24px;
            margin-bottom: 80px;
            position: relative;
        }
        .pipeline-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 12px;
        }
        .pipeline-nodes-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            overflow-x: auto;
            padding: 20px 0;
            position: relative;
        }
        .pipeline-node {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 18px;
            min-width: 130px;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            flex-shrink: 0;
        }
        .pipeline-node:hover, .pipeline-node.active {
            border-color: var(--primary-light);
            box-shadow: 0 0 16px rgba(56, 189, 248, 0.2);
            transform: translateY(-2px);
        }
        .pipeline-node.node-cleanup {
            border-color: rgba(245, 158, 11, 0.3);
            background: rgba(245, 158, 11, 0.05);
        }
        .pipeline-node.node-cleanup:hover, .pipeline-node.node-cleanup.active {
            border-color: var(--warning);
            box-shadow: 0 0 16px rgba(245, 158, 11, 0.25);
        }
        .pipeline-node-name {
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #fff;
            margin-top: 6px;
        }
        .pipeline-node-sub {
            font-size: 11px;
            color: var(--text-dim);
            margin-top: 2px;
        }
        .pipeline-arrow {
            color: var(--text-dim);
            flex-shrink: 0;
        }
        .node-inspector-panel {
            margin-top: 24px;
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }

        /* Demonstrations Box */
        .demos-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 24px;
            margin-bottom: 80px;
        }
        @media (max-width: 768px) {
            .demos-grid { grid-template-columns: 1fr; }
        }
        .demo-box {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 26px;
            display: flex;
            flex-direction: column;
        }
        .demo-box h3 {
            font-size: 18px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 6px;
        }
        .demo-box p.desc {
            color: var(--text-muted);
            font-size: 13.5px;
            margin-bottom: 20px;
        }
        .sandbox-input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 16px;
        }
        .sandbox-input {
            flex: 1;
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            color: #fff;
            font-family: var(--font-mono);
            font-size: 13px;
            outline: none;
        }
        .sandbox-input:focus {
            border-color: var(--primary-light);
        }
        .btn-test-action {
            background: var(--primary);
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 10px 18px;
            font-weight: 600;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }
        .btn-test-action:hover {
            background: #0284c7;
            transform: translateY(-1px);
        }
        .sandbox-result {
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: var(--font-mono);
            font-size: 12.5px;
            margin-top: 10px;
            min-height: 80px;
        }

        /* Questionnaire Simulator Rows */
        .q-simulator-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 16px;
        }
        .q-row {
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
            transition: all 0.2s;
        }
        .q-row-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 600;
            font-size: 13.5px;
            color: #fff;
        }
        .q-row-body {
            margin-top: 8px;
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.5;
            display: none;
        }
        .q-row.active .q-row-body {
            display: block;
        }
        .q-badge {
            font-family: var(--font-mono);
            font-size: 11px;
            padding: 2px 7px;
            border-radius: 4px;
            background: rgba(56, 189, 248, 0.1);
            color: var(--primary-light);
            border: 1px solid rgba(56, 189, 248, 0.2);
        }

        /* Quick Perimeter Check Widget */
        .perimeter-box {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(22, 32, 50, 0.9));
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 14px;
            padding: 30px;
            margin-bottom: 80px;
            position: relative;
        }
        .perimeter-form {
            display: flex;
            gap: 12px;
            max-width: 650px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .perimeter-input {
            flex: 1;
            min-width: 280px;
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            color: #fff;
            font-size: 14px;
            outline: none;
        }
        .perimeter-input:focus {
            border-color: var(--primary-light);
        }
        .perimeter-results-card {
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            display: none;
        }
        .perimeter-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-top: 14px;
        }
        .perimeter-item {
            background: var(--bg-elevated);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px 16px;
        }
        .perimeter-item-label {
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            font-weight: 700;
        }
        .perimeter-item-val {
            font-family: var(--font-mono);
            font-size: 13.5px;
            font-weight: 700;
            margin-top: 4px;
        }

        /* Governance & India Region */
        .governance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 80px;
        }
        .gov-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }
        .gov-card h3 {
            font-size: 17px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .gov-card p {
            color: var(--text-muted);
            font-size: 13.5px;
            line-height: 1.55;
            margin-bottom: 16px;
        }

        /* Modals */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            z-index: 2000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .modal-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            max-width: 680px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            padding: 28px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
            position: relative;
        }
        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 14px;
        }
        .modal-header h3 {
            font-size: 18px;
            font-weight: 700;
            color: #fff;
        }
        .modal-close-btn {
            background: transparent;
            border: none;
            color: var(--text-dim);
            cursor: pointer;
            padding: 4px;
            border-radius: 6px;
            transition: color 0.2s;
        }
        .modal-close-btn:hover {
            color: #fff;
        }
        .code-box-pre {
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: var(--font-mono);
            font-size: 12.5px;
            line-height: 1.5;
            color: #e2e8f0;
            overflow-x: auto;
            margin: 14px 0;
        }

        /* Custom Checkbox/Radio Styling */
        .form-check-group {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin: 16px 0;
        }
        .custom-checkbox-label {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 14px;
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .custom-checkbox-label:hover {
            border-color: rgba(56, 189, 248, 0.3);
        }
        .custom-checkbox-label input[type="checkbox"],
        .custom-checkbox-label input[type="radio"] {
            margin-top: 3px;
            accent-color: var(--primary-light);
            cursor: pointer;
        }
        .check-text-title {
            font-size: 13.5px;
            font-weight: 600;
            color: #fff;
        }
        .check-text-desc {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        /* Footer */
        .footer {
            border-top: 1px solid var(--border);
            padding: 50px 0 30px;
            background: #04070d;
            font-size: 13px;
            color: var(--text-dim);
        }
        .footer-disclaimer-box {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 24px;
            line-height: 1.6;
            color: var(--text-muted);
            font-size: 12.5px;
        }
        .footer-bottom {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
        }
        .footer-links {
            display: flex;
            gap: 18px;
            list-style: none;
        }
        .footer-links a {
            color: var(--text-dim);
            text-decoration: none;
            transition: color 0.2s;
        }
        .footer-links a:hover {
            color: #fff;
        }

        @media (max-width: 900px) {
            .bento-grid { grid-template-columns: 1fr; }
            .bento-card.col-span-2 { grid-column: span 1; }
            .nav-menu { display: none; }
        }
    </style>
</head>
<body>

    <!-- Scroll Progress Indicator -->
    <div id="scroll-progress"></div>

    <!-- Navigation -->
    <nav class="navbar" id="top-navbar">
        <div class="container nav-inner">
            <a href="/trust" class="brand">
                <div class="brand-logo-shield">
                    <svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                TrustAudit
            </a>
            <ul class="nav-menu">
                <li><a href="#overview" class="nav-link active">Overview</a></li>
                <li><a href="#control-explorer" class="nav-link">Framework Explorer</a></li>
                <li><a href="#cisa-telemetry" class="nav-link">Threat Intelligence</a></li>
                <li><a href="#security-posture" class="nav-link">Security Architecture</a></li>
                <li><a href="#data-flow" class="nav-link">Data Transparency</a></li>
                <li><a href="#interactive-demos" class="nav-link">Interactive Demos</a></li>
                <li><a href="#perimeter-check" class="nav-link">Perimeter Check</a></li>
                <li><a href="#disclosure" class="nav-link">Vulnerability Disclosure</a></li>
            </ul>
            <div class="nav-actions">
                <a href="/dashboard" class="nav-link" style="font-weight: 600;">Dashboard &rarr;</a>
                <button class="btn-pack-nav" onclick="openTrustPackModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Trust Pack
                </button>
            </div>
        </div>
    </nav>

    <main class="container">

        <!-- HERO SECTION -->
        <header class="hero" id="overview">
            <div class="eyebrow-pill">
                <span class="eyebrow-dot"></span>
                TRUSTAUDIT SECURITY & COMPLIANCE
            </div>
            <h1>Security You Can Inspect.<br><span class="gradient-text">Trust You Can Verify.</span></h1>
            <p class="subtitle">
                Explore how TrustAudit protects source-code information, identifies security weaknesses, maps compliance requirements and tracks remediation.
            </p>
            <div class="hero-ctas">
                <a href="#security-posture" class="btn-primary-lg">
                    <span>Explore Security Architecture</span>
                    <svg class="icon-svg" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>
                </a>
                <button class="btn-secondary-lg" onclick="openTrustPackModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    <span>Download Enterprise Trust Pack</span>
                </button>
            </div>

            <!-- Honest Current-Status Bar -->
            <div class="status-strip">
                <div class="status-item">
                    <span class="status-item-label">Platform Status</span>
                    <span class="status-item-val">
                        <span class="status-indicator-dot"></span>
                        OPERATIONAL
                    </span>
                </div>
                <div class="status-item">
                    <span class="status-item-label">CISA KEV Sync</span>
                    <span class="status-item-val" id="strip-cisa-sync">Healthy (1,782 CVEs)</span>
                </div>
                <div class="status-item">
                    <span class="status-item-label">Tenant Isolation Test</span>
                    <span class="status-item-val" style="color: #34d399;">v2.4 (18/18 Passed)</span>
                </div>
                <div class="status-item">
                    <span class="status-item-label">Password & SSRF Standard</span>
                    <span class="status-item-val">OWASP 600k & SSRF Safe</span>
                </div>
                <div class="status-item">
                    <span class="status-item-label">Framework Review Date</span>
                    <span class="status-item-val">18 November 2026</span>
                </div>
            </div>
        </header>

        <!-- SECURITY POSTURE BENTO GRID -->
        <section id="security-posture" style="padding-top: 40px;">
            <div class="section-header">
                <span class="section-tag">High-Assurance Architecture</span>
                <h2>Verified Security Architecture</h2>
                <p>
                    Every card reflects verified source-code implementations, official provider guarantees, or automated test assertions.
                </p>
            </div>

            <div class="bento-grid">
                <!-- 1. Encryption in Transit -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box">
                            <svg class="icon-svg" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        </div>
                        <h3>Encryption in Transit</h3>
                        <p>TLS 1.3 and TLS 1.2 enforced across all public endpoints with HSTS. Plaintext HTTP traffic automatically redirected to HTTPS.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-provider">PROVIDER-REPORTED</span>
                        <span>Render / AWS TLS</span>
                    </div>
                </div>

                <!-- 2. Password Security & Hardening -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box green">
                            <svg class="icon-svg" viewBox="0 0 24 24"><path d="M21 2l-2 2m-1.5 1.5L16 7l-4 4-2-2-4 4 2 2 4-4 1.5 1.5 2-2 2-2z"/></svg>
                        </div>
                        <h3>Password Security</h3>
                        <p>OWASP-recommended PBKDF2-HMAC-SHA256 with 600,000 iterations, unique 16-byte random salts, rate limiting, and seamless rehash-on-login.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span>OWASP 2024/2026</span>
                    </div>
                </div>

                <!-- 3. Secret Redaction Pipeline -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box">
                            <svg class="icon-svg" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                        </div>
                        <h3>Secret Redaction</h3>
                        <p>Pre-persistence credential masking via Shannon entropy analysis and regex pattern matching. Tokens masked to safe preview strings.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span>secret_detector.py</span>
                    </div>
                </div>

                <!-- 4. Tenant Access Boundaries -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box green">
                            <svg class="icon-svg" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                        </div>
                        <h3>Tenant Access Isolation</h3>
                        <p>Strict organization-scoped database queries and authorization checks. Cross-tenant access attempts return HTTP 404.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span>18/18 Tests Passed</span>
                    </div>
                </div>

                <!-- 5. Ephemeral Repository Processing -->
                <div class="bento-card col-span-2">
                    <div>
                        <div class="icon-box amber">
                            <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                        </div>
                        <h3>Ephemeral Repository Processing</h3>
                        <p>Source code repositories are cloned into isolated temporary working directories created with <code>tempfile.mkdtemp</code>. Upon completion of AST/SAST analysis, the temporary directory is deleted via <code>shutil.rmtree</code>, ensuring 0-day disk retention for source code.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span>0-Day Source Retention</span>
                    </div>
                </div>

                <!-- 6. Vulnerability Intelligence -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box purple">
                            <svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        </div>
                        <h3>Vulnerability Intelligence</h3>
                        <p>Continuous background synchronization with the official CISA Known Exploited Vulnerabilities catalog for prioritization.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-operational">OPERATIONAL</span>
                        <span>1,782 KEV Entries</span>
                    </div>
                </div>

                <!-- 7. Multi-Factor Authentication -->
                <div class="bento-card">
                    <div>
                        <div class="icon-box green">
                            <svg class="icon-svg" viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
                        </div>
                        <h3>Multi-Factor Auth (MFA)</h3>
                        <p>RFC 6238 standard TOTP multi-factor authentication for organization administrators and security leads, compatible with Google Authenticator.</p>
                    </div>
                    <div class="card-footer-meta">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span>RFC 6238 TOTP</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- FRAMEWORK EXPLORER & CONTROL MAPPINGS -->
        <section id="control-explorer" style="padding-top: 40px;">
            <div class="section-header">
                <span class="section-tag">Interactive GRC Explorer</span>
                <h2>Framework Explorer & Control Mappings</h2>
                <p>
                    Inspect how TrustAudit checks technical security controls against statutory regulations (including India's Digital Personal Data Protection Act, 2023 and Digital Personal Data Protection Rules, 2025) and international standards (SOC 2, ISO/IEC 27001:2022, GDPR).
                </p>
            </div>

            <!-- Pre-Launch vs Post-Launch Segmented Toggle -->
            <div class="framework-segment-wrapper">
                <div class="segment-container">
                    <button class="segment-btn active" id="btn-prelaunch" onclick="switchLaunchPhase('prelaunch')">
                        <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                        Pre-Launch Security Gates
                    </button>
                    <button class="segment-btn" id="btn-postlaunch" onclick="switchLaunchPhase('postlaunch')">
                        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                        Post-Launch Continuous Monitoring
                    </button>
                </div>
            </div>

            <!-- Phase Description Banner -->
            <div id="phase-banner" style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin-bottom: 24px; font-size: 13.5px; color: var(--text-muted);">
                <strong style="color: #fff;">Pre-Launch Shift-Left Security:</strong> Automated code scanning, SAST, secret detection, dependency CVE lookups, infrastructure-as-code checks, and statutory compliance gap analysis executed prior to merging code or deploying to production.
            </div>

            <!-- Explorer Filters -->
            <div class="explorer-controls">
                <div class="filter-group">
                    <button class="filter-btn active" onclick="filterFramework('ALL', this)">All Frameworks</button>
                    <button class="filter-btn" onclick="filterFramework('DPDP', this)">DPDP Act 2023</button>
                    <button class="filter-btn" onclick="filterFramework('SOC2', this)">SOC 2 Criteria</button>
                    <button class="filter-btn" onclick="filterFramework('ISO27001', this)">ISO/IEC 27001</button>
                    <button class="filter-btn" onclick="filterFramework('GDPR', this)">EU GDPR</button>
                </div>
                <div class="search-box">
                    <svg class="icon-svg search-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    <input type="text" class="search-input" id="control-search-input" placeholder="Search controls, IDs, clauses..." onkeyup="searchControls()">
                </div>
            </div>

            <!-- Accordion Controls List -->
            <div class="controls-list" id="controls-accordion-list">
                
                <!-- 1. DPDP Section 6(9) -->
                <div class="ctrl-card" data-framework="DPDP" data-id="DPDP-SEC-06">
                    <div class="ctrl-header" onclick="toggleCtrl(this)">
                        <div class="ctrl-header-left">
                            <span class="ctrl-id-badge">DPDP-SEC-06(9)</span>
                            <span class="ctrl-title">Consent Architecture & Statutory Consent Manager Integration</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span class="status-pill status-provider">In Force (13 November 2026)</span>
                            <svg class="icon-svg ctrl-chevron" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="ctrl-body">
                        <div class="ctrl-grid-details">
                            <div class="detail-block">
                                <h4>Statutory Requirement & Legal Source</h4>
                                <p>Digital Personal Data Protection Act, 2023 Section 6(9) read with Digital Personal Data Protection Rules, 2025 Rule 4. Data Principals may manage or withdraw consent through registered Consent Managers accountable to the DPBI.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Scans codebase for consent revocation API routes (e.g. <code>DELETE /api/consent</code>), webhooks, and instruction propagation to downstream processors.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Static checks verify consent API wiring. TrustAudit does <em>not</em> self-attest as a registered statutory Consent Manager.</p>
                            </div>
                        </div>
                        <div class="ctrl-actions">
                            <button class="btn-action-sm" onclick="openRemediationModal('dpdp')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                View Remediation Example
                            </button>
                            <button class="btn-action-sm" onclick="openEvidenceModal('DPDP-SEC-06')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                View Sample Evidence JSON
                            </button>
                        </div>
                    </div>
                </div>

                <!-- 2. DPDP Section 8(5) -->
                <div class="ctrl-card" data-framework="DPDP" data-id="DPDP-SEC-08-5">
                    <div class="ctrl-header" onclick="toggleCtrl(this)">
                        <div class="ctrl-header-left">
                            <span class="ctrl-id-badge">DPDP-SEC-08(5)</span>
                            <span class="ctrl-title">Reasonable Security Safeguards & Credential Protection</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span class="status-pill status-roadmap">Commencing 13 May 2027</span>
                            <svg class="icon-svg ctrl-chevron" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="ctrl-body">
                        <div class="ctrl-grid-details">
                            <div class="detail-block">
                                <h4>Statutory Requirement & Legal Source</h4>
                                <p>Digital Personal Data Protection Act, 2023 Section 8(5) read with Digital Personal Data Protection Rules, 2025 Rule 6. Data Fiduciaries must take reasonable security safeguards to prevent personal data breaches.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Detects hardcoded secrets, unprotected database connections, missing encryption in transit, and insecure storage configurations before deployment.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Identifies automated technical code flaws. Physical premises security, organizational background checks, and vendor contracts require human administrative audit.</p>
                            </div>
                        </div>
                        <div class="ctrl-actions">
                            <button class="btn-action-sm" onclick="openRemediationModal('dpdp')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                View Remediation Example
                            </button>
                            <button class="btn-action-sm" onclick="openEvidenceModal('DPDP-SEC-08-5')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                View Sample Evidence JSON
                            </button>
                        </div>
                    </div>
                </div>

                <!-- 3. SOC 2 CC8.1 / CC6.1 -->
                <div class="ctrl-card" data-framework="SOC2" data-id="SOC2-CC8.1">
                    <div class="ctrl-header" onclick="toggleCtrl(this)">
                        <div class="ctrl-header-left">
                            <span class="ctrl-id-badge">SOC2-CC8.1</span>
                            <span class="ctrl-title">Change Management & Branch Protection Security Gates</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span class="status-pill status-verified">Technical Mapping</span>
                            <svg class="icon-svg ctrl-chevron" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="ctrl-body">
                        <div class="ctrl-grid-details">
                            <div class="detail-block">
                                <h4>AICPA TSC Published Scope</h4>
                                <p>AICPA 2017 TSC with 2022 Points of Focus CC8.1 (Change Management) & CC6.1 (Logical Access). Enforces authorized changes, peer code review, and automated testing prior to production release.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Inspects GitHub repository branch protection rules, required PR approvals, CI security action status checks, and linear commit histories.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Branch protection provides technical change gate evidence. Complete SOC 2 compliance also requires identity provisioning, access reviews, and formal CPA audit.</p>
                            </div>
                        </div>
                        <div class="ctrl-actions">
                            <button class="btn-action-sm" onclick="openRemediationModal('soc2')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                View Remediation Example
                            </button>
                            <button class="btn-action-sm" onclick="openEvidenceModal('SOC2-CC8.1')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                View Sample Evidence JSON
                            </button>
                        </div>
                    </div>
                </div>

                <!-- 4. ISO/IEC 27001 A.8.28 / A.8.8 -->
                <div class="ctrl-card" data-framework="ISO27001" data-id="ISO-A.8.28">
                    <div class="ctrl-header" onclick="toggleCtrl(this)">
                        <div class="ctrl-header-left">
                            <span class="ctrl-id-badge">ISO-A.8.28</span>
                            <span class="ctrl-title">Secure Coding Standards & Technical Vulnerability Management</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span class="status-pill status-verified">Technical Mapping</span>
                            <svg class="icon-svg ctrl-chevron" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="ctrl-body">
                        <div class="ctrl-grid-details">
                            <div class="detail-block">
                                <h4>ISO/IEC 27001:2022 Standard Scope</h4>
                                <p>Annex A Technological Controls: A.8.28 (Secure Coding) and A.8.8 (Management of Technical Vulnerabilities). Requires secure coding principles applied to development and systematic vulnerability identification.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Executes Semgrep semantic SAST rules, AST taint tracking, dependency CVE matching via OSV/NVD, and AI-coded pattern flaw detection.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Automated scanning detects software flaws. Complete ISO 27001 certification requires an accredited certification body examination of an enterprise ISMS.</p>
                            </div>
                        </div>
                        <div class="ctrl-actions">
                            <button class="btn-action-sm" onclick="openRemediationModal('iso27001')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                View Remediation Example
                            </button>
                            <button class="btn-action-sm" onclick="openEvidenceModal('ISO-A.8.28')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                View Sample Evidence JSON
                            </button>
                        </div>
                    </div>
                </div>

                <!-- 5. EU GDPR Article 32 / 33 -->
                <div class="ctrl-card" data-framework="GDPR" data-id="GDPR-ART-32">
                    <div class="ctrl-header" onclick="toggleCtrl(this)">
                        <div class="ctrl-header-left">
                            <span class="ctrl-id-badge">GDPR-ART-32</span>
                            <span class="ctrl-title">Security of Processing & Documented Breach Assessment</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span class="status-pill status-provider">Technical Mapping</span>
                            <svg class="icon-svg ctrl-chevron" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>
                        </div>
                    </div>
                    <div class="ctrl-body">
                        <div class="ctrl-grid-details">
                            <div class="detail-block">
                                <h4>EU GDPR Regulatory Scope</h4>
                                <p>Article 32 (Security of processing), Article 33 (Notification of breach to supervisory authority within 72 hours), and Article 34 (Communication to data subject when high risk).</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Evaluates transport encryption, secret redaction, vulnerability exposure, and logs incident resolution timelines in the Remediation Centre.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Automated checks support technical posture evidence. Legal assessments regarding supervisory notification thresholds require legal counsel.</p>
                            </div>
                        </div>
                        <div class="ctrl-actions">
                            <button class="btn-action-sm" onclick="openRemediationModal('gdpr')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                                View Remediation Example
                            </button>
                            <button class="btn-action-sm" onclick="openEvidenceModal('GDPR-ART-32')">
                                <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                View Sample Evidence JSON
                            </button>
                        </div>
                    </div>
                </div>

            </div>
        </section>

        <!-- DATA FLOW & EPHEMERAL PIPELINE DIAGRAM -->
        <section id="data-flow" style="padding-top: 40px;">
            <div class="section-header">
                <span class="section-tag">Zero-Day Disk Retention</span>
                <h2>Interactive Repository Processing Pipeline</h2>
                <p>
                    Follow the verified lifecycle of customer code. Click any stage to inspect what data is processed, stored, and deleted.
                </p>
            </div>

            <div class="pipeline-wrapper">
                <div class="pipeline-header">
                    <span style="font-weight: 700; color: #fff;">SANDBOX PROCESSING LIFECYCLE</span>
                    <span class="status-pill status-verified">Verified 0-Day Disk Retention</span>
                </div>

                <div class="pipeline-nodes-container">
                    <div class="pipeline-node active" onclick="inspectNode('repo', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
                        <div class="pipeline-node-name">GitHub Repo</div>
                        <div class="pipeline-node-sub">Source Repository</div>
                    </div>
                    <div class="pipeline-arrow">&rarr;</div>
                    <div class="pipeline-node" onclick="inspectNode('clone', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                        <div class="pipeline-node-name">Ephemeral Clone</div>
                        <div class="pipeline-node-sub">tempfile.mkdtemp</div>
                    </div>
                    <div class="pipeline-arrow">&rarr;</div>
                    <div class="pipeline-node" onclick="inspectNode('ast', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                        <div class="pipeline-node-name">AST / SAST Analysis</div>
                        <div class="pipeline-node-sub">In-Memory Engine</div>
                    </div>
                    <div class="pipeline-arrow">&rarr;</div>
                    <div class="pipeline-node" onclick="inspectNode('redact', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                        <div class="pipeline-node-name">Secret Redaction</div>
                        <div class="pipeline-node-sub">Entropy Masking</div>
                    </div>
                    <div class="pipeline-arrow">&rarr;</div>
                    <div class="pipeline-node node-cleanup" onclick="inspectNode('cleanup', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
                        <div class="pipeline-node-name" style="color: #f59e0b;">Workspace Scrub</div>
                        <div class="pipeline-node-sub">shutil.rmtree</div>
                    </div>
                    <div class="pipeline-arrow">&rarr;</div>
                    <div class="pipeline-node" onclick="inspectNode('store', this)">
                        <svg class="icon-svg" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                        <div class="pipeline-node-name">Tenant Store</div>
                        <div class="pipeline-node-sub">Metadata & Fixes</div>
                    </div>
                </div>

                <!-- Stage Inspector Panel -->
                <div class="node-inspector-panel" id="node-inspector-panel">
                    <div>
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">STAGE NAME</div>
                        <div id="insp-title" style="font-size: 14.5px; font-weight: 700; color: #fff; margin-top: 2px;">GitHub Repository Connection</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">DATA INGESTED</div>
                        <div id="insp-ingest" style="font-size: 13.5px; color: var(--text-muted); margin-top: 2px;">Target repository URL and fine-grained PAT</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">STORAGE / DELETION ACTION</div>
                        <div id="insp-retention" style="font-size: 13.5px; color: #34d399; margin-top: 2px;">No source code stored; cloned to RAM/ephemeral disk</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- INTERACTIVE DEMONSTRATIONS -->
        <section id="interactive-demos" style="padding-top: 40px;">
            <div class="section-header">
                <span class="section-tag">Interactive Verification</span>
                <h2>Interactive Security Command Demos</h2>
                <p>
                    Test client-side credential masking, simulate enterprise security questionnaire population, and inspect live vulnerability intelligence.
                </p>
            </div>

            <div class="demos-grid">
                <!-- Demo 1: Secret Redaction Sandbox -->
                <div class="demo-box">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                        <h3>Test Secret Redaction Sandbox</h3>
                        <span class="status-pill status-provider" style="font-size: 10.5px;">CLIENT-SIDE DEMO — SYNTHETIC ONLY</span>
                    </div>
                    <p class="desc">
                        Type or paste a synthetic example credential below. Processing is 100% in-browser with zero network transmission, protected from XSS.
                    </p>

                    <div class="sandbox-input-group">
                        <input type="text" class="sandbox-input" id="sandbox-input-val" placeholder="sk-test-example-123456789" value="sk-test-example-123456789">
                        <button class="btn-test-action" id="btn-run-mask" onclick="runMaskingDemo()">Test Masking</button>
                        <button class="btn-action-sm" onclick="resetMaskingDemo()">Reset</button>
                    </div>

                    <div class="sandbox-result" id="sandbox-output-box">
                        <div style="color: var(--text-dim); font-size: 12px; margin-bottom: 4px;">DETECTION &rarr; MASKING &rarr; SAFE PREVIEW</div>
                        <div id="sandbox-result-text" style="color: #38bdf8; font-weight: 600;">sk-t...[REDACTED]...6789</div>
                        <div id="sandbox-entropy-text" style="color: var(--text-dim); font-size: 11px; margin-top: 6px;">Shannon Entropy: 3.42 bits/char &bull; Classification: API Key Pattern</div>
                    </div>
                </div>

                <!-- Demo 2: Questionnaire Simulator -->
                <div class="demo-box">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                        <h3>Enterprise Security Questionnaire Simulator</h3>
                        <span class="status-pill status-verified" style="font-size: 10.5px;">DEMO SIMULATION</span>
                    </div>
                    <p class="desc">
                        Watch how TrustAudit maps verified technical checks into answers for customer vendor risk questionnaires.
                    </p>

                    <div style="display: flex; gap: 10px; margin-bottom: 12px;">
                        <button class="btn-test-action" onclick="runQuestionnaireSimulator()">Auto-Fill Demo Evidence</button>
                        <button class="btn-action-sm" onclick="resetQuestionnaireSimulator()">Reset</button>
                    </div>

                    <div class="q-simulator-list">
                        <div class="q-row active" id="q-row-1">
                            <div class="q-row-header">
                                <span>1. How do you manage access to source code?</span>
                                <span class="q-badge" id="q-badge-1">SAMPLE EVIDENCE LINKED</span>
                            </div>
                            <div class="q-row-body" id="q-body-1">
                                <strong>DEMO ANSWER:</strong> Source code is processed strictly inside ephemeral sandboxes created with <code>tempfile.mkdtemp</code> and immediately wiped via <code>shutil.rmtree</code>. Scanners operate read-only without storing code on persistent media.
                            </div>
                        </div>

                        <div class="q-row" id="q-row-2">
                            <div class="q-row-header">
                                <span>2. How do you identify and remediate vulnerable dependencies?</span>
                                <span class="q-badge" id="q-badge-2">SAMPLE EVIDENCE LINKED</span>
                            </div>
                            <div class="q-row-body" id="q-body-2">
                                <strong>DEMO ANSWER:</strong> Continuous cross-referencing against Google OSV and the official CISA KEV catalog. Vulnerabilities are correlated to direct vs transitive dependencies with automated fix suggestions and SLA tracking.
                            </div>
                        </div>

                        <div class="q-row" id="q-row-3">
                            <div class="q-row-header">
                                <span>3. How do you manage security incidents and remediation?</span>
                                <span class="q-badge" id="q-badge-3">ILLUSTRATIVE CONTROL MAPPING</span>
                            </div>
                            <div class="q-row-body" id="q-body-3">
                                <strong>DEMO ANSWER:</strong> High and Critical vulnerabilities trigger automated remediation tasks with SLA clocks. Findings link directly to code files, severity classifications, and fix verification procedures.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- QUICK PERIMETER & PRIVACY CHECK WIDGET -->
        <section id="perimeter-check" style="padding-top: 40px;">
            <div class="perimeter-box">
                <div class="section-tag">Instant Technical Check</div>
                <h3 style="font-size: 22px; font-weight: 800; color: #fff; margin-bottom: 6px;">Quick Perimeter & Privacy Check</h3>
                <p style="color: var(--text-muted); font-size: 14px; max-width: 750px;">
                    Check basic publicly observable website security and privacy indicators. This is an initial technical check protected against SSRF, not a complete security assessment or legal compliance determination.
                </p>

                <div class="perimeter-form">
                    <input type="text" class="perimeter-input" id="perimeter-url-input" placeholder="https://example.com" value="https://example.com">
                    <button class="btn-primary-lg" id="btn-run-perimeter" onclick="runQuickPerimeterCheck()">
                        <svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
                        Run Quick Check
                    </button>
                </div>

                <div class="perimeter-results-card" id="perimeter-results-card">
                    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 10px;">
                        <span style="font-weight: 700; color: #fff;" id="perimeter-target-title">WEBSITE CHECK RESULTS</span>
                        <span class="status-pill status-verified" id="perimeter-status-pill">CHECK COMPLETE</span>
                    </div>

                    <div class="perimeter-grid">
                        <div class="perimeter-item">
                            <div class="perimeter-item-label">HTTPS Transport</div>
                            <div class="perimeter-item-val" id="res-https" style="color: #34d399;">PASS</div>
                        </div>
                        <div class="perimeter-item">
                            <div class="perimeter-item-label">TLS Certificate</div>
                            <div class="perimeter-item-val" id="res-tls" style="color: #38bdf8;">CHECKED</div>
                        </div>
                        <div class="perimeter-item">
                            <div class="perimeter-item-label">HSTS Header</div>
                            <div class="perimeter-item-val" id="res-hsts">PASS</div>
                        </div>
                        <div class="perimeter-item">
                            <div class="perimeter-item-label">Privacy Policy Link</div>
                            <div class="perimeter-item-val" id="res-policy">FOUND</div>
                        </div>
                        <div class="perimeter-item">
                            <div class="perimeter-item-label">Privacy / Grievance Contact</div>
                            <div class="perimeter-item-val" id="res-contact">FOUND</div>
                        </div>
                    </div>

                    <div style="font-size: 12px; color: var(--text-dim); margin-top: 14px; line-height: 1.5;" id="perimeter-disclaimer-text">
                        <strong>Notice:</strong> This check evaluates basic observable network transport and privacy links. It does not prove complete DPDP compliance or formal DPO appointment.
                    </div>

                    <div style="margin-top: 18px; text-align: right;">
                        <a href="/dashboard" class="btn-primary-lg" style="font-size: 13.5px; padding: 8px 16px;">
                            Run Full Pre-Launch Code + Compliance Scan &rarr;
                        </a>
                    </div>
                </div>
            </div>
        </section>

        <!-- LIVE CISA KEV TELEMETRY -->
        <section id="cisa-telemetry" style="padding-top: 40px; margin-bottom: 80px;">
            <div class="bento-card" style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 14px; padding: 30px;">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin-bottom: 20px;">
                    <div>
                        <div class="section-tag">Exploitation Intelligence</div>
                        <h3 style="font-size: 22px; font-weight: 800; color: #fff;">CISA Known Exploited Vulnerabilities (KEV) Live Telemetry</h3>
                    </div>
                    <button class="btn-action-sm" id="btn-tele-refresh" onclick="refreshTelemetry()">
                        <svg class="icon-svg" id="tele-spinner" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                        Refresh Telemetry
                    </button>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px;">
                    <div style="background: var(--bg-elevated); padding: 18px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.05);">
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">CATALOGUE COUNT</div>
                        <div id="tele-records" style="font-size: 26px; font-weight: 800; color: #38bdf8; font-family: var(--font-mono); margin-top: 4px;">1,782 CVEs</div>
                    </div>
                    <div style="background: var(--bg-elevated); padding: 18px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.05);">
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">SYNC HEALTH STATUS</div>
                        <div id="tele-status" style="font-size: 26px; font-weight: 800; color: #34d399; font-family: var(--font-mono); margin-top: 4px;">Healthy</div>
                    </div>
                    <div style="background: var(--bg-elevated); padding: 18px; border-radius: 10px; border: 1px solid rgba(255, 255, 255, 0.05);">
                        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">LAST SYNCHRONISATION</div>
                        <div id="tele-sync" style="font-size: 14px; font-weight: 600; color: #fff; font-family: var(--font-mono); margin-top: 8px;">2026-11-19 UTC</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- GOVERNANCE & PRIVACY SECTION -->
        <section id="disclosure" style="padding-top: 40px; margin-bottom: 80px;">
            <div class="section-header">
                <span class="section-tag">Governance & Transparency</span>
                <h2>Data Governance & Verified Contacts</h2>
                <p>
                    Clear infrastructure disclosures, official contacts, and grievance redressal workflows.
                </p>
            </div>

            <div class="governance-grid">
                <!-- India Region Card -->
                <div class="gov-card">
                    <h3>
                        <svg class="icon-svg" viewBox="0 0 24 24"><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>
                        India Hosting Region
                    </h3>
                    <p>
                        <strong>AWS Asia Pacific (Mumbai) — ap-south-1:</strong> TrustAudit evaluates dedicated India-region hosting for enterprise tenants. Shared SaaS is currently hosted on Render (US/EU).
                    </p>
                    <div style="margin-top: 10px;">
                        <span class="status-pill status-roadmap">INDIA REGION — PLANNED / ENTERPRISE ONLY</span>
                    </div>
                    <p style="font-size: 12px; color: var(--text-dim); margin-top: 10px;">
                        Note: DPDP Section 16 permits cross-border data transfer to countries not restricted by the Central Government. Data residency alone does not equate to complete compliance.
                    </p>
                </div>

                <!-- Grievance & Privacy Contact -->
                <div class="gov-card">
                    <h3>
                        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        Privacy & Grievance Contact
                    </h3>
                    <p>
                        Designated contact under DPDP Section 13 & Rule 14 for privacy enquiries and Data Principal rights requests:
                    </p>
                    <div style="font-family: var(--font-mono); font-size: 14px; color: #38bdf8; margin: 8px 0;">
                        grievance@trustaudit.io
                    </div>
                    <button class="btn-action-sm" style="margin-top: 8px;" onclick="openGrievanceModal()">
                        Submit Grievance / Data Request &rarr;
                    </button>
                </div>

                <!-- Security Contact & RFC 9116 -->
                <div class="gov-card">
                    <h3>
                        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        Security & Disclosure Policy
                    </h3>
                    <p>
                        For vulnerability reports and security inquiries: <strong>security@trustaudit.io</strong>. We support safe harbor for independent security researchers acting in good faith.
                    </p>
                    <div style="margin-top: 12px;">
                        <a href="/.well-known/security.txt" target="_blank" class="nav-link" style="color: var(--primary-light); font-size: 13px;">
                            View RFC 9116 security.txt &rarr;
                        </a>
                    </div>
                </div>
            </div>
        </section>

    </main>

    <!-- FOOTER & LEGAL DISCLAIMER -->
    <footer class="footer">
        <div class="container">
            <div class="footer-disclaimer-box">
                <strong>Legal & Regulatory Notice:</strong> TrustAudit provides automated technical gap analysis, security scanning, and compliance evidence management. 
                TrustAudit does not issue formal regulatory certifications, accredited ISO 27001 certificates, or certified SOC 2 Type II reports, which require independent examination by accredited third-party certification bodies and CPA firms. 
                Compliance with applicable laws (including Digital Personal Data Protection Act, 2023, GDPR, and sectoral regulations) remains the statutory responsibility of the customer organization. 
                TrustAudit does not send customer source code or vulnerability findings to third-party AI models.
            </div>

            <div class="footer-bottom">
                <div>&copy; 2026 TrustAudit Security Platform. All rights reserved.</div>
                <ul class="footer-links">
                    <li><a href="/trust">Trust Center</a></li>
                    <li><a href="/dashboard">Dashboard</a></li>
                    <li><a href="/.well-known/security.txt">security.txt</a></li>
                    <li><a href="mailto:security@trustaudit.io">Security</a></li>
                    <li><a href="mailto:grievance@trustaudit.io">Grievances</a></li>
                </ul>
            </div>
        </div>
    </footer>

    <!-- MODAL 1: ENTERPRISE TRUST PACK BUILDER -->
    <div class="modal-overlay" id="trust-pack-modal" onclick="closeModalOnOverlay(event, 'trust-pack-modal')">
        <div class="modal-card">
            <div class="modal-header">
                <div>
                    <h3 style="color: #fff; margin-bottom: 4px;">Download Enterprise Trust Pack</h3>
                    <p style="color: var(--text-muted); font-size: 13px;">Select approved security dossiers to bundle for vendor assessment.</p>
                </div>
                <button class="modal-close-btn" onclick="closeTrustPackModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>

            <form id="pack-download-form" onsubmit="handleTrustPackDownload(event)">
                <div class="form-check-group">
                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="overview" checked>
                        <div>
                            <div class="check-text-title">TrustAudit Security Overview & Posture Statement</div>
                            <div class="check-text-desc">High-level threat modeling, architecture, and security principles.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="dpdp" checked>
                        <div>
                            <div class="check-text-title">DPDP Act 2023 & Rules 2025 Readiness Mapping</div>
                            <div class="check-text-desc">Statutory timeline mapping (Nov 2026 vs May 2027) and technical safeguards.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="soc2" checked>
                        <div>
                            <div class="check-text-title">SOC 2 Control Mapping (2017 TSC / 2022 Focus)</div>
                            <div class="check-text-desc">Technical mappings across CC6.1, CC6.6, CC6.8, CC7.1, and CC8.1.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="iso27001" checked>
                        <div>
                            <div class="check-text-title">ISO/IEC 27001:2022 Technological Controls Mapping</div>
                            <div class="check-text-desc">Annex A mappings (A.8.8, A.8.20, A.8.24, A.8.25, A.8.28).</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="retention" checked>
                        <div>
                            <div class="check-text-title">Data Retention & Ephemeral Scrubbing Schedule</div>
                            <div class="check-text-desc">Verified 0-day disk retention disclosures and customer deletion procedures.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="subprocessors" checked>
                        <div>
                            <div class="check-text-title">Official Subprocessor Register</div>
                            <div class="check-text-desc">Exhaustive list of hosting, compute, and database infrastructure providers.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="disclosure">
                        <div>
                            <div class="check-text-title">Vulnerability Disclosure & Safe Harbor Policy</div>
                            <div class="check-text-desc">Reporting channels, SLA commitments, and researcher guidelines.</div>
                        </div>
                    </label>

                    <label class="custom-checkbox-label">
                        <input type="checkbox" name="doc" value="architecture">
                        <div>
                            <div class="check-text-title">Technical Security Architecture Overview</div>
                            <div class="check-text-desc">Detailed multi-tenant isolation, PBKDF2 hashing, and AST taint engine.</div>
                        </div>
                    </label>
                </div>

                <div style="border-top: 1px solid var(--border); padding-top: 16px; margin-top: 16px;">
                    <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 8px;">Select Output Format:</div>
                    <div style="display: flex; gap: 20px;">
                        <label style="display: flex; align-items: center; gap: 8px; font-size: 13.5px; color: var(--text-muted); cursor: pointer;">
                            <input type="radio" name="format" value="zip" checked style="accent-color: var(--primary-light);">
                            Structured ZIP Bundle (.zip)
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; font-size: 13.5px; color: var(--text-muted); cursor: pointer;">
                            <input type="radio" name="format" value="markdown" style="accent-color: var(--primary-light);">
                            Consolidated Markdown (.md)
                        </label>
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px;">
                    <button type="button" class="btn-action-sm" onclick="closeTrustPackModal()">Cancel</button>
                    <button type="submit" class="btn-primary-lg" style="font-size: 13.5px; padding: 9px 20px;">Download Trust Pack</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL 2: SAFE REMEDIATION EXAMPLE MODAL -->
    <div class="modal-overlay" id="remediation-modal" onclick="closeModalOnOverlay(event, 'remediation-modal')">
        <div class="modal-card">
            <div class="modal-header">
                <h3 id="rem-modal-title">Illustrative Remediation Guidance</h3>
                <button class="modal-close-btn" onclick="closeRemediationModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <div style="font-size: 13px; color: var(--text-dim); margin-bottom: 10px;" id="rem-modal-meta">
                STATUTORY MAPPING & TESTING GUIDELINES
            </div>
            <div id="rem-modal-desc" style="color: var(--text-muted); font-size: 13.5px; margin-bottom: 12px;"></div>
            <pre class="code-box-pre"><code id="rem-modal-code"></code></pre>
            <div id="rem-modal-notes" style="font-size: 12.5px; color: var(--text-dim); line-height: 1.5;"></div>
            <div style="margin-top: 20px; text-align: right;">
                <button class="btn-primary-lg" style="font-size: 13px; padding: 7px 16px;" onclick="closeRemediationModal()">Done</button>
            </div>
        </div>
    </div>

    <!-- MODAL 3: EVIDENCE JSON SAMPLE PREVIEW -->
    <div class="modal-overlay" id="evidence-modal" onclick="closeModalOnOverlay(event, 'evidence-modal')">
        <div class="modal-card">
            <div class="modal-header">
                <div>
                    <h3 style="color: #fff;">Sample Evidence Artifact</h3>
                    <div style="font-size: 12px; color: var(--warning); font-weight: 600;">ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD</div>
                </div>
                <button class="modal-close-btn" onclick="closeEvidenceModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <pre class="code-box-pre"><code id="evidence-modal-code"></code></pre>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px;">
                <span id="evidence-copy-feedback" style="font-size: 12px; color: #34d399;"></span>
                <button class="btn-primary-lg" style="font-size: 13px; padding: 7px 16px;" onclick="copyEvidenceJson()">Copy Sample JSON</button>
            </div>
        </div>
    </div>

    <!-- MODAL 4: GRIEVANCE REDRESSAL SUBMISSION -->
    <div class="modal-overlay" id="grievance-modal" onclick="closeModalOnOverlay(event, 'grievance-modal')">
        <div class="modal-card">
            <div class="modal-header">
                <div>
                    <h3 style="color: #fff;">Submit Grievance / Privacy Request</h3>
                    <p style="color: var(--text-muted); font-size: 12.5px;">DPDP Act 2023 Section 13 & Rule 14 Grievance Redressal</p>
                </div>
                <button class="modal-close-btn" onclick="closeGrievanceModal()">
                    <svg class="icon-svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <form onsubmit="handleGrievanceSubmit(event)">
                <div style="margin-bottom: 12px;">
                    <label style="font-size: 12.5px; font-weight: 600; color: #fff;">Your Full Name *</label>
                    <input type="text" id="grv-name" required class="sandbox-input" style="width: 100%; margin-top: 4px;" placeholder="Full Name">
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="font-size: 12.5px; font-weight: 600; color: #fff;">Email Address *</label>
                    <input type="email" id="grv-email" required class="sandbox-input" style="width: 100%; margin-top: 4px;" placeholder="name@example.com">
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="font-size: 12.5px; font-weight: 600; color: #fff;">Category *</label>
                    <select id="grv-category" class="sandbox-input" style="width: 100%; margin-top: 4px;">
                        <option value="Personal Data Erasure">Personal Data Erasure Request</option>
                        <option value="Consent Withdrawal Inquiry">Consent Withdrawal Inquiry</option>
                        <option value="Data Processing Question">Data Processing Question</option>
                        <option value="Security Finding Inquiry">Security Finding Inquiry</option>
                        <option value="Other Grievance">Other Grievance</option>
                    </select>
                </div>
                <div style="margin-bottom: 16px;">
                    <label style="font-size: 12.5px; font-weight: 600; color: #fff;">Description of Request *</label>
                    <textarea id="grv-desc" required class="sandbox-input" style="width: 100%; height: 90px; margin-top: 4px;" placeholder="Please describe your enquiry or request..."></textarea>
                </div>
                <div style="display: flex; justify-content: flex-end; gap: 10px;">
                    <button type="button" class="btn-action-sm" onclick="closeGrievanceModal()">Cancel</button>
                    <button type="submit" class="btn-primary-lg" style="font-size: 13px; padding: 8px 18px;">Submit Request</button>
                </div>
            </form>
        </div>
    </div>

    <!-- CLIENT INTERACTIVE JAVASCRIPT LOGIC -->
    <script>
        // 1. Scroll Progress & Scroll Spy
        window.addEventListener('scroll', () => {
            const docH = document.documentElement.scrollHeight - window.innerHeight;
            const progress = (window.scrollY / docH) * 100;
            document.getElementById('scroll-progress').style.width = progress + '%';

            const sections = ['overview', 'control-explorer', 'cisa-telemetry', 'security-posture', 'data-flow', 'interactive-demos', 'perimeter-check', 'disclosure'];
            let current = '';
            sections.forEach(id => {
                const el = document.getElementById(id);
                if (el && window.scrollY >= (el.offsetTop - 120)) {
                    current = id;
                }
            });
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {
                    link.classList.add('active');
                }
            });
        });

        // 2. Pre-Launch vs Post-Launch Switcher
        function switchLaunchPhase(phase) {
            const btnPre = document.getElementById('btn-prelaunch');
            const btnPost = document.getElementById('btn-postlaunch');
            const banner = document.getElementById('phase-banner');

            if (phase === 'prelaunch') {
                btnPre.classList.add('active');
                btnPost.classList.remove('active');
                banner.innerHTML = '<strong style="color: #fff;">Pre-Launch Shift-Left Security:</strong> Automated code scanning, SAST, secret detection, dependency CVE lookups, infrastructure-as-code checks, and statutory compliance gap analysis executed prior to merging code or deploying to production.';
            } else {
                btnPost.classList.add('active');
                btnPre.classList.remove('active');
                banner.innerHTML = '<strong style="color: #fff;">Post-Launch Continuous Monitoring:</strong> TLS & certificate tracking, vulnerable dependency alerts from CISA KEV, security posture drift detection, continuous compliance tasks, and fresh evidence collection on running applications.';
            }
        }

        // 3. Framework Filter
        function filterFramework(framework, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const cards = document.querySelectorAll('.ctrl-card');
            cards.forEach(c => {
                if (framework === 'ALL' || c.getAttribute('data-framework') === framework) {
                    c.style.display = 'block';
                } else {
                    c.style.display = 'none';
                }
            });
        }

        // 4. Keyword Search across Controls
        function searchControls() {
            const q = document.getElementById('control-search-input').value.toLowerCase();
            const cards = document.querySelectorAll('.ctrl-card');
            cards.forEach(c => {
                const text = c.innerText.toLowerCase();
                c.style.display = text.includes(q) ? 'block' : 'none';
            });
        }

        // 5. Accordion Toggle
        function toggleCtrl(headerEl) {
            const card = headerEl.parentElement;
            card.classList.toggle('open');
        }

        // 6. Architecture Node Inspector
        const ARCH_NODES = {
            repo: {
                title: "GitHub Repository Connection",
                ingest: "Target repository URL, branch metadata, fine-grained personal access token.",
                retention: "No source code stored. Connected via read-only GitHub API integration."
            },
            clone: {
                title: "Ephemeral Sandbox Workspace",
                ingest: "Temporary shallow git clone executed into tempfile.mkdtemp.",
                retention: "Ephemeral directory strictly sandboxed with restricted OS worker permissions."
            },
            ast: {
                title: "AST & Semantic SAST Analysis",
                ingest: "In-memory AST parsing, Semgrep semantic rules, taint analysis.",
                retention: "Analyzed completely in RAM. No source code persisted beyond worker execution."
            },
            redact: {
                title: "Secret Detection & Redaction Pipeline",
                ingest: "Raw findings with candidate API tokens, private keys, or credentials.",
                retention: "High-entropy and regex matching secrets masked to safe previews before persistence."
            },
            cleanup: {
                title: "Temporary Workspace Scrubbing",
                ingest: "Temporary workspace path targeted upon scan completion.",
                retention: "Deleted immediately using shutil.rmtree. Verified 0-day disk retention."
            },
            store: {
                title: "Tenant-Isolated Findings Store",
                ingest: "Normalized finding titles, CWE/CVE mappings, line numbers, remediation tasks.",
                retention: "Retained under organization context with cryptographic isolation test coverage."
            }
        };

        function inspectNode(key, element) {
            document.querySelectorAll('.pipeline-node').forEach(n => n.classList.remove('active'));
            element.classList.add('active');
            const data = ARCH_NODES[key] || ARCH_NODES.repo;
            document.getElementById('insp-title').innerText = data.title;
            document.getElementById('insp-ingest').innerText = data.ingest;
            document.getElementById('insp-retention').innerText = data.retention;
        }

        // 7. Client-Side Secret Redaction Sandbox (100% In-Browser, XSS Protected via textContent)
        function calculateEntropy(str) {
            if (!str) return 0;
            const len = str.length;
            const freqs = {};
            for (let i = 0; i < len; i++) {
                freqs[str[i]] = (freqs[str[i]] || 0) + 1;
            }
            let entropy = 0;
            for (const char in freqs) {
                const p = freqs[char] / len;
                entropy -= p * Math.log2(p);
            }
            return entropy.toFixed(2);
        }

        function runMaskingDemo() {
            const rawVal = document.getElementById('sandbox-input-val').value.trim();
            const resEl = document.getElementById('sandbox-result-text');
            const entEl = document.getElementById('sandbox-entropy-text');

            if (!rawVal) {
                resEl.textContent = "[Empty Input - Enter a synthetic token]";
                entEl.textContent = "Shannon Entropy: 0 bits/char";
                return;
            }

            // Masking rule: keep first 4 chars, mask middle with [REDACTED], keep last 4 chars
            let masked = "";
            if (rawVal.length <= 8) {
                masked = rawVal.substring(0, 2) + "...[REDACTED]";
            } else {
                masked = rawVal.substring(0, 4) + "...[REDACTED]..." + rawVal.substring(rawVal.length - 4);
            }

            // Safe textContent assignment (strictly prevents XSS)
            resEl.textContent = masked;
            const entropy = calculateEntropy(rawVal);
            entEl.textContent = `Shannon Entropy: ${entropy} bits/char • Pattern Detected: Candidate Credential • Zero Network Transmission`;
        }

        function resetMaskingDemo() {
            document.getElementById('sandbox-input-val').value = "sk-test-example-123456789";
            runMaskingDemo();
        }

        // 8. Questionnaire Simulator with 150ms Staggered Typewriter Animation
        function runQuestionnaireSimulator() {
            const rows = [1, 2, 3];
            rows.forEach((num, index) => {
                setTimeout(() => {
                    const row = document.getElementById('q-row-' + num);
                    if (row) row.classList.add('active');
                }, (index + 1) * 150);
            });
        }

        function resetQuestionnaireSimulator() {
            [2, 3].forEach(num => {
                const row = document.getElementById('q-row-' + num);
                if (row) row.classList.remove('active');
            });
        }

        // 9. Quick Perimeter Check (SSRF-Protected)
        function runQuickPerimeterCheck() {
            const urlInput = document.getElementById('perimeter-url-input');
            const btn = document.getElementById('btn-run-perimeter');
            const resultsCard = document.getElementById('perimeter-results-card');

            const targetUrl = urlInput.value.trim();
            if (!targetUrl) {
                alert("Please enter a valid URL.");
                return;
            }

            btn.disabled = true;
            btn.innerHTML = 'Scanning Perimeter...';

            fetch('/api/public/quick-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            })
            .then(res => res.json())
            .then(data => {
                resultsCard.style.display = 'block';
                document.getElementById('perimeter-target-title').innerText = 'PERIMETER RESULTS: ' + (data.url || targetUrl);

                const checks = data.checks || {};
                document.getElementById('res-https').innerText = checks.https || 'UNKNOWN';
                document.getElementById('res-tls').innerText = checks.tls || 'UNKNOWN';
                document.getElementById('res-hsts').innerText = checks.hsts || 'UNKNOWN';
                document.getElementById('res-policy').innerText = checks.privacy_policy || 'NOT DETECTED';
                document.getElementById('res-contact').innerText = checks.privacy_contact || 'NOT DETECTED';

                // Style based on results
                document.getElementById('res-https').style.color = (checks.https === 'PASS') ? '#34d399' : '#f59e0b';
                document.getElementById('res-hsts').style.color = (checks.hsts === 'PASS') ? '#34d399' : '#f59e0b';

                if (data.status === 'blocked') {
                    document.getElementById('perimeter-status-pill').className = 'status-pill status-roadmap';
                    document.getElementById('perimeter-status-pill').innerText = 'SSRF BLOCKED';
                    document.getElementById('perimeter-disclaimer-text').innerText = data.message;
                } else {
                    document.getElementById('perimeter-status-pill').className = 'status-pill status-verified';
                    document.getElementById('perimeter-status-pill').innerText = 'CHECK COMPLETE';
                }
            })
            .catch(err => {
                resultsCard.style.display = 'block';
                document.getElementById('perimeter-status-pill').innerText = 'CHECK FAILED';
                document.getElementById('perimeter-disclaimer-text').innerText = 'Unable to complete perimeter check: ' + err;
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = '<svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg> Run Quick Check';
            });
        }

        // 10. Live Telemetry Polling
        function refreshTelemetry() {
            const spinner = document.getElementById('tele-spinner');
            if (spinner) spinner.style.animation = 'spin 0.8s linear infinite';

            fetch('/api/public/trust-status')
                .then(res => res.json())
                .then(data => {
                    if (data && data.kev_sync) {
                        document.getElementById('tele-records').innerText = data.kev_sync.catalog_entries + ' CVEs';
                        document.getElementById('tele-status').innerText = data.kev_sync.status;
                        document.getElementById('tele-sync').innerText = (data.kev_sync.last_successful_sync || '').substring(0, 19) + ' UTC';
                    }
                })
                .catch(() => {})
                .finally(() => {
                    if (spinner) spinner.style.animation = 'none';
                });
        }

        // 11. Remediation Modals Data & Handlers
        const REMEDIATION_PLAYBOOKS = {
            dpdp: {
                title: "DPDP Act 2023 Consent Withdrawal Workflow",
                meta: "DPDP ACT 2023 SECTION 6(4)-(6) READ WITH DPDP RULES 2025",
                desc: "Illustrative backend endpoint implementing authenticated consent revocation, stop-processing instruction dispatch to processors, and audit trail preservation. Prior lawful processing is not rendered unlawful.",
                code: `@app.route("/api/v1/consent/withdraw", methods=["POST"])
def withdraw_consent():
    # DPDP Section 6(4)-(6) Compliant Consent Withdrawal Handler:
    # 1. Authenticate Data Principal.
    # 2. Identify purpose-specific consent record.
    # 3. Update consent status to WITHDRAWN with UTC timestamp.
    # 4. Cause downstream processors to cease processing (Section 6(6)).
    # 5. Retain audit record of withdrawal.
    user_id = request.user.id
    data = request.get_json()
    purpose_id = data.get("purpose_id")

    # Update Data Fiduciary store
    record = consent_store.update_consent_status(
        user_id=user_id,
        purpose_id=purpose_id,
        status="WITHDRAWN",
        timestamp=time.time()
    )

    # Dispatch stop-processing instruction to third-party processors
    dispatch_processor_instruction(
        instruction="CEASE_PROCESSING",
        data_principal_id=user_id,
        purpose_id=purpose_id
    )

    audit_log.record(
        action="CONSENT_WITHDRAWAL",
        data_principal=user_id,
        purpose=purpose_id,
        statutory_basis="DPDP_SECTION_6_4"
    )

    return jsonify({
        "status": "success",
        "message": "Consent withdrawal processed. Processors instructed to cease processing.",
        "effective_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }), 200`,
                notes: "Limitations: This illustrative snippet demonstrates API wiring. Legally authorized processing exceptions (e.g., statutory compliance under Section 6(6)) require application-specific routing."
            },
            soc2: {
                title: "SOC 2 Change Management (CC8.1) Branch Protection",
                meta: "AICPA 2017 TSC WITH 2022 FOCUS CC8.1 & CC6.1",
                desc: "Illustrative GitHub branch protection configuration enforcing peer pull-request review, status check gating, and linear history. Note: Logical access (CC6.1) requires broader identity & provisioning evidence.",
                code: `// .github/branch-protection-policy.json (Applied via Terraform / GitHub API)
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "TrustAudit Security Gate",
      "test / unit-test-suite",
      "sast / semgrep-security-check"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": true
}`,
                notes: "What it fixes: Enforces change management controls (CC8.1). What it does not prove: Does not satisfy logical access security (CC6.1), which requires identity provisioning and quarterly access review evidence."
            },
            iso27001: {
                title: "ISO/IEC 27001 Secure Coding (A.8.28) & Vulnerability (A.8.8)",
                meta: "ISO/IEC 27001:2022 ANNEX A TECHNOLOGICAL CONTROLS",
                desc: "Illustrative input validation and dependency vulnerability patch script preventing SQL injection and outdated package exploitation.",
                code: `# Secure Coding Remediation (Python SQLAlchemy Parameterized Query)
# Bad: db.execute(f"SELECT * FROM accounts WHERE org_id = '{untrusted_org_id}'")
# Good:
from sqlalchemy import text

stmt = text("SELECT * FROM accounts WHERE org_id = :org_id AND status = :status")
results = db.session.execute(stmt, {"org_id": verified_org_id, "status": "ACTIVE"}).fetchall()

# Dependency Vulnerability Remediation (A.8.8)
# Upgrade vulnerable package identified by OSV/NVD scan:
# pip install requests>=2.31.0 urllib3>=2.0.7 --upgrade`,
                notes: "Verification: Run Semgrep SAST check and pip audit to verify zero high-severity findings remain before deployment."
            },
            gdpr: {
                title: "GDPR Documented Breach Assessment & Escalation Workflow",
                meta: "EU GDPR ARTICLES 32, 33 (72-HOUR NOTIFICATION) & 34",
                desc: "Illustrative security incident assessment and supervisory authority breach notification workflow with SLA tracking.",
                code: `def assess_and_escalate_incident(incident_data):
    # Evaluates personal data breach risk under GDPR Articles 33 & 34:
    # - Assesses confidentiality, integrity, and availability impact.
    # - If risk to rights and freedoms of natural persons is likely,
    #   initiates supervisory authority notification within 72 hours.
    t_detected = incident_data["detected_at"]
    risk_level = evaluate_risk_to_data_subjects(incident_data)

    if risk_level in ("MEDIUM", "HIGH"):
        supervisory_notification_deadline = t_detected + (72 * 3600)
        task = remediation_center.create_task(
            title="DPO Supervisory Authority Notification (GDPR Art 33)",
            severity="CRITICAL",
            deadline=supervisory_notification_deadline,
            affected_category=incident_data["categories"]
        )
        alert_security_lead(task)
    return risk_level`,
                notes: "Limitations: Whether a breach is reportable requires formal assessment by an appointed DPO or external legal counsel."
            }
        };

        function openRemediationModal(type) {
            const data = REMEDIATION_PLAYBOOKS[type] || REMEDIATION_PLAYBOOKS.dpdp;
            document.getElementById('rem-modal-title').innerText = data.title;
            document.getElementById('rem-modal-meta').innerText = data.meta;
            document.getElementById('rem-modal-desc').innerText = data.desc;
            document.getElementById('rem-modal-code').innerText = data.code;
            document.getElementById('rem-modal-notes').innerText = data.notes;
            document.getElementById('remediation-modal').style.display = 'flex';
        }

        function closeRemediationModal() {
            document.getElementById('remediation-modal').style.display = 'none';
        }

        // 12. Evidence Sample JSON Modal
        const SAMPLE_EVIDENCE = {
            "DPDP-SEC-06": {
                "evidence_id": "EV-DPDP-2026-06",
                "framework": "DPDP:2023",
                "control_id": "DPDP-SEC-06(9)",
                "control_name": "Consent Architecture & Revocation Endpoint",
                "verification_method": "AST_API_ROUTE_INSPECTION",
                "asset_inspected": "https://github.com/example/saas-backend",
                "findings_count": 0,
                "status": "PASS",
                "evidence_payload": {
                    "consent_withdrawal_route": "/api/v1/consent/withdraw",
                    "http_method": "POST",
                    "processor_notification_webhook": "configured",
                    "audit_logging_enabled": true
                },
                "watermark": "ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD"
            },
            "DPDP-SEC-08-5": {
                "evidence_id": "EV-DPDP-2026-08-5",
                "framework": "DPDP:2023",
                "control_id": "DPDP-SEC-08(5)",
                "control_name": "Reasonable Security Safeguards & Redaction",
                "verification_method": "SECRETS_ENTROPY_SCAN",
                "asset_inspected": "https://github.com/example/saas-backend",
                "findings_count": 0,
                "status": "PASS",
                "evidence_payload": {
                    "high_entropy_secrets_found": 0,
                    "masked_tokens_logged": true,
                    "hardcoded_credentials": "none"
                },
                "watermark": "ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD"
            },
            "SOC2-CC8.1": {
                "evidence_id": "EV-SOC2-2026-CC8.1",
                "framework": "SOC2:2017/2022",
                "control_id": "SOC2-CC8.1",
                "control_name": "Change Management & Branch Protection",
                "verification_method": "GITHUB_API_CONFIGURATION_AUDIT",
                "asset_inspected": "repo:default_branch",
                "findings_count": 0,
                "status": "PASS",
                "evidence_payload": {
                    "branch": "main",
                    "required_approving_reviews": 1,
                    "strict_status_checks": ["TrustAudit Security Gate"],
                    "force_push_blocked": true
                },
                "watermark": "ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD"
            },
            "ISO-A.8.28": {
                "evidence_id": "EV-ISO-2026-A.8.28",
                "framework": "ISO/IEC 27001:2022",
                "control_id": "A.8.28",
                "control_name": "Secure Coding & SAST Verification",
                "verification_method": "SEMGREP_AST_SCAN",
                "asset_inspected": "src/app.py",
                "findings_count": 0,
                "status": "PASS",
                "evidence_payload": {
                    "rules_evaluated": 184,
                    "sql_injection_flaws": 0,
                    "xss_patterns": 0,
                    "insecure_deserialization": 0
                },
                "watermark": "ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD"
            },
            "GDPR-ART-32": {
                "evidence_id": "EV-GDPR-2026-32",
                "framework": "GDPR:2016",
                "control_id": "Article 32",
                "control_name": "Security of Processing",
                "verification_method": "TLS_CIPHER_AUDIT",
                "asset_inspected": "https://mcp-scanner.onrender.com",
                "findings_count": 0,
                "status": "PASS",
                "evidence_payload": {
                    "tls_version": "TLSv1.3",
                    "hsts_max_age": 31536000,
                    "encryption_cipher": "TLS_AES_256_GCM_SHA384"
                },
                "watermark": "ILLUSTRATIVE SAMPLE — NOT A LIVE CUSTOMER RECORD"
            }
        };

        let currentEvidenceJson = "";
        function openEvidenceModal(controlId) {
            const data = SAMPLE_EVIDENCE[controlId] || SAMPLE_EVIDENCE["DPDP-SEC-06"];
            currentEvidenceJson = JSON.stringify(data, null, 2);
            document.getElementById('evidence-modal-code').innerText = currentEvidenceJson;
            document.getElementById('evidence-copy-feedback').innerText = "";
            document.getElementById('evidence-modal').style.display = 'flex';
        }

        function closeEvidenceModal() {
            document.getElementById('evidence-modal').style.display = 'none';
        }

        function copyEvidenceJson() {
            if (navigator.clipboard && currentEvidenceJson) {
                navigator.clipboard.writeText(currentEvidenceJson).then(() => {
                    document.getElementById('evidence-copy-feedback').innerText = "✓ Copied to clipboard!";
                });
            }
        }

        // 13. Trust Pack Modal Handlers
        function openTrustPackModal() {
            document.getElementById('trust-pack-modal').style.display = 'flex';
        }

        function closeTrustPackModal() {
            document.getElementById('trust-pack-modal').style.display = 'none';
        }

        function handleTrustPackDownload(e) {
            e.preventDefault();
            const form = document.getElementById('pack-download-form');
            const checkboxes = form.querySelectorAll('input[name="doc"]:checked');
            const selectedDocs = Array.from(checkboxes).map(c => c.value);
            const formatRadio = form.querySelector('input[name="format"]:checked');
            const fmt = formatRadio ? formatRadio.value : 'zip';

            if (selectedDocs.length === 0) {
                alert('Please select at least one document to include in your Trust Pack.');
                return;
            }

            const docsParam = selectedDocs.join(',');
            const url = `/api/public/trust-pack/download?docs=${encodeURIComponent(docsParam)}&format=${fmt}`;
            window.location.href = url;
            closeTrustPackModal();
        }

        // 14. Grievance Modal Handlers
        function openGrievanceModal() {
            document.getElementById('grievance-modal').style.display = 'flex';
        }

        function closeGrievanceModal() {
            document.getElementById('grievance-modal').style.display = 'none';
        }

        function handleGrievanceSubmit(e) {
            e.preventDefault();
            const name = document.getElementById('grv-name').value;
            const email = document.getElementById('grv-email').value;
            const category = document.getElementById('grv-category').value;
            const description = document.getElementById('grv-desc').value;

            fetch('/api/public/grievance/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, category, description })
            })
            .then(res => res.json())
            .then(data => {
                alert(data.message || 'Grievance recorded successfully.');
                closeGrievanceModal();
            })
            .catch(err => {
                alert('Submission error: ' + err);
            });
        }

        function closeModalOnOverlay(e, modalId) {
            if (e.target && e.target.id === modalId) {
                document.getElementById(modalId).style.display = 'none';
            }
        }

        // Close modals on Escape key
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeRemediationModal();
                closeEvidenceModal();
                closeTrustPackModal();
                closeGrievanceModal();
            }
        });
    </script>
</body>
</html>
"""
