"""
TrustAudit Interactive Enterprise Security & Compliance Trust Centre Template.

Design Standard:
- Enterprise command-centre visual identity (comparable to Vanta, Wiz, Aikido, Linear)
- Dark technical theme (#070b12, #0f172a, #1e293b, #0284c7, #38bdf8, #10b981)
- Interactive Live Control Explorer (Accordion cards, framework filters, illustrative JSON previews, safe remediation diffs)
- Interactive Client-Side Secret Redaction Sandbox (zero network transmission, live detection -> masking -> safe preview)
- Interactive Enterprise Security Questionnaire Simulator (sequential auto-fill, evidence links, progress tracking)
- Interactive Data Flow Architecture Diagram (clickable nodes with stage inspection panels)
- Live CISA KEV Telemetry Card (powered by /api/public/trust-status)
- Enterprise Trust Pack Builder (interactive drawer, document selection, ZIP / Markdown downloads)
- Sticky Glassmorphism Navigation with real-time scroll progress and section tracking
- Responsive Bento Grid and cursor-following spotlight (disabled on touch devices)
- 100% accessible, semantic, keyboard-navigable, and respects prefers-reduced-motion
"""

TRUST_CENTRE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit Security, Compliance & Trust Center</title>
    <meta name="description" content="Explore how TrustAudit handles source code, detects security vulnerabilities, maps compliance frameworks (DPDP, SOC 2, ISO 27001, GDPR), and enforces multi-tenant boundaries.">
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
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;
            --radius-xl: 18px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            overflow-x: hidden;
            position: relative;
        }

        /* Ambient subtle radial background */
        .ambient-bg {
            position: fixed;
            top: 0; left: 0; right: 0; height: 600px;
            background: radial-gradient(circle at 50% -10%, rgba(2, 132, 199, 0.12) 0%, rgba(99, 102, 241, 0.04) 40%, transparent 70%);
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 24px;
            position: relative;
            z-index: 1;
        }

        /* Top Progress Bar */
        #scroll-progress {
            position: fixed;
            top: 0; left: 0; height: 3px;
            background: linear-gradient(90deg, #0284c7, #38bdf8, #6366f1);
            width: 0%;
            z-index: 100;
            transition: width 0.1s linear;
        }

        /* Sticky Glass Navigation */
        .navbar {
            position: sticky;
            top: 0;
            z-index: 90;
            background: rgba(7, 11, 18, 0.85);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
            padding: 14px 0;
            transition: border-color 0.2s;
        }
        .nav-inner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            font-size: 17px;
            color: #fff;
            text-decoration: none;
            letter-spacing: -0.01em;
        }
        .brand-icon {
            width: 32px;
            height: 32px;
            border-radius: 8px;
            background: linear-gradient(135deg, #0284c7, #6366f1);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            box-shadow: 0 0 12px rgba(2, 132, 199, 0.3);
        }
        .nav-menu {
            display: flex;
            align-items: center;
            gap: 6px;
            list-style: none;
        }
        .nav-item a {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 13.5px;
            font-weight: 500;
            padding: 6px 12px;
            border-radius: var(--radius-sm);
            transition: all 0.15s ease;
        }
        .nav-item a:hover {
            color: #fff;
            background: rgba(255, 255, 255, 0.05);
        }
        .nav-item a.active {
            color: var(--primary-light);
            background: rgba(2, 132, 199, 0.12);
            font-weight: 600;
        }
        .nav-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .btn-pack-nav {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border);
            color: #fff;
            padding: 7px 14px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn-pack-nav:hover {
            background: rgba(255, 255, 255, 0.12);
            border-color: rgba(255, 255, 255, 0.2);
        }
        .btn-dashboard-nav {
            background: var(--primary);
            color: #fff;
            padding: 7px 16px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            font-weight: 600;
            text-decoration: none;
            transition: background 0.15s ease;
        }
        .btn-dashboard-nav:hover { background: #0369a1; }

        /* Hero Header */
        .hero {
            padding: 70px 0 40px;
            text-align: center;
        }
        .eyebrow-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--primary-glow);
            color: var(--primary-light);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 5px 14px;
            border-radius: 9999px;
            font-size: 12.5px;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            margin-bottom: 22px;
        }
        .eyebrow-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
        }
        .hero h1 {
            font-size: 48px;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.15;
            margin: 0 0 18px;
            background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .hero p.subtitle {
            font-size: 18px;
            color: var(--text-muted);
            max-width: 800px;
            margin: 0 auto 30px;
            line-height: 1.6;
        }
        .hero-ctas {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            margin-bottom: 34px;
            flex-wrap: wrap;
        }
        .btn-primary-lg {
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: #fff;
            padding: 12px 24px;
            border-radius: var(--radius-md);
            font-size: 15px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 18px rgba(2, 132, 199, 0.25);
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .btn-primary-lg:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 24px rgba(2, 132, 199, 0.35);
        }
        .btn-secondary-lg {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: #fff;
            padding: 12px 24px;
            border-radius: var(--radius-md);
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: border-color 0.15s, background 0.15s;
        }
        .btn-secondary-lg:hover {
            border-color: rgba(255, 255, 255, 0.25);
            background: var(--bg-elevated);
        }

        /* Compact Verification Row */
        .verification-bar {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 14px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 13px;
            color: var(--text-dim);
            flex-wrap: wrap;
            gap: 16px;
        }
        .vbar-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .vbar-item strong { color: var(--text-main); font-weight: 600; }
        .vbar-tag {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Section Titles */
        .section-header {
            margin: 70px 0 26px;
        }
        .section-header .section-tag {
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--primary-light);
            letter-spacing: 0.08em;
            margin-bottom: 6px;
            display: block;
        }
        .section-header h2 {
            font-size: 30px;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin: 0 0 10px;
            color: #fff;
        }
        .section-header p {
            color: var(--text-muted);
            font-size: 15px;
            max-width: 820px;
            margin: 0;
        }

        /* Bento Grid */
        .bento-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        .bento-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 24px;
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: border-color 0.2s, transform 0.2s;
        }
        .bento-card:hover {
            border-color: var(--border-hover);
        }
        .bento-col-2 { grid-column: span 2; }
        .bento-card h3 {
            font-size: 17px;
            font-weight: 700;
            margin: 12px 0 6px;
            color: #fff;
        }
        .bento-card p {
            font-size: 13.5px;
            color: var(--text-muted);
            line-height: 1.55;
            margin-bottom: 18px;
        }
        .bento-icon {
            width: 38px;
            height: 38px;
            border-radius: var(--radius-md);
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .bento-footer {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            font-size: 12px;
        }

        /* Status Badge Styles */
        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 9px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
        }
        .status-verified {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .status-provider {
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .status-evidence {
            background: rgba(129, 140, 248, 0.12);
            color: #a5b4fc;
            border: 1px solid rgba(129, 140, 248, 0.3);
        }
        .status-self {
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .status-readiness {
            background: rgba(96, 165, 250, 0.12);
            color: #93c5fd;
            border: 1px solid rgba(96, 165, 250, 0.3);
        }
        .status-roadmap {
            background: rgba(148, 163, 184, 0.12);
            color: #cbd5e1;
            border: 1px solid rgba(148, 163, 184, 0.3);
        }

        /* Live Control Explorer */
        .explorer-controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 22px;
            flex-wrap: wrap;
        }
        .filter-group {
            display: flex;
            align-items: center;
            gap: 6px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            padding: 4px;
            border-radius: var(--radius-md);
            flex-wrap: wrap;
        }
        .filter-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 6px 14px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .filter-btn:hover { color: #fff; }
        .filter-btn.active {
            background: var(--primary);
            color: #fff;
            box-shadow: 0 2px 8px rgba(2, 132, 199, 0.3);
        }
        .search-box {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 8px 14px;
            color: #fff;
            font-size: 13.5px;
            width: 260px;
            outline: none;
            transition: border-color 0.15s;
        }
        .search-box:focus { border-color: var(--primary-light); }

        /* Control Accordion Card */
        .control-accordion {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .accordion-item {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            overflow: hidden;
            transition: border-color 0.15s;
        }
        .accordion-item:hover { border-color: rgba(255, 255, 255, 0.18); }
        .accordion-header {
            padding: 18px 22px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
            gap: 16px;
        }
        .accordion-title-wrap {
            display: flex;
            align-items: center;
            gap: 14px;
            flex-wrap: wrap;
        }
        .ctrl-id-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            font-weight: 700;
            color: var(--primary-light);
            background: rgba(2, 132, 199, 0.12);
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }
        .ctrl-name {
            font-size: 15px;
            font-weight: 700;
            color: #fff;
        }
        .ctrl-chevron {
            font-size: 14px;
            color: var(--text-dim);
            transition: transform 0.2s ease;
        }
        .accordion-item.open .ctrl-chevron {
            transform: rotate(180deg);
        }
        .accordion-content {
            display: none;
            padding: 0 22px 22px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            background: var(--bg-elevated);
        }
        .accordion-item.open .accordion-content {
            display: block;
        }
        .ctrl-details-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 18px;
            margin: 18px 0;
        }
        .detail-block h4 {
            font-size: 12.5px;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-dim);
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }
        .detail-block p {
            font-size: 13.5px;
            color: var(--text-muted);
            margin: 0;
            line-height: 1.55;
        }

        /* JSON Sample Box */
        .code-box-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #090e17;
            padding: 8px 14px;
            border-radius: var(--radius-sm) var(--radius-sm) 0 0;
            font-size: 12px;
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-dim);
            border: 1px solid var(--border);
            border-bottom: none;
        }
        .code-pre {
            background: #070a10;
            border: 1px solid var(--border);
            border-radius: 0 0 var(--radius-sm) var(--radius-sm);
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: #e2e8f0;
            overflow-x: auto;
            margin: 0 0 16px;
            line-height: 1.5;
        }
        .btn-copy-code {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #cbd5e1;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
        }
        .btn-copy-code:hover { background: rgba(255, 255, 255, 0.16); }

        /* Interactive Remediation Drawer / Modal */
        .drawer-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(8px);
            z-index: 200;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .drawer-overlay.open { display: flex; }
        .drawer-modal {
            background: var(--bg-surface);
            border: 1px solid var(--border-hover);
            border-radius: var(--radius-xl);
            width: 100%;
            max-width: 680px;
            max-height: 85vh;
            overflow-y: auto;
            padding: 30px;
            position: relative;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
        }
        .drawer-close {
            position: absolute;
            top: 20px; right: 20px;
            background: rgba(255, 255, 255, 0.08);
            border: none;
            color: #fff;
            width: 32px; height: 32px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Secret Redaction Sandbox */
        .sandbox-box {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 28px;
            margin-top: 20px;
        }
        .sandbox-input-row {
            display: flex;
            gap: 12px;
            margin: 18px 0;
        }
        .sandbox-input {
            flex: 1;
            background: #090e17;
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 12px 16px;
            color: #fff;
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            outline: none;
        }
        .sandbox-input:focus { border-color: var(--primary-light); }
        .btn-test-mask {
            background: var(--primary);
            color: #fff;
            border: none;
            padding: 12px 20px;
            border-radius: var(--radius-md);
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            white-space: nowrap;
            transition: background 0.15s;
        }
        .btn-test-mask:hover { background: #0369a1; }
        .sandbox-pipeline {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            margin: 18px 0;
            gap: 12px;
        }
        .pipe-step {
            text-align: center;
            flex: 1;
        }
        .pipe-step-num {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--primary-light);
            font-weight: 700;
            text-transform: uppercase;
        }
        .pipe-step-name {
            font-size: 13.5px;
            font-weight: 600;
            color: #fff;
            margin-top: 2px;
        }
        .pipe-arrow {
            color: var(--text-dim);
            font-size: 16px;
        }
        .sandbox-result-box {
            background: #090e17;
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: var(--radius-md);
            padding: 16px;
            display: none;
        }
        .sandbox-result-box.active { display: block; }

        /* Questionnaire Simulator */
        .simulator-box {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 28px;
            margin-top: 20px;
        }
        .sim-question-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 18px;
            margin-bottom: 14px;
        }
        .sim-q-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .sim-q-title {
            font-size: 14.5px;
            font-weight: 700;
            color: #fff;
        }
        .sim-answer-text {
            font-size: 13.5px;
            color: var(--text-muted);
            line-height: 1.5;
            min-height: 22px;
        }
        .sim-evidence-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        .sim-evidence-badge {
            background: rgba(99, 102, 241, 0.15);
            color: #a5b4fc;
            border: 1px solid rgba(99, 102, 241, 0.3);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11.5px;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Interactive Data Flow Diagram */
        .diagram-container {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-xl);
            padding: 30px;
            margin-top: 20px;
        }
        .flow-nodes-wrapper {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            overflow-x: auto;
            padding: 16px 0 24px;
        }
        .flow-node {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 14px 18px;
            min-width: 150px;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
            position: relative;
        }
        .flow-node:hover {
            border-color: var(--primary-light);
            transform: translateY(-2px);
        }
        .flow-node.active {
            border-color: var(--primary-light);
            background: rgba(2, 132, 199, 0.15);
            box-shadow: 0 0 16px rgba(2, 132, 199, 0.25);
        }
        .flow-node-icon { font-size: 20px; margin-bottom: 6px; }
        .flow-node-title {
            font-size: 12.5px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.01em;
        }
        .flow-node-sub {
            font-size: 10.5px;
            color: var(--text-dim);
            font-family: 'JetBrains Mono', monospace;
            margin-top: 2px;
        }
        .flow-arrow-conn {
            color: var(--text-dim);
            font-size: 16px;
            font-weight: 700;
        }
        .node-inspector {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 22px;
            margin-top: 14px;
        }
        .node-inspector h4 {
            font-size: 16px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .inspector-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-top: 14px;
        }

        /* Live CISA Telemetry Card */
        .telemetry-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-xl);
            padding: 30px;
            margin-top: 20px;
        }
        .telemetry-stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 24px 0;
        }
        .tstat-box {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 18px;
        }
        .tstat-num {
            font-family: 'JetBrains Mono', monospace;
            font-size: 28px;
            font-weight: 800;
            color: #fff;
            line-height: 1.1;
        }
        .tstat-lbl {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.05em;
            margin-top: 6px;
        }

        /* Trust Pack Download Modal */
        .pack-item-row {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        .pack-item-row:last-child { border-bottom: none; }
        .pack-check {
            width: 18px;
            height: 18px;
            accent-color: var(--primary);
            cursor: pointer;
            margin-top: 2px;
        }

        /* Footer */
        .footer {
            margin-top: 90px;
            padding: 50px 0 60px;
            border-top: 1px solid var(--border);
            font-size: 13.5px;
            color: var(--text-dim);
        }
        .footer-inner {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 30px;
            flex-wrap: wrap;
        }
        .footer-left { max-width: 700px; }
        .footer-left p { margin-bottom: 12px; line-height: 1.6; }
        .footer-links {
            display: flex;
            gap: 22px;
            flex-wrap: wrap;
        }
        .footer-links a {
            color: var(--text-muted);
            text-decoration: none;
            transition: color 0.15s;
        }
        .footer-links a:hover { color: #fff; }

        /* Responsive Breakpoints */
        @media (max-width: 1024px) {
            .bento-grid { grid-template-columns: repeat(2, 1fr); }
            .telemetry-stats-row { grid-template-columns: repeat(2, 1fr); }
            .inspector-grid { grid-template-columns: 1fr; }
            .ctrl-details-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .hero h1 { font-size: 34px; }
            .bento-grid { grid-template-columns: 1fr; }
            .bento-col-2 { grid-column: span 1; }
            .telemetry-stats-row { grid-template-columns: 1fr; }
            .nav-menu { display: none; }
            .sandbox-pipeline { flex-direction: column; }
            .pipe-arrow { transform: rotate(90deg); }
        }

        /* Accessibility: Reduced Motion */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }
    </style>
</head>
<body>

    <div class="ambient-bg"></div>
    <div id="scroll-progress"></div>

    <!-- Navigation -->
    <nav class="navbar" id="top-navbar">
        <div class="container nav-inner">
            <a href="/trust" class="brand">
                <div class="brand-icon">🛡️</div>
                TrustAudit
            </a>
            <ul class="nav-menu">
                <li class="nav-item"><a href="#overview" class="active">Overview</a></li>
                <li class="nav-item"><a href="#frameworks">Framework Explorer</a></li>
                <li class="nav-item"><a href="#threat-intel">Threat Intel</a></li>
                <li class="nav-item"><a href="#security-architecture">Security Architecture</a></li>
                <li class="nav-item"><a href="#data-transparency">Data Transparency</a></li>
                <li class="nav-item"><a href="#demos">Interactive Demos</a></li>
                <li class="nav-item"><a href="#contact">Disclosure</a></li>
            </ul>
            <div class="nav-actions">
                <button class="btn-pack-nav" onclick="openTrustPackModal()">📦 Trust Pack</button>
                <a href="/dashboard" class="btn-dashboard-nav">Console &rarr;</a>
            </div>
        </div>
    </nav>

    <div class="container">

        <!-- HERO SECTION -->
        <header class="hero" id="overview">
            <div class="eyebrow-pill">
                <span class="eyebrow-dot"></span>
                TRUSTAUDIT SECURITY & COMPLIANCE
            </div>
            <h1>Security You Can Inspect.<br>Compliance You Can Understand.</h1>
            <p class="subtitle">
                Explore how TrustAudit handles source code, detects security risks, maps compliance requirements 
                and protects customer information.
            </p>
            <div class="hero-ctas">
                <a href="#security-architecture" class="btn-primary-lg">
                    <span>Explore Security Architecture</span> &darr;
                </a>
                <button class="btn-secondary-lg" onclick="openTrustPackModal()">
                    <span>Download Trust Pack</span> 📥
                </button>
            </div>

            <!-- Compact Information Row -->
            <div class="verification-bar">
                <div class="vbar-item">
                    <span>📅 Last Reviewed:</span>
                    <strong>18 November 2026</strong>
                </div>
                <div class="vbar-item">
                    <span>🏛️ Frameworks & Mappings:</span>
                    <strong>DPDP 2023, SOC 2, ISO 27001, GDPR</strong>
                </div>
                <div class="vbar-item">
                    <span>🛡️ Latest Negative Isolation Test:</span>
                    <span class="vbar-tag">PASSED (Suite v2.4)</span>
                </div>
                <div class="vbar-item">
                    <span>📧 Disclosure Contact:</span>
                    <a href="mailto:security@trustaudit.io" style="color: var(--primary-light); text-decoration: none; font-weight: 600;">security@trustaudit.io</a>
                </div>
            </div>
        </header>

        <!-- PHASE 4: SECURITY POSTURE BENTO GRID -->
        <section id="security-architecture">
            <div class="section-header">
                <span class="section-tag">Platform Posture</span>
                <h2>Verified Security Architecture</h2>
                <p>
                    Evidence-based breakdown of TrustAudit technical security controls. Every claim is supported by actual 
                    code implementations, provider attestations, or automated regression tests.
                </p>
            </div>

            <div class="bento-grid">
                <!-- Card 1 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">🔐</div>
                        <h3>Encryption in Transit</h3>
                        <p>All incoming and egress web traffic is strictly redirected to HTTPS with TLS 1.3/1.2 enforced across public API and dashboard endpoints.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">TLS 1.3 / HSTS</span>
                    </div>
                </div>

                <!-- Card 2 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">🗄️</div>
                        <h3>Encryption at Rest</h3>
                        <p>Persistent storage volumes are encrypted with AES-256 at the hosting provider storage-volume layer (Render / AWS). Evidence Vault files are fingerprinted with SHA-256 hashes.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-provider">PROVIDER-REPORTED</span>
                        <span style="color: var(--text-dim); font-size: 11px;">AES-256 Volume</span>
                    </div>
                </div>

                <!-- Card 3 -->
                <div class="bento-card bento-col-2">
                    <div>
                        <div class="bento-icon">⚡</div>
                        <h3>Ephemeral Repository Processing</h3>
                        <p>Git repositories are cloned into isolated, sandboxed temporary directories. Code is parsed for AST structures and security heuristics, and is <strong>immediately wiped from disk upon scan completion</strong> via <code>shutil.rmtree</code>. Full source code repositories are never permanently retained.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">0-Day Code Retention</span>
                    </div>
                </div>

                <!-- Card 4 -->
                <div class="bento-card bento-col-2">
                    <div>
                        <div class="bento-icon">👁️</div>
                        <h3>Secret Redaction & Preview Masking</h3>
                        <p>Multi-layered regex and Shannon entropy credential scanning inspects code for exposed tokens. Detected credentials are automatically masked (e.g. <code>prefix...[REDACTED]...suffix</code>) before rendering in findings, database stores, or reports. Gitleaks CLI outputs are sanitized prior to memory persistence.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">Regex + Shannon Entropy</span>
                    </div>
                </div>

                <!-- Card 5 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">🏢</div>
                        <h3>Tenant Access Isolation</h3>
                        <p>Customer data, scan results, evidence documents, and projects are strictly partitioned by organization IDs and authorized via server-side session bearer tokens.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">Negative Suite Passed</span>
                    </div>
                </div>

                <!-- Card 6 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">🚨</div>
                        <h3>Vulnerability Intelligence</h3>
                        <p>Continuous synchronization with CISA Known Exploited Vulnerabilities (KEV) and Google OSV.dev catalogs to correlate third-party dependencies against in-the-wild exploitation.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-provider">OPERATIONAL</span>
                        <span style="color: var(--text-dim); font-size: 11px;">CISA KEV / OSV.dev</span>
                    </div>
                </div>

                <!-- Card 7 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">🔑</div>
                        <h3>Authentication & Hashing</h3>
                        <p>User passwords are protected using PBKDF2-HMAC-SHA256 with 100,000 iterations and per-user 16-byte random salts. Multi-factor authentication (MFA) is on our product roadmap.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">PBKDF2-HMAC-SHA256</span>
                    </div>
                </div>

                <!-- Card 8 -->
                <div class="bento-card">
                    <div>
                        <div class="bento-icon">📁</div>
                        <h3>Evidence Vault Integrity</h3>
                        <p>Customer audit documents are stored in tenant-isolated directories with immutable SHA-256 cryptographic fingerprints, control linkages, and annual review cycle tracking.</p>
                    </div>
                    <div class="bento-footer">
                        <span class="status-pill status-verified">VERIFIED BY TEST</span>
                        <span style="color: var(--text-dim); font-size: 11px;">SHA-256 Hashing</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- PHASE 5 & 6: INTERACTIVE LIVE CONTROL EXPLORER -->
        <section id="frameworks">
            <div class="section-header">
                <span class="section-tag">Interactive GRC Explorer</span>
                <h2>Framework Explorer & Control Mappings</h2>
                <p>
                    Inspect how TrustAudit checks technical security controls against statutory regulations (including India's Digital Personal Data Protection Act, 2023 and Digital Personal Data Protection Rules, 2025) and international standards (SOC 2, ISO/IEC 27001:2022, GDPR). 
                    Filter by framework, view evidence previews, and inspect remediation guidance.
                </p>
            </div>

            <div class="explorer-controls">
                <div class="filter-group">
                    <button class="filter-btn active" onclick="filterFramework('ALL', this)">All Frameworks</button>
                    <button class="filter-btn" onclick="filterFramework('DPDP', this)">DPDP Act 2023</button>
                    <button class="filter-btn" onclick="filterFramework('SOC2', this)">SOC 2 Criteria</button>
                    <button class="filter-btn" onclick="filterFramework('ISO27001', this)">ISO/IEC 27001:2022</button>
                    <button class="filter-btn" onclick="filterFramework('GDPR', this)">EU GDPR</button>
                </div>
                <input type="text" class="search-box" id="ctrl-search" placeholder="Search controls (e.g. CC6.1, A.8.8)..." onkeyup="searchControls(this.value)">
            </div>

            <!-- Expandable Control Cards Container -->
            <div class="control-accordion" id="control-accordion-list">
                <!-- DPDP Control 1: Sec 6(9) -->
                <div class="accordion-item" data-framework="DPDP" data-id="DPDP-SEC-06">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">DPDP Section 6(9) & Rule 4</span>
                            <span class="ctrl-name">Consent Architecture & Statutory Consent Manager Integration</span>
                            <span class="status-pill status-provider">Already in force (13 Nov 2026)</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>Statutory Requirement & Official Source</h4>
                                <p>DPDP Act 2023 Section 6(9) read with DPDP Rules 2025 Rule 4. Data Principals may give, manage, review, or withdraw consent through registered Consent Managers accountable to the DPBI.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Evaluates application consent token schemas and self-service consent withdrawal workflows. TrustAudit does <em>not</em> self-attest as a registered statutory Consent Manager.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Automated checks verify API consent withdrawal endpoints. Formal Consent Manager interoperability certification requires DPBI registration.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Assessment Classification</h4>
                                <p><span class="status-pill status-provider">Operational Readiness</span> &bull; Commenced 13 November 2026</p>
                            </div>
                        </div>

                        <!-- JSON Sample Box -->
                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "DPDP:2023",
  "control": "Section 6(9) & Rule 4",
  "assessment": "Consent withdrawal endpoint responds with HTTP 200 and revokes token",
  "source": "TrustAudit API Analyzer",
  "status": "Readiness evaluated",
  "evidence_type": "Consent revocation audit log schema",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('dpdp-sec-6')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- DPDP Control 2: Sec 8(5) -->
                <div class="accordion-item" data-framework="DPDP" data-id="DPDP-SEC-08-5">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">DPDP Section 8(5) & Rule 6</span>
                            <span class="ctrl-name">Reasonable Security Safeguards to Prevent Personal Data Breach</span>
                            <span class="status-pill status-readiness">Scheduled (13 May 2027)</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>Statutory Requirement & Official Source</h4>
                                <p>DPDP Act 2023 Section 8(5) read with DPDP Rules 2025 Rule 6. A Data Fiduciary must protect personal data in its possession or control by taking reasonable security safeguards to prevent personal data breach.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Automated secret scanning across repositories, TLS 1.3/1.2 transit encryption checks, HSTS validation, and OWASP Top 10 code security analysis.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Identifies technical vulnerabilities. Does not evaluate physical data center access security or third-party processor on-premise safeguards.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Assessment Classification</h4>
                                <p><span class="status-pill status-readiness">Readiness Assessment</span> (IT Act Section 43A baseline in force)</p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "DPDP:2023",
  "control": "Section 8(5) & Rule 6",
  "assessment": "Zero active production credentials detected in git source code",
  "source": "TrustAudit Secret Detector",
  "status": "PASS",
  "evidence_type": "Static analysis secret scan report",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('dpdp-sec-8-5')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- SOC 2: CC6.1 -->
                <div class="accordion-item" data-framework="SOC2" data-id="SOC2-CC6.1">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">SOC 2 CC6.1</span>
                            <span class="ctrl-name">Logical Access Security & Credential Management</span>
                            <span class="status-pill status-verified">Verified by Test</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>AICPA TSC Published Scope</h4>
                                <p>AICPA 2017 TSC with 2022 Points of Focus CC6.1. The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Automated secret scanning detects committed private keys, AWS tokens, and Stripe keys in repositories. Evidence Vault stores MFA configuration screenshots and quarterly access reviews.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Automated detection covers source code and git histories. Employee onboarding/offboarding workflows require customer-uploaded HR evidence.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Auditing Status</h4>
                                <p><span class="status-pill status-evidence">Readiness Evaluation</span> &bull; Formal report requires CPA examination</p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "SOC2:2017",
  "control": "CC6.1",
  "assessment": "Hardcoded credential detection across 12 source files",
  "source": "TrustAudit Secret Scanner",
  "status": "0_CRITICAL_SECRETS_FOUND",
  "evidence_type": "Repository secret audit snapshot",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('soc2-cc6-1')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- SOC 2: CC7.1 -->
                <div class="accordion-item" data-framework="SOC2" data-id="SOC2-CC7.1">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">SOC 2 CC7.1</span>
                            <span class="ctrl-name">Monitoring Configuration Changes & Vulnerability Susceptibility</span>
                            <span class="status-pill status-verified">Verified by Test</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>AICPA TSC Published Scope</h4>
                                <p>AICPA 2017 TSC with 2022 Points of Focus CC7.1. Procedures to identify (1) changes to configurations that result in new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities. (Not simply patch SLAs).</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Automated dependency SBOM scanning against CISA KEV and OSV.dev feeds. Tracks configuration changes in Dockerfiles and Terraform IaC.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Scans software packages and infrastructure manifests. Cloud runtime configuration drift (AWS IAM/EC2) requires cloud provider connector evidence.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Auditing Status</h4>
                                <p><span class="status-pill status-evidence">Readiness Evaluation</span></p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "SOC2:2017",
  "control": "CC7.1",
  "assessment": "Third-party component vulnerability tracking with CISA KEV correlation",
  "source": "TrustAudit Vulnerability Intelligence",
  "status": "PASS",
  "evidence_type": "Dependency scan result & KEV correlation",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('soc2-cc7-1')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- ISO 27001: A.8.8 -->
                <div class="accordion-item" data-framework="ISO27001" data-id="ISO-A.8.8">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">ISO/IEC 27001:2022 A.8.8</span>
                            <span class="ctrl-name">Management of Technical Vulnerabilities</span>
                            <span class="status-pill status-verified">Verified by Test</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>Official ISO/IEC 27001:2022 Scope</h4>
                                <p>ISO/IEC 27001:2022 Annex A.8.8. Information about technical vulnerabilities of systems in use shall be obtained, exposure evaluated, and appropriate measures taken to address associated risk.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Executes static code analysis (SAST) and dynamic dependency checks. Prioritizes findings using CISA KEV exploitability metrics and assigns SLA remediation tasks.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Evaluates repository dependencies and web perimeters. Does not evaluate physical server firmware or legacy OT devices.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Certification Status</h4>
                                <p><span class="status-pill status-readiness">Implementation Posture Evaluation</span> &bull; Accredited certificate requires Stage 1/2 CB audits</p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "ISO27001:2022",
  "control": "A.8.8",
  "assessment": "Technical vulnerability management across production repos",
  "source": "TrustAudit SAST Engine",
  "status": "PASS",
  "evidence_type": "Static application security testing report",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('iso-a-8-8')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- ISO 27001: A.8.20 -->
                <div class="accordion-item" data-framework="ISO27001" data-id="ISO-A.8.20">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">ISO/IEC 27001:2022 A.8.20</span>
                            <span class="ctrl-name">Network Security</span>
                            <span class="status-pill status-verified">Verified by Test</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>Official ISO/IEC 27001:2022 Scope</h4>
                                <p>ISO/IEC 27001:2022 Annex A.8.20 Network security. Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Perimeter network security scanner verifies CORS policies, security headers (CSP, HSTS), open debug ports, and network-exposed unauthenticated RPC interfaces.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Tests public web endpoints and DNS configurations. Internal private VPC subnet routing requires customer firewall architecture evidence.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Certification Status</h4>
                                <p><span class="status-pill status-readiness">Implementation Posture Evaluation</span></p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "ISO27001:2022",
  "control": "A.8.20",
  "assessment": "Network perimeter inspection: HSTS verified, CORS allowlist enforced",
  "source": "TrustAudit Perimeter Scanner",
  "status": "PASS",
  "evidence_type": "TLS & Network Header Analysis",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('iso-a-8-20')">View Remediation Example &rarr;</button>
                    </div>
                </div>

                <!-- GDPR: Art 25 & 32 -->
                <div class="accordion-item" data-framework="GDPR" data-id="GDPR-ART-32">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="accordion-title-wrap">
                            <span class="ctrl-id-badge">EU GDPR Article 32</span>
                            <span class="ctrl-name">Security of Processing & Technical Safeguards</span>
                            <span class="status-pill status-verified">Verified by Test</span>
                        </div>
                        <span class="ctrl-chevron">&#9660;</span>
                    </div>
                    <div class="accordion-content">
                        <div class="ctrl-details-grid">
                            <div class="detail-block">
                                <h4>EU GDPR Statutory Scope</h4>
                                <p>Regulation (EU) 2016/679 Article 32. The controller and processor shall implement technical and organisational measures to ensure a level of security appropriate to the risk, including encryption and ongoing confidentiality.</p>
                            </div>
                            <div class="detail-block">
                                <h4>What TrustAudit Checks</h4>
                                <p>Verifies transport encryption, access boundary configurations, tenant isolation enforcement, and hardcoded credential absence.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Coverage & Limitations</h4>
                                <p>Verifies technological security baseline. Legal basis for processing, Article 30 records, and DPA agreements require organizational compliance review.</p>
                            </div>
                            <div class="detail-block">
                                <h4>Statutory Status</h4>
                                <p><span class="status-pill status-provider">Enacted & Enforceable</span></p>
                            </div>
                        </div>

                        <div class="code-box-header">
                            <span>ILLUSTRATIVE SAMPLE &mdash; NOT A LIVE CUSTOMER RECORD</span>
                            <button class="btn-copy-code" onclick="copySnippet(this)">Copy JSON</button>
                        </div>
                        <pre class="code-pre"><code>{
  "framework": "GDPR:2016/679",
  "control": "Article 32(1)(a)",
  "assessment": "Cryptographic transport security verified across personal data ingestion points",
  "source": "TrustAudit TLS Inspector",
  "status": "PASS",
  "evidence_type": "Perimeter encryption verification report",
  "verified_at": "2026-11-18T23:55:00Z"
}</code></pre>

                        <button class="btn-pack-nav" onclick="openRemediationModal('gdpr-art-32')">View Remediation Example &rarr;</button>
                    </div>
                </div>
            </div>
        </section>

        <!-- PHASE 7, 8, 9: INTERACTIVE DEMOS & SANDBOX -->
        <section id="demos">
            <div class="section-header">
                <span class="section-tag">Interactive Demos</span>
                <h2>Interactive Security Command Demos</h2>
                <p>
                    Experience TrustAudit's core capabilities in action: test client-side secret masking, watch sample enterprise questionnaires populate, and inspect our ephemeral repository processing pipeline.
                </p>
            </div>

            <!-- Demo 1: Secret Redaction Sandbox -->
            <div class="sandbox-box">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <h3 style="color: #fff; font-size: 18px; margin-bottom: 4px;">Test Secret Redaction Sandbox</h3>
                        <p style="color: var(--text-muted); font-size: 13.5px; margin: 0;">
                            Paste a synthetic example credential and see how a masking rule transforms sensitive-looking text before it is displayed in findings.
                        </p>
                    </div>
                    <span class="status-pill status-provider">100% Client-Side &bull; Zero Network Transmission</span>
                </div>

                <div class="sandbox-input-row">
                    <input type="text" class="sandbox-input" id="sandbox-input-val" placeholder="sk-test-example-123456789" value="sk-test-example-123456789">
                    <button class="btn-test-mask" id="btn-run-mask" onclick="runMaskingDemo()">Test Masking</button>
                    <button class="btn-pack-nav" onclick="resetMaskingDemo()">Reset</button>
                </div>

                <div class="sandbox-pipeline">
                    <div class="pipe-step">
                        <div class="pipe-step-num">Step 1</div>
                        <div class="pipe-step-name">Pattern Detection</div>
                    </div>
                    <div class="pipe-arrow">&rarr;</div>
                    <div class="pipe-step">
                        <div class="pipe-step-num">Step 2</div>
                        <div class="pipe-step-name">Entropy & Masking</div>
                    </div>
                    <div class="pipe-arrow">&rarr;</div>
                    <div class="pipe-step">
                        <div class="pipe-step-num">Step 3</div>
                        <div class="pipe-step-name">Safe Preview Output</div>
                    </div>
                </div>

                <div class="sandbox-result-box active" id="sandbox-result">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 12px; color: var(--text-dim);">
                        <span>OUTPUT COMPARISON (PROCESSED IN YOUR BROWSER)</span>
                        <span style="color: #34d399; font-weight: 600;">✓ MASKING SUCCESSFUL</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.6;">
                        <div style="color: #94a3b8;">Original: <span id="res-orig" style="color: #fca5a5;">sk-test-example-123456789</span></div>
                        <div style="color: #94a3b8;">Masked:   <strong id="res-masked" style="color: #34d399;">sk-t...[REDACTED]...6789</strong></div>
                    </div>
                    <p style="font-size: 12px; color: var(--text-dim); margin-top: 10px;">
                        <strong>Explanation:</strong> Strings matching known API key patterns or exceeding Shannon entropy thresholds are masked retaining only 4 prefix and 4 suffix characters for developer reference. Raw tokens are never logged or exposed in UI views.
                    </p>
                </div>

                <div style="font-size: 12px; color: var(--text-dim); margin-top: 14px;">
                    🔒 <strong>CLIENT-SIDE DEMONSTRATION &mdash; USE SYNTHETIC CREDENTIALS ONLY.</strong> Input is executed locally via browser JavaScript and never transmitted to our backend or any external API.
                </div>
            </div>

            <!-- Demo 2: Enterprise Questionnaire Simulator -->
            <div class="simulator-box">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 18px;">
                    <div>
                        <h3 style="color: #fff; font-size: 18px; margin-bottom: 4px;">Enterprise Security Questionnaire Simulator</h3>
                        <p style="color: var(--text-muted); font-size: 13.5px; margin: 0;">
                            See how TrustAudit organizes verified technical evidence for customer vendor risk questionnaires.
                        </p>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn-test-mask" onclick="runQuestionnaireSimulator()">Auto-Fill Demo Evidence</button>
                        <button class="btn-pack-nav" onclick="resetQuestionnaireSimulator()">Reset</button>
                    </div>
                </div>

                <div id="sim-questions-container">
                    <!-- Q1 -->
                    <div class="sim-question-card" id="sim-q-1">
                        <div class="sim-q-header">
                            <span class="sim-q-title">1. How do you manage access to source code and developer permissions?</span>
                            <span class="status-pill status-roadmap" id="sim-status-1">Not Filled</span>
                        </div>
                        <div class="sim-answer-text" id="sim-ans-1">Click 'Auto-Fill Demo Evidence' to populate verified response.</div>
                        <div class="sim-evidence-row" id="sim-ev-1" style="display: none;">
                            <span class="sim-evidence-badge">SAMPLE EVIDENCE: GitHub_Branch_Protection_Rules.json</span>
                            <span class="sim-evidence-badge">CONTROL: SOC2-CC6.1</span>
                        </div>
                    </div>

                    <!-- Q2 -->
                    <div class="sim-question-card" id="sim-q-2">
                        <div class="sim-q-header">
                            <span class="sim-q-title">2. How do you identify and remediate vulnerable third-party dependencies?</span>
                            <span class="status-pill status-roadmap" id="sim-status-2">Not Filled</span>
                        </div>
                        <div class="sim-answer-text" id="sim-ans-2">Click 'Auto-Fill Demo Evidence' to populate verified response.</div>
                        <div class="sim-evidence-row" id="sim-ev-2" style="display: none;">
                            <span class="sim-evidence-badge">SAMPLE EVIDENCE: OSV_SBOM_Scan_Report.json</span>
                            <span class="sim-evidence-badge">CONTROL: ISO-A.8.8</span>
                        </div>
                    </div>

                    <!-- Q3 -->
                    <div class="sim-question-card" id="sim-q-3">
                        <div class="sim-q-header">
                            <span class="sim-q-title">3. How do you handle security findings and track remediation SLAs?</span>
                            <span class="status-pill status-roadmap" id="sim-status-3">Not Filled</span>
                        </div>
                        <div class="sim-answer-text" id="sim-ans-3">Click 'Auto-Fill Demo Evidence' to populate verified response.</div>
                        <div class="sim-evidence-row" id="sim-ev-3" style="display: none;">
                            <span class="sim-evidence-badge">SAMPLE EVIDENCE: SLA_Remediation_Log.pdf</span>
                            <span class="sim-evidence-badge">CONTROL: DPDP-SEC-08-5</span>
                        </div>
                    </div>
                </div>

                <div style="font-size: 12px; color: var(--text-dim); margin-top: 14px;">
                    ℹ️ <strong>ILLUSTRATIVE CONTROL MAPPING &mdash; SAMPLE DATA ONLY.</strong> Inside customer dashboards, real evidence is scoped to authenticated organizations.
                </div>
            </div>

            <!-- Demo 3: Interactive Data Flow Architecture Diagram -->
            <div class="diagram-container">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
                    <div>
                        <h3 style="color: #fff; font-size: 18px; margin-bottom: 4px;">Interactive Repository Processing Pipeline</h3>
                        <p style="color: var(--text-muted); font-size: 13.5px; margin: 0;">
                            Click any node in the architecture flow to inspect what happens, what data is processed, and how cleanup is verified.
                        </p>
                    </div>
                    <span class="status-pill status-verified">Verified Ephemeral Processing</span>
                </div>

                <div class="flow-nodes-wrapper">
                    <div class="flow-node active" onclick="inspectNode('repo', this)">
                        <div class="flow-node-icon">📦</div>
                        <div class="flow-node-title">GitHub Repo</div>
                        <div class="flow-node-sub">Source Ingress</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('auth', this)">
                        <div class="flow-node-icon">🔑</div>
                        <div class="flow-node-title">Fine-Grained PAT</div>
                        <div class="flow-node-sub">Read-Only Auth</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('sandbox', this)">
                        <div class="flow-node-icon">🛡️</div>
                        <div class="flow-node-title">Temp Sandbox</div>
                        <div class="flow-node-sub">mkdtemp()</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('ast', this)">
                        <div class="flow-node-icon">🔍</div>
                        <div class="flow-node-title">AST / SAST Pass</div>
                        <div class="flow-node-sub">Static Scan</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('redaction', this)">
                        <div class="flow-node-icon">✂️</div>
                        <div class="flow-node-title">Redaction Pass</div>
                        <div class="flow-node-sub">Mask Findings</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('cleanup', this)">
                        <div class="flow-node-icon">🧹</div>
                        <div class="flow-node-title">Zero-Day Wipe</div>
                        <div class="flow-node-sub">shutil.rmtree()</div>
                    </div>
                    <div class="flow-arrow-conn">&rarr;</div>
                    <div class="flow-node" onclick="inspectNode('tenant', this)">
                        <div class="flow-node-icon">🗄️</div>
                        <div class="flow-node-title">Tenant Store</div>
                        <div class="flow-node-sub">Findings Only</div>
                    </div>
                </div>

                <!-- Inspector Box -->
                <div class="node-inspector" id="node-inspector-box">
                    <h4 id="inspector-title"><span>📦</span> GitHub Repository Ingress</h4>
                    <p id="inspector-desc" style="color: var(--text-muted); font-size: 13.5px; line-height: 1.55;">
                        Customer provides repository URL and fine-grained read-only Personal Access Token (PAT) with <code>contents:read</code> permission. No write or administrative permissions are requested.
                    </p>
                    <div class="inspector-grid">
                        <div class="detail-block">
                            <h4>What is Processed</h4>
                            <p id="inspector-proc">Git commit ref, branch tree, manifest files, and source code files.</p>
                        </div>
                        <div class="detail-block">
                            <h4>What is Stored</h4>
                            <p id="inspector-stored">Repository name, scan initiation timestamp, and commit SHA.</p>
                        </div>
                        <div class="detail-block">
                            <h4>Security Controls</h4>
                            <p id="inspector-ctrl">TLS 1.3 transit encryption, token memory isolation, least privilege.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- PHASE 10: LIVE CISA KEV TELEMETRY -->
        <section id="threat-intel">
            <div class="section-header">
                <span class="section-tag">Vulnerability Intelligence</span>
                <h2>CISA Known Exploited Vulnerabilities (KEV) Live Telemetry</h2>
                <p>
                    TrustAudit enriches identified software vulnerabilities with entries from CISA's Known Exploited 
                    Vulnerabilities catalogue, helping organisations prioritise vulnerabilities known to have been exploited in the wild.
                </p>
            </div>

            <div class="telemetry-card">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h3 style="color: #fff; font-size: 18px; margin-bottom: 4px;">Live Synchronization Status</h3>
                        <p style="color: var(--text-muted); font-size: 13px; margin: 0;">Automated hourly background worker synchronizing official CISA KEV feed</p>
                    </div>
                    <button class="btn-pack-nav" onclick="refreshTelemetry()">🔄 Re-check Telemetry</button>
                </div>

                <div class="telemetry-stats-row">
                    <div class="tstat-box">
                        <div class="tstat-num" id="tele-records">{{ cisa_records_count }}</div>
                        <div class="tstat-lbl">Active KEV Catalog CVEs</div>
                    </div>
                    <div class="tstat-box">
                        <div class="tstat-num" id="tele-status" style="color: #34d399; font-size: 20px;">{{ cisa_status }}</div>
                        <div class="tstat-lbl">Sync Engine Health</div>
                    </div>
                    <div class="tstat-box">
                        <div class="tstat-num" id="tele-sync" style="font-size: 14px; color: #cbd5e1;">{{ cisa_last_sync[:19] }} UTC</div>
                        <div class="tstat-lbl">Last Successful Sync</div>
                    </div>
                    <div class="tstat-box">
                        <div class="tstat-num" style="font-size: 14px; color: #38bdf8;">Hourly Cron</div>
                        <div class="tstat-lbl">Sync Cadence</div>
                    </div>
                </div>

                <div class="callout" style="margin-bottom: 0;">
                    <strong>Catalog Clarification:</strong> CISA KEV catalog is maintained by the U.S. Cybersecurity and Infrastructure Security Agency. 
                    It lists publicly disclosed vulnerabilities with documented active exploitation in the wild. Most have formal CVE IDs and vendor-issued patches; 
                    it is not restricted to zero-days.
                </div>
            </div>
        </section>

        <!-- SECTION: DATA TRANSPARENCY & SUBPROCESSORS -->
        <section id="data-transparency">
            <div class="section-header">
                <span class="section-tag">Governance & Privacy</span>
                <h2>Customer Data Transparency Disclosures</h2>
                <p>
                    Exhaustive disclosures regarding how customer data is processed, stored, and protected throughout its lifecycle.
                </p>
            </div>

            <div class="bento-grid" style="grid-template-columns: repeat(2, 1fr);">
                <div class="bento-card">
                    <div>
                        <span class="status-pill status-verified" style="margin-bottom: 8px;">Disclosure 1 & 2</span>
                        <h3>Source Code & Ephemeral Processing</h3>
                        <p>When executing repository scans, TrustAudit downloads a shallow clone into a temporary sandboxed directory. The code is parsed for AST structures and secret patterns, and is <strong>immediately deleted upon scan completion</strong> via <code>shutil.rmtree</code>. Full source code repositories are never permanently stored.</p>
                    </div>
                </div>

                <div class="bento-card">
                    <div>
                        <span class="status-pill status-verified" style="margin-bottom: 8px;">Disclosure 3 & 4</span>
                        <h3>Scan Results & Registration Data</h3>
                        <p>Normalized finding summaries (CWE IDs, category, severity, masked snippet, line numbers) are retained for 12 months for drift tracking. User passwords are encrypted using PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salts.</p>
                    </div>
                </div>

                <div class="bento-card">
                    <div>
                        <span class="status-pill status-provider" style="margin-bottom: 8px;">Disclosure 5 & 6</span>
                        <h3>Subprocessors & Cloud Hosting</h3>
                        <p>Core infrastructure is hosted on Render and Amazon Web Services (AWS) data centers located in the United States. Vulnerability feeds are pulled directly from public feeds (CISA KEV, NIST NVD, OSV.dev). No customer code is shared with third parties.</p>
                    </div>
                </div>

                <div class="bento-card">
                    <div>
                        <span class="status-pill status-verified" style="margin-bottom: 8px;">Disclosure 7 & 8</span>
                        <h3>AI Processing & Data Sharing Policy</h3>
                        <p>Core vulnerability scanning runs deterministic local analyzers and AST parsers. Fix prompts generated for coding assistants rely on static templates. <strong>Zero customer source code or findings are sent to OpenAI, Anthropic, or any public AI model training pool.</strong></p>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION: VULNERABILITY DISCLOSURE & CONTACT -->
        <section id="contact">
            <div class="section-header">
                <span class="section-tag">Security Response</span>
                <h2>Vulnerability Disclosure & Security Contact</h2>
                <p>
                    We welcome responsible reports from security researchers and customers. We operate a coordinated disclosure process with a 24-hour response SLA.
                </p>
            </div>

            <div class="bento-card" style="margin-top: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
                    <div>
                        <h3 style="font-size: 19px; margin-top: 0;">Coordinated Vulnerability Disclosure Policy</h3>
                        <p style="max-width: 750px;">
                            If you believe you have found a security vulnerability in TrustAudit, please email our dedicated security response team:
                        </p>
                        <div style="display: flex; gap: 20px; align-items: center; font-size: 14px; margin: 14px 0; flex-wrap: wrap;">
                            <span>📧 <strong>Security Contact:</strong> <a href="mailto:security@trustaudit.io" style="color: var(--primary-light); text-decoration: none;">security@trustaudit.io</a></span>
                            <span>⏱️ <strong>Response SLA:</strong> Within 24 business hours</span>
                            <span>🛡️ <strong>Safe Harbor:</strong> Guaranteed for good-faith testing</span>
                        </div>
                    </div>
                    <span class="status-pill status-verified">Safe Harbor Active</span>
                </div>
                <div style="border-top: 1px solid var(--border); padding-top: 16px; margin-top: 10px; font-size: 13px; color: var(--text-dim); line-height: 1.6;">
                    <strong>Safe Harbor Terms:</strong> We will not pursue legal action against researchers who test in good faith, avoid compromising customer data, refrain from denial-of-service attacks, and provide reasonable remediation time before public disclosure.
                </div>
            </div>
        </section>

        <!-- FOOTER -->
        <footer class="footer">
            <div class="footer-inner">
                <div class="footer-left">
                    <p>
                        <strong>Regulatory & Legal Notice:</strong> TrustAudit provides automated technical gap analysis, security scanning, 
                        and compliance evidence management. TrustAudit does not issue formal regulatory certifications, accredited ISO 27001 certificates, 
                        or certified SOC 2 Type II reports, which require independent examination by accredited third-party certification bodies and CPA firms. 
                        Compliance with applicable laws (including DPDP Act 2023, GDPR, and sectoral regulations) remains the statutory responsibility of the customer organization.
                    </p>
                    <p>&copy; 2026 TrustAudit Security Platform. All rights reserved.</p>
                </div>
                <div class="footer-links">
                    <a href="/dashboard">App Console</a>
                    <a href="#frameworks">Framework Explorer</a>
                    <a href="#data-transparency">Subprocessor Register</a>
                    <a href="mailto:security@trustaudit.io">Security Contact</a>
                </div>
            </div>
        </footer>

    </div>

    <!-- REMEDIATION EXAMPLE MODAL -->
    <div class="drawer-overlay" id="remediation-modal">
        <div class="drawer-modal">
            <button class="drawer-close" onclick="closeRemediationModal()">&times;</button>
            <div id="modal-content">
                <h3 style="color: #fff; margin-bottom: 8px;" id="modal-title">Remediation Guidance</h3>
                <p style="color: var(--text-muted); font-size: 14px;" id="modal-desc">Technical step-by-step guidance.</p>
                <div style="background: #090e17; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px; margin: 16px 0;">
                    <div style="font-size: 12px; color: var(--primary-light); font-weight: 700; margin-bottom: 4px;">SAFE FIX EXAMPLE</div>
                    <pre style="font-family: 'JetBrains Mono', monospace; font-size: 12.5px; color: #e2e8f0; margin: 0; overflow-x: auto;"><code id="modal-code"># Safe configuration example</code></pre>
                </div>
                <div style="font-size: 12px; color: var(--text-dim);">
                    ℹ️ <strong>SAFE CODE GUIDANCE &mdash; NON-EXECUTABLE PREVIEW.</strong> Does not alter customer repositories from public Trust Centre.
                </div>
            </div>
        </div>
    </div>

    <!-- TRUST PACK DOWNLOAD MODAL -->
    <div class="drawer-overlay" id="trust-pack-modal">
        <div class="drawer-modal" style="max-width: 600px;">
            <button class="drawer-close" onclick="closeTrustPackModal()">&times;</button>
            <h3 style="color: #fff; margin-bottom: 6px;">Download Enterprise Trust Pack</h3>
            <p style="color: var(--text-muted); font-size: 13.5px; margin-bottom: 18px;">
                Select approved security and compliance disclosures to download as an audit-ready bundle:
            </p>

            <form id="pack-download-form" onsubmit="handleTrustPackDownload(event)">
                <div style="margin-bottom: 18px;">
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="overview" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">TrustAudit Security Overview & Posture Statement</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Executive summary of architecture and threat models</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="dpdp" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">DPDP Act 2023 & DPDP Rules 2025 Readiness Mapping</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Statutory sections, Rule 6/7 mappings, and commencement timeline</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="soc2" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">SOC 2 Trust Services Criteria Control Mapping</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">CC6.1, CC6.6, CC6.8, CC7.1, CC8.1 technical mapping</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="iso27001" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">ISO/IEC 27001:2022 Technical Controls Mapping</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Annex A technological controls (A.8.8, A.8.20, A.8.24, A.8.25, A.8.28)</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="retention" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">Data Processing & Retention Schedule</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">0-day repository retention, 12-month finding drift lifecycle</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="subprocessors" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">Official Third-Party Subprocessor Register</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Infrastructure providers, processing locations, and certifications</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="disclosure" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">Coordinated Vulnerability Disclosure Policy</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Safe harbor terms and 24h response SLA</div>
                        </div>
                    </div>
                    <div class="pack-item-row">
                        <input type="checkbox" class="pack-check" name="doc" value="architecture" checked>
                        <div>
                            <strong style="color: #fff; font-size: 13.5px;">Technical Security Architecture & Isolation Model</strong>
                            <div style="font-size: 12px; color: var(--text-dim);">Multi-tenant boundaries and secret masking pipeline</div>
                        </div>
                    </div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px;">
                    <div style="display: flex; gap: 12px; font-size: 13px;">
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                            <input type="radio" name="format" value="zip" checked> ZIP Archive (.zip)
                        </label>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                            <input type="radio" name="format" value="markdown"> Markdown Bundle (.md)
                        </label>
                    </div>
                    <button type="submit" class="btn-primary-lg" style="padding: 10px 20px; font-size: 14px;">
                        Download Bundle &darr;
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- JAVASCRIPT: INTERACTIVE ENGINE & TELEMETRY -->
    <script>
        // 1. Scroll Progress & Sticky Navbar Scrollspy
        window.addEventListener('scroll', () => {
            const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
            const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
            const scrolled = (winScroll / height) * 100;
            document.getElementById('scroll-progress').style.width = scrolled + '%';

            // Active section highlighting
            const sections = document.querySelectorAll('section, header');
            const navLinks = document.querySelectorAll('.nav-menu a');
            let current = 'overview';

            sections.forEach(sec => {
                const top = sec.offsetTop - 120;
                if (winScroll >= top) {
                    current = sec.getAttribute('id') || 'overview';
                }
            });

            navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {
                    link.classList.add('active');
                }
            });
        });

        // 2. Control Explorer Accordion & Filters
        function toggleAccordion(header) {
            const item = header.parentElement;
            item.classList.toggle('open');
        }

        function filterFramework(fw, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const items = document.querySelectorAll('.accordion-item');
            items.forEach(item => {
                const itemFw = item.getAttribute('data-framework');
                if (fw === 'ALL' || itemFw === fw) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        }

        function searchControls(query) {
            const clean = query.toLowerCase().trim();
            const items = document.querySelectorAll('.accordion-item');
            items.forEach(item => {
                const text = item.innerText.toLowerCase();
                if (!clean || text.includes(clean)) {
                    item.style.display = 'block';
                } else {
                    item.style.display = 'none';
                }
            });
        }

        function copySnippet(btn) {
            const pre = btn.parentElement.nextElementSibling;
            navigator.clipboard.writeText(pre.innerText).then(() => {
                const old = btn.innerText;
                btn.innerText = 'Copied!';
                setTimeout(() => btn.innerText = old, 1500);
            });
        }

        // 3. Remediation Modal Logic
        const REMEDIATION_SAMPLES = {
            'dpdp-sec-6': {
                title: 'DPDP Section 6(9) Consent Revocation Workflow',
                desc: 'Provide an authenticated self-service API endpoint that immediately halts personal data processing and cascades revocation to downstream processors.',
                code: 'POST /api/user/consent/revoke\nHeaders: Authorization: Bearer <user_token>\nPayload: {"consent_categories": ["marketing", "analytics"]}\n\nResponse 200 OK:\n{\n  "status": "revoked",\n  "effective_at": "2026-11-18T23:55:00Z",\n  "cascade_notice_sent_to_processors": true\n}'
            },
            'dpdp-sec-8-5': {
                title: 'DPDP Section 8(5) Hardcoded Credential Remediation',
                desc: 'Move hardcoded database credentials to secure environment variables and add .env to .gitignore.',
                code: '# Step 1: Remove secret from source file\n- db_password = "super_secret_db_password"\n+ db_password = os.environ.get("DATABASE_PASSWORD")\n\n# Step 2: Add to .gitignore\necho ".env" >> .gitignore\n\n# Step 3: Rotate compromised credential in database'
            },
            'soc2-cc6-1': {
                title: 'SOC 2 CC6.1 Logical Access Isolation',
                desc: 'Enforce server-side tenant isolation checking session tokens before returning customer resources.',
                code: 'def get_customer_project(project_id, user_session):\n    tenant_org_id = user_session.get("org_id")\n    project = db.query(Project).filter_by(id=project_id, org_id=tenant_org_id).first()\n    if not project:\n        raise Unauthorized("Project not found or cross-tenant access prohibited")\n    return project'
            },
            'soc2-cc7-1': {
                title: 'SOC 2 CC7.1 CISA KEV Vulnerability Patch SLA',
                desc: 'Automate build-breaking CI gate for dependencies listed on the CISA KEV active exploitation catalog.',
                code: '# In CI security check (ci_scan.py):\nfor package in manifest.dependencies:\n    if lookup_cisa_kev(package.cve_id):\n        print(f"CRITICAL: {package.cve_id} is in CISA KEV!")\n        sys.exit(1) # Break build to enforce 7-day patch SLA'
            },
            'iso-a-8-8': {
                title: 'ISO 27001 Control A.8.8 SAST Vulnerability Remediation',
                desc: 'Replace unsafe raw SQL string concatenation with parameterized prepared statements.',
                code: '# Unsafe command injection vector:\n- subprocess.run(f"cat {user_file}", shell=True)\n# Safe parameterized execution:\n+ subprocess.run(["cat", os.path.basename(user_file)], shell=False)'
            },
            'iso-a-8-20': {
                title: 'ISO 27001 Control A.8.20 Network Boundary & CORS',
                desc: 'Replace wildcard CORS allowlists with trusted origin verification.',
                code: '- response.headers["Access-Control-Allow-Origin"] = "*"\n+ allowed_origins = ["https://app.trustaudit.io"]\n+ if origin in allowed_origins:\n+     response.headers["Access-Control-Allow-Origin"] = origin'
            },
            'gdpr-art-32': {
                title: 'GDPR Article 32 Transport Encryption Enforcement',
                desc: 'Enforce strict HTTPS with HTTP Strict Transport Security (HSTS) headers.',
                code: 'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"\nresponse.headers["X-Content-Type-Options"] = "nosniff"\nresponse.headers["X-Frame-Options"] = "DENY"'
            }
        };

        function openRemediationModal(key) {
            const data = REMEDIATION_SAMPLES[key] || {
                title: 'Remediation Guidance',
                desc: 'Implement secure configuration and verify via automated re-scan.',
                code: '# Review finding details and apply recommended fix'
            };
            document.getElementById('modal-title').innerText = data.title;
            document.getElementById('modal-desc').innerText = data.desc;
            document.getElementById('modal-code').innerText = data.code;
            document.getElementById('remediation-modal').classList.add('open');
        }

        function closeRemediationModal() {
            document.getElementById('remediation-modal').classList.remove('open');
        }

        // 4. Client-Side Secret Redaction Sandbox
        function runMaskingDemo() {
            const input = document.getElementById('sandbox-input-val').value.trim();
            const btn = document.getElementById('btn-run-mask');
            btn.innerText = 'Analyzing...';

            setTimeout(() => {
                let masked = '[REDACTED]';
                if (!input) {
                    masked = '[EMPTY INPUT]';
                } else if (input.length <= 8) {
                    masked = '[REDACTED]';
                } else {
                    const prefix = input.substring(0, 4);
                    const suffix = input.substring(input.length - 4);
                    masked = `${prefix}...[REDACTED]...${suffix}`;
                }

                document.getElementById('res-orig').innerText = input || '(empty)';
                document.getElementById('res-masked').innerText = masked;
                document.getElementById('sandbox-result').classList.add('active');
                btn.innerText = 'Test Masking';
            }, 250);
        }

        function resetMaskingDemo() {
            document.getElementById('sandbox-input-val').value = 'sk-test-example-123456789';
            runMaskingDemo();
        }

        // 5. Enterprise Questionnaire Simulator
        const SIM_DATA = [
            {
                qId: 1,
                answer: 'Source code access is restricted via organization-wide GitHub fine-grained permissions requiring hardware security keys and branch protection rules. Direct commits to production branches are blocked.',
                badge: 'SAMPLE EVIDENCE: GitHub_Branch_Protection_Rules.json'
            },
            {
                qId: 2,
                answer: 'Third-party dependencies are continuously scanned across pull requests using automated SBOM analyzers. Any dependency flagged in the CISA KEV catalog triggers a high-priority 7-day patch SLA.',
                badge: 'SAMPLE EVIDENCE: OSV_SBOM_Scan_Report.json'
            },
            {
                qId: 3,
                answer: 'Security findings are automatically categorized into remediation tasks with enforced SLAs (7 days for Critical, 14 days for High). Each finding links directly to required auditor verification proof.',
                badge: 'SAMPLE EVIDENCE: SLA_Remediation_Log.pdf'
            }
        ];

        function runQuestionnaireSimulator() {
            SIM_DATA.forEach((item, idx) => {
                setTimeout(() => {
                    document.getElementById(`sim-ans-${item.qId}`).innerText = item.answer;
                    const st = document.getElementById(`sim-status-${item.qId}`);
                    st.innerText = 'DEMO ANSWER POPULATED';
                    st.className = 'status-pill status-verified';
                    document.getElementById(`sim-ev-${item.qId}`).style.display = 'flex';
                }, (idx + 1) * 350);
            });
        }

        function resetQuestionnaireSimulator() {
            [1, 2, 3].forEach(id => {
                document.getElementById(`sim-ans-${id}`).innerText = "Click 'Auto-Fill Demo Evidence' to populate verified response.";
                const st = document.getElementById(`sim-status-${id}`);
                st.innerText = 'Not Filled';
                st.className = 'status-pill status-roadmap';
                document.getElementById(`sim-ev-${id}`).style.display = 'none';
            });
        }

        // 6. Interactive Data Flow Node Inspector
        const NODE_DATA = {
            'repo': {
                icon: '📦',
                title: 'GitHub Repository Ingress',
                desc: 'Customer provides repository URL and fine-grained read-only Personal Access Token (PAT) with contents:read permission. No write or administrative permissions are requested.',
                proc: 'Git commit ref, branch tree, manifest files, and source code files.',
                stored: 'Repository name, scan initiation timestamp, and commit SHA.',
                ctrl: 'TLS 1.3 transit encryption, token memory isolation, least privilege.'
            },
            'auth': {
                icon: '🔑',
                title: 'Authorised Connection & Scoping',
                desc: 'Fine-grained PAT or GitHub App connection validated. Scopes strictly enforced; token is kept in ephemeral execution memory only.',
                proc: 'GitHub API authentication tokens and webhook signatures.',
                stored: 'Encrypted token handle with tenant organization scoping.',
                ctrl: 'HMAC signature verification, token rotation support.'
            },
            'sandbox': {
                icon: '🛡️',
                title: 'Sandboxed Scan Environment',
                desc: 'Repository is cloned into a unique sandboxed temporary folder (tempfile.mkdtemp) isolated from other tenants.',
                proc: 'Shallow git clone of target repository.',
                stored: 'Zero permanent storage (stored exclusively in ephemeral temporary filesystem).',
                ctrl: 'Filesystem permission isolation, subprocess timeouts.'
            },
            'ast': {
                icon: '🔍',
                title: 'AST & Static Security Analysis',
                desc: 'Parses source code into Abstract Syntax Trees (AST). Checks MCP tool definitions for capability creep, prompt injection vectors, and hardcoded secrets.',
                proc: 'Python, TypeScript, JavaScript AST nodes and package manifests.',
                stored: 'Vulnerability pattern match locations and AST telemetry.',
                ctrl: 'Deterministic local execution; no code sent to external LLMs.'
            },
            'redaction': {
                icon: '✂️',
                title: 'Finding Normalisation & Preview Redaction',
                desc: 'Every finding is normalized to a 12-field schema. Credential values are masked (prefix...[REDACTED]...suffix) before reaching database storage.',
                proc: 'Raw scanner finding dictionaries and line snippets.',
                stored: 'Redacted code preview snippets only; raw credentials discarded.',
                ctrl: 'Regex & Shannon entropy preview masking engine.'
            },
            'cleanup': {
                icon: '🧹',
                title: 'Measured Zero-Day Cleanup',
                desc: 'Upon scan completion, temporary working directories are wiped immediately using shutil.rmtree(temp_dir). Complete source code is never permanently stored.',
                proc: 'Temporary filesystem directories and downloaded files.',
                stored: 'Zero source code retained (0-day retention verified).',
                ctrl: 'Automated post-scan cleanup hook in scan manager.'
            },
            'tenant': {
                icon: '🗄️',
                title: 'Tenant-Scoped Storage & Reporting',
                desc: 'Normalized findings and compliance mappings are persisted in tenant-isolated stores guarded by server-side session token authorization.',
                proc: 'Aggregated findings, SLA deadlines, and audit evidence hashes.',
                stored: 'Finding summaries, CWE IDs, and remediation lifecycle states.',
                ctrl: 'Multi-tenant database partitioning, SHA-256 evidence hashing.'
            }
        };

        function inspectNode(key, element) {
            document.querySelectorAll('.flow-node').forEach(n => n.classList.remove('active'));
            element.classList.add('active');

            const info = NODE_DATA[key];
            if (!info) return;

            document.getElementById('inspector-title').innerHTML = `<span>${info.icon}</span> ${info.title}`;
            document.getElementById('inspector-desc').innerText = info.desc;
            document.getElementById('inspector-proc').innerText = info.proc;
            document.getElementById('inspector-stored').innerText = info.stored;
            document.getElementById('inspector-ctrl').innerText = info.ctrl;
        }

        // 7. Live Telemetry Fetcher
        function refreshTelemetry() {
            fetch('/api/public/trust-status')
                .then(res => res.json())
                .then(data => {
                    if (data && data.kev_sync) {
                        document.getElementById('tele-records').innerText = data.kev_sync.catalog_entries + ' CVEs';
                        document.getElementById('tele-status').innerText = data.kev_sync.status;
                        document.getElementById('tele-sync').innerText = data.kev_sync.last_successful_sync.substring(0, 19) + ' UTC';
                    }
                })
                .catch(() => {
                    // Retain server-rendered baseline if network fails
                });
        }

        // 8. Trust Pack Modal
        function openTrustPackModal() {
            document.getElementById('trust-pack-modal').classList.add('open');
        }

        function closeTrustPackModal() {
            document.getElementById('trust-pack-modal').classList.remove('open');
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

        // Close modals on Escape key
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeRemediationModal();
                closeTrustPackModal();
            }
        });
    </script>

</body>
</html>
"""
