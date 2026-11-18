"""
TrustAudit Public Security & Compliance Trust Centre Template.

Renders an evidence-based, transparent Trust Centre detailing:
- DPDP Act 2023 & DPDP Rules 2025 with statutory legal commencement timeline
- SOC 2 Trust Services Criteria (2017 TSC with 2022 Focus) readiness & evidence management
- ISO/IEC 27001:2022 (including AMD 1:2024 Climate action) technical controls
- EU GDPR (Articles 25, 32, 33)
- Live CISA KEV Intelligence synchronization telemetry
- Secret Handling & Preview Masking verified architecture
- Multi-Tenant Isolation with automated negative test validation
- Customer Data Transparency (10 required items)
- Scanning Authorization & Scope (Passive vs Active)
- Platform Security, Vulnerability Disclosure (security@trustaudit.io) & Certification Roadmap
"""

TRUST_CENTRE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit Security, Compliance & Trust Center</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #111827;
            --surface-alt: #161f30;
            --surface-elevated: #1e293b;
            --border: rgba(255, 255, 255, 0.08);
            --border-highlight: rgba(56, 189, 248, 0.25);
            --primary: #0284c7;
            --primary-light: #38bdf8;
            --accent: #6366f1;
            --success: #10b981;
            --warning: #f59e0b;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --text-dim: #64748b;
        }

        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 0;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        .container {
            max-width: 1180px;
            margin: 0 auto;
            padding: 0 24px;
        }

        /* Top Navigation */
        .navbar {
            position: sticky;
            top: 0;
            z-index: 50;
            background: rgba(11, 15, 25, 0.85);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 16px 0;
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
            font-weight: 700;
            font-size: 18px;
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
        }
        .nav-links {
            display: flex;
            align-items: center;
            gap: 24px;
        }
        .nav-link {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            transition: color 0.15s;
        }
        .nav-link:hover { color: #fff; }
        .btn-launch {
            background: var(--primary);
            color: #fff;
            padding: 8px 18px;
            border-radius: 8px;
            font-size: 13.5px;
            font-weight: 600;
            text-decoration: none;
            transition: background 0.15s;
        }
        .btn-launch:hover { background: #0369a1; }

        /* Hero Section */
        .hero {
            padding: 64px 0 40px;
            text-align: center;
        }
        .pill-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(2, 132, 199, 0.12);
            color: var(--primary-light);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 5px 14px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        .hero h1 {
            font-size: 44px;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin: 0 0 16px;
            line-height: 1.15;
            background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .hero p.subtitle {
            font-size: 18px;
            color: var(--text-muted);
            max-width: 780px;
            margin: 0 auto 28px;
            line-height: 1.6;
        }
        .meta-bar {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 24px;
            font-size: 13px;
            color: var(--text-dim);
            flex-wrap: wrap;
        }
        .meta-bar span { display: flex; align-items: center; gap: 6px; }

        /* Section Headings */
        .section-header {
            margin: 60px 0 24px;
        }
        .section-header .tag {
            font-size: 11.5px;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--primary-light);
            letter-spacing: 0.08em;
            margin-bottom: 6px;
            display: block;
        }
        .section-header h2 {
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin: 0 0 8px;
            color: #fff;
        }
        .section-header p {
            color: var(--text-muted);
            margin: 0;
            font-size: 15px;
            max-width: 820px;
        }

        /* Cards & Grids */
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 24px;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 26px;
            transition: border-color 0.15s, transform 0.15s;
        }
        .card:hover {
            border-color: var(--border-highlight);
        }
        .card h3 {
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 8px;
            color: #fff;
        }
        .card p {
            font-size: 14px;
            color: var(--text-muted);
            margin: 0 0 16px;
            line-height: 1.55;
        }

        /* Status Badges */
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            white-space: nowrap;
        }
        .badge-verified {
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .badge-operational {
            background: rgba(56, 189, 248, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .badge-customer-evidence {
            background: rgba(129, 140, 248, 0.12);
            color: #a5b4fc;
            border: 1px solid rgba(129, 140, 248, 0.3);
        }
        .badge-self-attested {
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .badge-readiness {
            background: rgba(96, 165, 250, 0.12);
            color: #93c5fd;
            border: 1px solid rgba(96, 165, 250, 0.3);
        }
        .badge-roadmap {
            background: rgba(148, 163, 184, 0.12);
            color: #cbd5e1;
            border: 1px solid rgba(148, 163, 184, 0.3);
        }

        /* Callout Box */
        .callout {
            background: var(--surface-alt);
            border-left: 3px solid var(--primary);
            border-radius: 0 10px 10px 0;
            padding: 16px 20px;
            margin: 18px 0;
            font-size: 13.5px;
            color: var(--text-muted);
        }
        .callout strong { color: #fff; }
        .callout-warning {
            border-left-color: var(--warning);
            background: rgba(245, 158, 11, 0.06);
        }

        /* Table */
        .table-wrap {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--surface);
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
            text-align: left;
        }
        th {
            background: var(--surface-alt);
            color: #cbd5e1;
            font-weight: 600;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
            vertical-align: top;
        }
        tr:last-child td { border-bottom: none; }
        td strong { color: #fff; font-weight: 600; }
        .code-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            background: rgba(255, 255, 255, 0.04);
            padding: 2px 6px;
            border-radius: 4px;
            color: #e2e8f0;
        }

        /* Telemetry Block */
        .telemetry-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            background: var(--surface-alt);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-top: 18px;
        }
        .telemetry-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .telemetry-label {
            font-size: 11.5px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        .telemetry-val {
            font-size: 16px;
            font-weight: 700;
            color: #fff;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Transparency List */
        .transparency-list {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }
        .transparency-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px 22px;
        }
        .transparency-card h4 {
            font-size: 15px;
            margin: 0 0 6px;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .transparency-card p {
            font-size: 13.5px;
            color: var(--text-muted);
            margin: 0;
            line-height: 1.55;
        }

        /* Footer */
        .footer {
            margin-top: 80px;
            padding: 40px 0 60px;
            border-top: 1px solid var(--border);
            font-size: 13px;
            color: var(--text-dim);
        }
        .footer-inner {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 30px;
            flex-wrap: wrap;
        }
        .footer-left { max-width: 650px; }
        .footer-left p { margin: 0 0 10px; line-height: 1.6; }
        .footer-links {
            display: flex;
            gap: 20px;
        }
        .footer-links a {
            color: var(--text-muted);
            text-decoration: none;
            transition: color 0.15s;
        }
        .footer-links a:hover { color: #fff; }

        @media (max-width: 900px) {
            .grid-2, .grid-3 { grid-template-columns: 1fr; }
            .telemetry-grid { grid-template-columns: repeat(2, 1fr); }
            .hero h1 { font-size: 32px; }
            .nav-links { display: none; }
        }
    </style>
</head>
<body>

    <!-- Navigation -->
    <nav class="navbar">
        <div class="container nav-inner">
            <a href="/trust" class="brand">
                <div class="brand-icon">🛡️</div>
                TrustAudit Trust Center
            </a>
            <div class="nav-links">
                <a href="#frameworks" class="nav-link">Frameworks</a>
                <a href="#threat-intel" class="nav-link">Threat Intel</a>
                <a href="#data-transparency" class="nav-link">Data Transparency</a>
                <a href="#security-controls" class="nav-link">Security Architecture</a>
                <a href="#contact" class="nav-link">Security Contact</a>
            </div>
            <a href="/dashboard" class="btn-launch">Open Console &rarr;</a>
        </div>
    </nav>

    <div class="container">

        <!-- Hero Header -->
        <header class="hero">
            <span class="pill-badge">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: #10b981;"></span>
                Evidence-Based Security & Compliance Transparency
            </span>
            <h1>Security, Compliance & Trust Center</h1>
            <p class="subtitle">
                TrustAudit provides transparent, verifiable visibility into our technical security controls, 
                customer data boundaries, GRC framework readiness, and real-time threat intelligence.
            </p>
            <div class="meta-bar">
                <span>📅 <strong>Last Reviewed:</strong> 18 November 2026</span>
                <span>🏛️ <strong>Audited Standards:</strong> DPDP 2023, SOC 2, ISO/IEC 27001:2022, GDPR</span>
                <span>🔒 <strong>Tenant Isolation:</strong> Enforced & Cryptographically Verified</span>
            </div>
        </header>

        <!-- SECTION 1: REGULATORY & COMPLIANCE FRAMEWORKS -->
        <section id="frameworks">
            <div class="section-header">
                <span class="tag">Compliance Center</span>
                <h2>Regulatory & Compliance Frameworks</h2>
                <p>
                    TrustAudit evaluates technical controls against statutory data protection laws and international 
                    information security standards. We clearly distinguish published criteria from draft rules, and present 
                    readiness without misrepresenting statutory certification.
                </p>
            </div>

            <!-- Framework 1: DPDP -->
            <div class="card" style="margin-bottom: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <span class="tag">Statutory Data Protection</span>
                        <h3>Digital Personal Data Protection Act, 2023 & DPDP Rules, 2025</h3>
                        <div style="color: var(--text-dim); font-size: 13px;">Jurisdiction: India &bull; Authority: Data Protection Board of India (DPBI) / MeitY &bull; Version: Act No. 22 of 2023 & DPDP Rules, 2025</div>
                    </div>
                    <span class="status-badge badge-readiness">Phased Commencement</span>
                </div>

                <div class="callout">
                    <strong>Statutory Commencement Timeline (as of 18 November 2026):</strong><br>
                    &bull; <strong>Already in force:</strong> Section 6(9) and Rule 4 concerning the registration and operation of Consent Managers commenced on <strong>13 November 2026</strong>.<br>
                    &bull; <strong>Scheduled commencement:</strong> Substantive Data Fiduciary obligations (including Sections 5, 8, 9, 10) and Rules 3, 5–16 are scheduled to commence on <strong>13 May 2027</strong>.<br>
                    &bull; <strong>Statutory Notice:</strong> TrustAudit is a security and compliance evaluation platform and is <em>not</em> a registered statutory Consent Manager under Section 6(9). Future statutory requirements are evaluated as readiness and never represented as existing legal violations.
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Section & Rule</th>
                                <th>Control Title</th>
                                <th>Statutory Description</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><span class="code-cell">Section 5 & Rule 3</span></td>
                                <td><strong>Notice Requirements</strong></td>
                                <td>Itemized notice before requesting consent, specifying personal data sought, purpose, rights withdrawal, and grievance contact.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 6(9) & Rule 4</span></td>
                                <td><strong>Consent Manager Integration</strong></td>
                                <td>Interoperability readiness to interface with registered Consent Managers for consent lifecycle tracking.</td>
                                <td><span class="status-badge badge-operational">Already in force</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 8(1)</span></td>
                                <td><strong>General Fiduciary Responsibility</strong></td>
                                <td>Statutory responsibility of the Data Fiduciary to comply with the Act for all processing undertaken by it or on its behalf.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 8(4)</span></td>
                                <td><strong>Technical & Organisational Measures</strong></td>
                                <td>Implementation of appropriate technical and organizational measures to ensure effective observance of the Act.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 8(5) & Rule 6</span></td>
                                <td><strong>Reasonable Security Safeguards</strong></td>
                                <td>Mandatory technical safeguards (encryption, access boundaries, secret security) to prevent personal data breach.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 8(6) & Rule 7</span></td>
                                <td><strong>Breach Notification to DPBI</strong></td>
                                <td>Mandatory intimation of personal data breach to the Data Protection Board of India and affected Data Principals.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 9 & Rules</span></td>
                                <td><strong>Children's Personal Data</strong></td>
                                <td>Verifiable parental consent before processing children's data; prohibition on behavioral tracking and targeted advertising.</td>
                                <td><span class="status-badge badge-readiness">Readiness assessment</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">Section 10</span></td>
                                <td><strong>Significant Data Fiduciary (SDF)</strong></td>
                                <td>Higher governance obligations (India-based DPO, statutory data auditor, DPIA) upon government designation.</td>
                                <td><span class="status-badge badge-self-attested">Requires legal review</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Framework 2: SOC 2 -->
            <div class="card" style="margin-bottom: 24px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <span class="tag">Auditing Criteria</span>
                        <h3>SOC 2 Trust Services Criteria (Readiness & Evidence Management)</h3>
                        <div style="color: var(--text-dim); font-size: 13px;">Authority: AICPA &bull; Standard: 2017 TSC with 2022 Points of Focus &bull; Category: Security (Common Criteria)</div>
                    </div>
                    <span class="status-badge badge-customer-evidence">Readiness Evaluation</span>
                </div>

                <div class="callout">
                    <strong>Auditing Disclaimer:</strong> TrustAudit tracks control readiness and automated evidence collection for selected technical criteria. 
                    Automated technical mappings do not constitute complete SOC 2 coverage, an issued SOC 2 examination report, or CPA attestation. 
                    Formal SOC 2 Type 1 and Type 2 reports require an independent examination by a licensed CPA firm.
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Criteria ID</th>
                                <th>Criterion Title</th>
                                <th>AICPA Published Scope</th>
                                <th>TrustAudit Implementation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><span class="code-cell">CC6.1</span></td>
                                <td><strong>Logical Access Security</strong></td>
                                <td>Implementation of logical access security software and infrastructure to protect assets from unauthorized events.</td>
                                <td><span class="status-badge badge-verified">Verified (Secrets & Access)</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">CC6.6</span></td>
                                <td><strong>Protection Against Threats Originating Outside Boundaries</strong></td>
                                <td>Logical boundaries and perimeter protection to prevent unauthorized network access and secure data transmission.</td>
                                <td><span class="status-badge badge-verified">Verified (TLS & Headers)</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">CC6.8</span></td>
                                <td><strong>Prevention, Detection, and Remediation of Malicious Software</strong></td>
                                <td>Controls to prevent or detect the introduction of unauthorized software, malicious code, or compromised integrations.</td>
                                <td><span class="status-badge badge-verified">Verified (MCP Tool Defense)</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">CC7.1</span></td>
                                <td><strong>Monitoring Configuration Changes & Vulnerability Susceptibility</strong></td>
                                <td>Procedures to monitor changes to configurations and susceptibility to newly discovered vulnerabilities (not simply Patch SLAs).</td>
                                <td><span class="status-badge badge-verified">Verified (CISA KEV & CVEs)</span></td>
                            </tr>
                            <tr>
                                <td><span class="code-cell">CC8.1</span></td>
                                <td><strong>Authorized Change Management & CI/CD Security</strong></td>
                                <td>Authorization, testing, approval, and documentation of changes to applications prior to production deployment.</td>
                                <td><span class="status-badge badge-customer-evidence">Customer-provided evidence</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Framework 3 & 4: ISO 27001 & GDPR -->
            <div class="grid-2">
                <div class="card">
                    <span class="tag">ISMS Standard</span>
                    <h3>ISO/IEC 27001:2022 (+ AMD 1:2024)</h3>
                    <p style="font-size: 13px; color: var(--text-dim); margin-bottom: 12px;">Standard: ISO/IEC 27001:2022 (including AMD 1:2024 Climate action) &bull; Scope: Technological Controls</p>
                    <p>
                        TrustAudit evaluates technical control posture across selected Annex A controls. Automated static and dynamic testing 
                        does not establish full ISMS conformity or accredited ISO 27001 certification.
                    </p>
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr><th>Control</th><th>Official Title</th><th>Status</th></tr>
                            </thead>
                            <tbody>
                                <tr><td><span class="code-cell">A.8.8</span></td><td>Management of technical vulnerabilities</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                                <tr><td><span class="code-cell">A.8.20</span></td><td>Networks security</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                                <tr><td><span class="code-cell">A.8.24</span></td><td>Use of cryptography</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                                <tr><td><span class="code-cell">A.8.25</span></td><td>Secure development life cycle</td><td><span class="status-badge badge-customer-evidence">Evidence required</span></td></tr>
                                <tr><td><span class="code-cell">A.8.28</span></td><td>Secure coding</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <span class="tag">European Privacy</span>
                    <h3>EU GDPR (Regulation 2016/679)</h3>
                    <p style="font-size: 13px; color: var(--text-dim); margin-bottom: 12px;">Jurisdiction: European Union / EEA &bull; Status: Fully Enacted & Enforceable</p>
                    <p>
                        Technical safeguards and record-keeping tools for systems processing EU/EEA personal data. 
                        Compliance remains the continuous legal responsibility of the Data Controller.
                    </p>
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr><th>Article</th><th>Scope</th><th>Status</th></tr>
                            </thead>
                            <tbody>
                                <tr><td><span class="code-cell">Art. 25</span></td><td>Data protection by design and default (least privilege, tenant boundaries)</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                                <tr><td><span class="code-cell">Art. 32</span></td><td>Security of processing, encryption of personal data in transit and rest</td><td><span class="status-badge badge-verified">Verified</span></td></tr>
                                <tr><td><span class="code-cell">Art. 33</span></td><td>72-hour personal data breach intimation workflow to supervisory authority</td><td><span class="status-badge badge-readiness">Readiness</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION 2: THREAT INTELLIGENCE (CISA KEV) -->
        <section id="threat-intel">
            <div class="section-header">
                <span class="tag">Vulnerability Intelligence</span>
                <h2>CISA Known Exploited Vulnerabilities (KEV) Ground Truth</h2>
                <p>
                    TrustAudit enriches identified software vulnerabilities with entries from CISA's Known Exploited 
                    Vulnerabilities catalogue, helping organisations prioritise vulnerabilities known to have been exploited in the wild.
                </p>
            </div>

            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <h3 style="margin: 0;">Live CISA KEV Synchronization Telemetry</h3>
                        <div style="font-size: 13px; color: var(--text-dim);">Automated background synchronizer polling CISA official catalog</div>
                    </div>
                    <span class="status-badge badge-operational">Operational & Synchronized</span>
                </div>

                <div class="telemetry-grid">
                    <div class="telemetry-item">
                        <span class="telemetry-label">Data Source</span>
                        <span class="telemetry-val" style="font-size: 13px;">CISA.gov JSON</span>
                    </div>
                    <div class="telemetry-item">
                        <span class="telemetry-label">Catalog Records</span>
                        <span class="telemetry-val">{{ cisa_records_count }} CVEs</span>
                    </div>
                    <div class="telemetry-item">
                        <span class="telemetry-label">Sync Health</span>
                        <span class="telemetry-val" style="color: #34d399;">{{ cisa_status }}</span>
                    </div>
                    <div class="telemetry-item">
                        <span class="telemetry-label">Last Successful Sync</span>
                        <span class="telemetry-val" style="font-size: 13px;">{{ cisa_last_sync[:19] }} UTC</span>
                    </div>
                </div>

                <div style="margin-top: 18px; font-size: 13.5px; color: var(--text-muted);">
                    <strong>Catalog Clarification:</strong> CISA KEV contains confirmed publicly known vulnerabilities with documented 
                    active in-the-wild exploitation. It is <em>not</em> restricted to zero-day vulnerabilities; the majority possess formal CVE 
                    identifiers and vendor-issued remediation patches.
                </div>
            </div>
        </section>

        <!-- SECTION 3 & 4: SECRET HANDLING & TENANT ISOLATION -->
        <section id="security-architecture">
            <div class="section-header">
                <span class="tag">Engineering Architecture</span>
                <h2>Data Protection & Isolation Architecture</h2>
                <p>
                    Objective, implementation-verified descriptions of how customer credentials, source code, 
                    and multi-tenant boundaries are secured within TrustAudit.
                </p>
            </div>

            <div class="grid-2">
                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                        <h3>Secret Handling & Preview Masking</h3>
                        <span class="status-badge badge-verified">Verified Implementation</span>
                    </div>
                    <p>
                        Multi-layered regex and Shannon entropy credential detection inspects source files for hardcoded API keys, 
                        tokens, and database credentials.
                    </p>
                    <ul style="font-size: 13.5px; color: var(--text-muted); padding-left: 18px; margin: 0 0 16px;">
                        <li><strong>Automated Preview Redaction:</strong> When a secret is detected, raw values are masked to safe preview fragments (e.g. <code>prefix...[REDACTED]...suffix</code>) before rendering in scan results, database stores, or reports.</li>
                        <li><strong>Engine Sanitization:</strong> Gitleaks CLI integrations sanitize raw finding outputs prior to in-memory persistence.</li>
                        <li><strong>Transparent Standard:</strong> We do not make unsupported absolute marketing claims (such as "Zero Secret Leakage Guarantee"). Masking is enforced programmatically across normalizers and serializers.</li>
                    </ul>
                </div>

                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                        <h3>Multi-Tenant Data Partitioning</h3>
                        <span class="status-badge badge-verified">Verified Negative Tests</span>
                    </div>
                    <p>
                        Customer organizations, scan reports, evidence files, and remediation tasks are partitioned by 
                        tenant organization IDs with server-side authorization checks.
                    </p>
                    <ul style="font-size: 13.5px; color: var(--text-muted); padding-left: 18px; margin: 0 0 16px;">
                        <li><strong>Server-Side Verification:</strong> An organization ID alone is an identifier, not a security boundary. Access is validated against authenticated session bearer tokens derived from salted PBKDF2-HMAC-SHA256 credentials.</li>
                        <li><strong>Automated Negative Testing:</strong> Suite <code>TestTenantIsolationAndNegativeAccessControl</code> asserts that cross-tenant requests attempting to view, download, or delete another organization's evidence or projects return HTTP 404.</li>
                        <li><strong>Isolated Storage:</strong> Evidence vault files are saved into tenant-isolated directory paths with SHA-256 cryptographic hashes.</li>
                    </ul>
                </div>
            </div>
        </section>

        <!-- SECTION 5: CUSTOMER DATA TRANSPARENCY -->
        <section id="data-transparency">
            <div class="section-header">
                <span class="tag">Privacy & Data Governance</span>
                <h2>Customer Data Transparency Disclosures</h2>
                <p>
                    Detailed disclosures outlining what customer data TrustAudit processes, where it is stored, 
                    how repositories are handled, and our data retention and deletion policies.
                </p>
            </div>

            <div class="transparency-list">
                <div class="transparency-card">
                    <h4>1. Types of Customer Data Processed <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>User registration details (name, work email, organization name, country), repository metadata (repo name, commit hashes), vulnerability scan findings, normalized issue descriptions, and user-uploaded compliance evidence.</p>
                </div>

                <div class="transparency-card">
                    <h4>2. Source Code & Repository Access (Ephemeral Only) <span class="status-badge badge-verified">Verified</span></h4>
                    <p>When scanning a Git repository, TrustAudit performs a transient shallow clone into a temporary sandboxed directory. The code is parsed for AST structures, dependency manifests, and secret patterns, and is <strong>immediately wiped from disk upon scan completion</strong>. Complete repositories are never permanently retained.</p>
                </div>

                <div class="transparency-card">
                    <h4>3. Security Scan Results & Finding Storage <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>Normalized finding summaries (CWE IDs, category, severity, masked snippet, file path and line number) are stored in the tenant store to enable drift tracking, baseline comparison, and remediation tracking.</p>
                </div>

                <div class="transparency-card">
                    <h4>4. Personal Information & Password Security <span class="status-badge badge-verified">Verified</span></h4>
                    <p>User passwords are encrypted using PBKDF2-HMAC-SHA256 with 100,000 iterations and unique 16-byte cryptographically random salts. Plaintext passwords are never stored or logged.</p>
                </div>

                <div class="transparency-card">
                    <h4>5. Uploaded Evidence Documents <span class="status-badge badge-verified">Verified</span></h4>
                    <p>Audit documents and screenshots uploaded to the Evidence Vault are stored in tenant-isolated volumes. Each file is fingerprinted with a SHA-256 cryptographic hash to prove document integrity during compliance audits.</p>
                </div>

                <div class="transparency-card">
                    <h4>6. Third-Party Subprocessors <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>Application hosting, container orchestration, and storage volumes are hosted on Render Cloud Infrastructure (United States regions). Open-source threat intelligence feeds are ingested directly from official public feeds (CISA KEV, NIST NVD, OSV.dev).</p>
                </div>

                <div class="transparency-card">
                    <h4>7. AI Processing & Training Policy <span class="status-badge badge-verified">Verified</span></h4>
                    <p>Core security scanning relies on local AST analyzers, Semgrep rules, and deterministic heuristic engines. Fix prompts provided for AI coding assistants are generated locally using static templates. <strong>No customer source code or personal data is transmitted to public AI training pools.</strong></p>
                </div>

                <div class="transparency-card">
                    <h4>8. Hosting & Processing Locations <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>All primary compute, API processing, and storage services are hosted in ISO 27001 and SOC 2-certified AWS / Render data center regions in the United States.</p>
                </div>

                <div class="transparency-card">
                    <h4>9. Data Retention Schedules <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>&bull; <strong>Source code:</strong> 0 days (deleted immediately after scan execution).<br>&bull; <strong>Scan findings & reports:</strong> Retained for 12 months to support historical compliance reporting.<br>&bull; <strong>Evidence Vault files:</strong> Retained until deleted by the customer or upon account closure.</p>
                </div>

                <div class="transparency-card">
                    <h4>10. Deletion & Account Termination Procedures <span class="status-badge badge-operational">Disclosed</span></h4>
                    <p>Customers can self-delete evidence items and projects at any time via the console. Complete organization account deletion and cryptographic purging of all associated findings and files can be requested by emailing <code>support@trustaudit.io</code>.</p>
                </div>
            </div>
        </section>

        <!-- SECTION 6: SCANNING AUTHORIZATION & SCOPE -->
        <section id="scanning-scope">
            <div class="section-header">
                <span class="tag">Security Scope</span>
                <h2>Scanning Authorization & Operational Scope</h2>
                <p>
                    Clear operational boundaries defining what TrustAudit scans, what permissions are required, 
                    and how customer consent is enforced before executing active security checks.
                </p>
            </div>

            <div class="card">
                <div class="grid-2">
                    <div>
                        <h4 style="color: #fff; margin: 0 0 8px;">GitHub Permissions & Scope</h4>
                        <p style="font-size: 13.5px;">When connecting GitHub, TrustAudit requests fine-grained read-only permissions (<code>contents:read</code>) to parse package manifests and configuration files. Optional <code>pull_requests:write</code> is requested solely to publish automated CI security comments on Pull Requests.</p>
                    </div>
                    <div>
                        <h4 style="color: #fff; margin: 0 0 8px;">Passive vs Active Security Testing</h4>
                        <p style="font-size: 13.5px;">Repository scanning is entirely passive static analysis. Website perimeter scanning defaults to non-intrusive passive TLS and HTTP header analysis. <strong>Active DAST scanning (Nuclei/OWASP ZAP) strictly requires explicit customer toggle authorization</strong> and verified ownership confirmation.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- SECTION 7: PLATFORM SECURITY & DISCLOSURE -->
        <section id="security-controls">
            <div class="section-header">
                <span class="tag">Platform Hardening</span>
                <h2>Internal Security Posture & Vulnerability Disclosure</h2>
                <p>
                    Technical controls protecting the TrustAudit platform and our coordinated vulnerability disclosure policy.
                </p>
            </div>

            <div class="grid-3" style="margin-bottom: 24px;">
                <div class="card">
                    <span class="tag">Transport</span>
                    <h3>Encryption in Transit</h3>
                    <p>All HTTP traffic is strictly redirected to HTTPS with TLS 1.3/1.2 enforced across all public endpoints. HSTS is preloaded with strong cipher suites.</p>
                    <span class="status-badge badge-verified">Verified TLS 1.3</span>
                </div>

                <div class="card">
                    <span class="tag">Storage</span>
                    <h3>Encryption at Rest</h3>
                    <p>Persistent storage volumes are encrypted using AES-256 at the host hypervisor layer. Uploaded compliance documents are verified using SHA-256 hashes.</p>
                    <span class="status-badge badge-verified">Verified AES-256</span>
                </div>

                <div class="card">
                    <span class="tag">Access Control</span>
                    <h3>Authentication & MFA</h3>
                    <p>Local authentication uses 100,000-round PBKDF2-HMAC-SHA256 password hashing. Multi-factor authentication (MFA) is currently on our product roadmap.</p>
                    <span class="status-badge badge-roadmap">MFA on Roadmap</span>
                </div>
            </div>

            <div class="card" id="contact">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 14px;">
                    <div>
                        <h3 style="margin: 0 0 6px;">Vulnerability Disclosure & Security Contact</h3>
                        <p style="margin: 0 0 12px; font-size: 14px;">
                            We welcome responsible reports from security researchers and customers. If you discover a security vulnerability 
                            affecting TrustAudit, please report it to our security response team:
                        </p>
                        <div style="display: flex; gap: 16px; align-items: center; font-size: 14px;">
                            <span>📧 <strong>Security Contact:</strong> <a href="mailto:security@trustaudit.io" style="color: var(--primary-light); text-decoration: none;">security@trustaudit.io</a></span>
                            <span>⏱️ <strong>Response SLA:</strong> Within 24 business hours</span>
                        </div>
                    </div>
                    <span class="status-badge badge-operational">Coordinated Disclosure</span>
                </div>
                <div style="margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border); font-size: 13px; color: var(--text-dim);">
                    <strong>Safe Harbor:</strong> TrustAudit will not pursue legal action against security researchers who conduct testing in good faith, 
                    avoid accessing customer data, avoid denial of service attacks, and provide reasonable time for remediation prior to public disclosure.
                </div>
            </div>
        </section>

        <!-- Footer -->
        <footer class="footer">
            <div class="footer-inner">
                <div class="footer-left">
                    <p>
                        <strong>Regulatory & Legal Disclaimer:</strong> TrustAudit provides automated technical security scanning, gap analysis, 
                        and compliance evidence management. TrustAudit does not issue formal regulatory certifications, accredited ISO 27001 certificates, 
                        or certified SOC 2 Type II reports, which require independent examination by accredited third-party certification bodies and CPA firms. 
                        Compliance with applicable laws (including DPDP Act 2023, GDPR, and sectoral regulations) remains the statutory responsibility of the customer organization.
                    </p>
                    <p>&copy; 2026 TrustAudit Security Platform. All rights reserved.</p>
                </div>
                <div class="footer-links">
                    <a href="/dashboard">App Dashboard</a>
                    <a href="#frameworks">Frameworks</a>
                    <a href="#data-transparency">Privacy Disclosures</a>
                    <a href="mailto:security@trustaudit.io">Security Contact</a>
                </div>
            </div>
        </footer>

    </div>

</body>
</html>
"""
