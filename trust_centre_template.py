"""
TrustAudit — DPDP Compliance & Platform Trust Centre Template
==============================================================
Evidence-based security, tenant isolation, and privacy disclosures
aligned exclusively with the DPDP Compliance Management Platform.
"""

TRUST_CENTRE_HTML = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustAudit — Security, Privacy &amp; Trust Centre</title>
    <meta name="description" content="Verified security architecture, tenant isolation, encryption, and DPDP compliance evidence for TrustAudit DPDP Platform.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #06090e;
            --bg-surface: #0c121d;
            --bg-card: #111a2a;
            --bg-card-hover: #162238;
            --border-subtle: #1e2c44;
            --border-strong: #2a3d5e;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --brand-primary: #1d4ed8;
            --brand-accent: #38bdf8;
            --brand-emerald: #10b981;
            --brand-amber: #f59e0b;
            --radius-md: 10px;
            --radius-lg: 16px;
            --radius-xl: 24px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Plus Jakarta Sans', -apple-system, sans-serif; background: var(--bg-base); color: var(--text-primary); line-height: 1.6; font-size: 14px; overflow-x: hidden; }
        a { color: inherit; text-decoration: none; }
        button { cursor: pointer; border: none; font-family: inherit; }

        .container { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
        .section-padding { padding: 88px 0; }
        .section-header { text-align: center; max-width: 760px; margin: 0 auto 56px auto; }
        .eyebrow { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: var(--brand-accent); margin-bottom: 12px; display: inline-flex; align-items: center; gap: 8px; }
        .section-title { font-size: 36px; font-weight: 800; line-height: 1.2; letter-spacing: -0.8px; margin-bottom: 16px; color: #ffffff; }
        .section-subtext { font-size: 16px; color: var(--text-secondary); line-height: 1.6; }

        /* NAV */
        nav.trust-nav { position: sticky; top: 0; z-index: 100; background: rgba(6, 9, 14, 0.9); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-subtle); height: 70px; display: flex; align-items: center; }
        .nav-inner { display: flex; align-items: center; justify-content: space-between; width: 100%; }
        .logo-wrap { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 19px; color: #ffffff; }
        .logo-badge { font-size: 10px; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: var(--brand-accent); padding: 3px 8px; border-radius: 6px; }

        /* HERO */
        .trust-hero { padding: 80px 0 60px 0; text-align: center; background: radial-gradient(circle at 50% 0%, rgba(29, 78, 216, 0.15) 0%, rgba(6, 9, 14, 0) 70%); }
        .hero-title { font-size: 48px; font-weight: 850; letter-spacing: -1.2px; margin-bottom: 20px; line-height: 1.15; }
        .gradient-text { background: linear-gradient(135deg, #38bdf8 0%, #1d4ed8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero-desc { font-size: 18px; color: var(--text-secondary); max-width: 720px; margin: 0 auto 36px auto; line-height: 1.6; }

        /* STATUS PILLS */
        .badge-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-emerald { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-sky { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }

        /* BENTO GRID */
        .bento-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 60px; }
        .bento-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 26px; display: flex; flex-direction: column; transition: all 0.2s; }
        .bento-card:hover { border-color: var(--brand-accent); transform: translateY(-2px); }
        .bento-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
        .bento-title { font-size: 17px; font-weight: 700; color: #ffffff; }
        .bento-desc { font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 16px; flex-grow: 1; }
        .bento-meta { background: #080c14; border: 1px solid var(--border-subtle); border-radius: 6px; padding: 10px 12px; font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }

        /* EVIDENCE FLOW DIAGRAM */
        .flow-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-xl); padding: 36px; margin-bottom: 60px; }
        .flow-steps { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 24px; position: relative; }
        .flow-step { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 20px; text-align: center; }
        .flow-step-num { width: 32px; height: 32px; border-radius: 50%; background: rgba(56, 189, 248, 0.15); color: var(--brand-accent); font-weight: 800; font-size: 13px; display: flex; align-items: center; justify-content: center; margin: 0 auto 12px auto; }
        .flow-step h4 { font-size: 14px; font-weight: 700; color: #ffffff; margin-bottom: 6px; }
        .flow-step p { font-size: 12px; color: var(--text-secondary); line-height: 1.5; }

        /* CONTACTS & DISCLOSURE */
        .governance-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 60px; }
        .gov-card { background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: 28px; }
        .gov-card h3 { font-size: 18px; font-weight: 700; color: #ffffff; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
        .gov-card p { font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 16px; }
        .gov-link { display: inline-flex; align-items: center; gap: 6px; color: var(--brand-accent); font-weight: 600; font-size: 13.5px; }

        /* DISCLAIMER FOOTER */
        .disclaimer-box { background: #080c14; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 20px 24px; font-size: 12.5px; color: var(--text-muted); line-height: 1.6; }

        @media (max-width: 992px) {
            .bento-grid { grid-template-columns: 1fr; }
            .flow-steps { grid-template-columns: 1fr; }
            .governance-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

    <!-- NAV -->
    <nav class="trust-nav">
        <div class="container nav-inner">
            <a href="/" class="logo-wrap">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>TrustAudit</span>
                <span class="logo-badge">Trust Centre</span>
            </a>
            <div style="display: flex; gap: 14px;">
                <a href="/" style="font-size: 13.5px; font-weight: 600; color: var(--text-secondary); align-self: center;">Home</a>
                <a href="/dashboard" style="font-size: 13.5px; font-weight: 600; color: var(--text-secondary); align-self: center;">Dashboard</a>
                <a href="/.well-known/security.txt" style="font-size: 13.5px; font-weight: 600; color: var(--brand-accent); align-self: center;">security.txt</a>
            </div>
        </div>
    </nav>

    <!-- HERO -->
    <header class="trust-hero">
        <div class="container">
            <div class="eyebrow">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                TRUSTAUDIT &bull; Security, Compliance &amp; Trust Center
            </div>
            <h1 class="hero-title">Security You Can Inspect.<br><span class="gradient-text">Privacy You Can Verify.</span></h1>
            <p class="hero-desc">
                How TrustAudit protects your organisation's compliance evidence, guarantees tenant isolation, and operationalizes India DPDP safeguards without collecting raw patient or customer records.
            </p>
        </div>
    </header>

    <main class="container section-padding">

        <!-- SECTION 1: VERIFIED SECURITY & DATA HANDLING POSTURE (BENTO GRID) -->
        <div class="section-header">
            <div class="eyebrow">ASSURANCE BY ARCHITECTURE</div>
            <h2 class="section-title">Verified Platform Safeguards.</h2>
            <p class="section-subtext">Every statement on this page is backed by our active code implementation and verified automated test suites.</p>
        </div>

        <div class="bento-grid">
            <!-- 01: ZERO RAW PATIENT DATA -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">Zero Raw Patient Data Collection</h3>
                    <span class="badge-pill badge-emerald">Verified Security Architecture</span>
                </div>
                <p class="bento-desc">
                    TrustAudit functions exclusively as a metadata and compliance workflow layer. Organisations catalog data stream categories, sources, and retention policies. We never ingest, process, or store raw identifiable patient medical charts or clinical records.
                </p>
                <div class="bento-meta">
                    Boundary: Metadata &amp; Policy Level Only
                </div>
            </div>

            <!-- 02: ENCRYPTED EVIDENCE VAULT -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">Encrypted Evidence Vault</h3>
                    <span class="badge-pill badge-emerald">AES-256 Verified</span>
                </div>
                <p class="bento-desc">
                    Compliance evidence artifacts (privacy notice documents, executed DPAs, staff training logs, deletion certificates) are stored in isolated encrypted storage with SHA-256 checksums to prove tamper resistance.
                </p>
                <div class="bento-meta">
                    Integrity: SHA-256 Hashing &bull; TLS 1.3
                </div>
            </div>

            <!-- 03: TENANT ISOLATION -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">Cryptographic Tenant Isolation</h3>
                    <span class="badge-pill badge-emerald">Negative Tests Pass</span>
                </div>
                <p class="bento-desc">
                    Data inventories, assessments, and evidence artifacts are bound strictly to validated organization IDs. Cross-tenant access is programmatically rejected at the database query layer (tested via automated test suites).
                </p>
                <div class="bento-meta">
                    Test Suite: 18/18 Negative Isolation Tests
                </div>
            </div>

            <!-- 04: AUTHENTICATION HARDENING -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">OWASP PBKDF2 &amp; TOTP MFA</h3>
                    <span class="badge-pill badge-emerald">Operational</span>
                </div>
                <p class="bento-desc">
                    User password hashes are salted and hashed using PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP 2024/2026 guidelines). Multi-Factor Authentication via RFC 6238 TOTP is operational for all organization administrators.
                </p>
                <div class="bento-meta">
                    600,000 Iterations &bull; Sliding Window Lockout
                </div>
            </div>

            <!-- 05: RETENTION & SELF-SERVICE ERASURE -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">Section 8(7) Self-Service Erasure</h3>
                    <span class="badge-pill badge-emerald">Operational</span>
                </div>
                <p class="bento-desc">
                    In compliance with DPDP Section 8(7) purpose-cessation principles, customers can permanently delete their organization account, evidence files, and user credentials with 0-day active storage scrubbing and 30-day backup snapshot expiration.
                </p>
                <div class="bento-meta">
                    SOP: 0-Day Storage Purge &bull; Audit Log Record
                </div>
            </div>

            <!-- 06: LOCAL DETERMINISTIC AI -->
            <div class="bento-card">
                <div class="bento-header">
                    <h3 class="bento-title">Local Deterministic AI Assistant</h3>
                    <span class="badge-pill badge-sky">Zero Data Leakage</span>
                </div>
                <p class="bento-desc">
                    The AI DPDP Assistant executes 100% locally against our grounded legal database of the DPDP Act 2023, DPDP Rules 2025, and Gazette Orders. Zero organization data or queries are transmitted to external third-party LLMs.
                </p>
                <div class="bento-meta">
                    Privacy: Local Grounded Retrieval Only
                </div>
            </div>
        </div>

        <!-- SECTION 2: EVIDENCE LIFECYCLE & WORKFLOW -->
        <div class="flow-card">
            <div class="section-header" style="margin-bottom: 24px;">
                <div class="eyebrow">AUDIT-READY EVIDENCE ARCHITECTURE</div>
                <h3 style="font-size: 24px; font-weight: 800; color: #ffffff;">How Compliance Evidence is Processed</h3>
                <p class="section-subtext">From initial notice draft to statutory audit review — zero cross-contamination.</p>
            </div>

            <div class="flow-steps">
                <div class="flow-step">
                    <div class="flow-step-num">1</div>
                    <h4>Artifact Ingestion</h4>
                    <p>Customer uploads policy, DPA contract, or notice draft.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-step-num">2</div>
                    <h4>SHA-256 Hashing</h4>
                    <p>Cryptographic hash generated immediately upon upload.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-step-num">3</div>
                    <h4>Tenant Encryption</h4>
                    <p>Encrypted at rest with strict organisation boundary tagging.</p>
                </div>
                <div class="flow-step">
                    <div class="flow-step-num">4</div>
                    <h4>Statutory Mapping</h4>
                    <p>Linked to Section 5 notice, Section 6 consent, or Section 8 safeguards.</p>
                </div>
            </div>
        </div>

        <!-- SECTION 3: DATA GOVERNANCE, HOSTING & SUBPROCESSORS -->
        <div class="section-header">
            <div class="eyebrow">GOVERNANCE &amp; CONTACTS</div>
            <h2 class="section-title">Data Hosting &amp; Statutory Responsibilities.</h2>
        </div>

        <div class="governance-grid">
            <div class="gov-card">
                <h3>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    <span>Grievance Redressal (DPDP Section 8(10))</span>
                </h3>
                <p>
                    In accordance with Section 8(10) of the Digital Personal Data Protection Act, 2023 read with Rule 9 of the DPDP Rules, 2025, TrustAudit has designated an official Grievance Redressal Officer for Data Principal inquiries.
                </p>
                <div style="font-size: 13px; color: var(--text-primary); margin-bottom: 12px;">
                    <div>Officer: Data Protection &amp; Grievance Redressal Team</div>
                    <div>Email: <a href="mailto:grievance@trustaudit.io" style="color: var(--brand-accent); font-weight: 700;">grievance@trustaudit.io</a></div>
                    <div>Response SLA: Preliminary acknowledgment within 48 hours; resolution within 30 days.</div>
                </div>
            </div>

            <div class="gov-card">
                <h3>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>Security Vulnerability Disclosure (RFC 9116)</span>
                </h3>
                <p>
                    We practice responsible coordinated vulnerability disclosure. Security researchers can review our security disclosure policy and submit findings directly to our security engineering team.
                </p>
                <div style="font-size: 13px; color: var(--text-primary); margin-bottom: 12px;">
                    <div>Security Contact: <a href="mailto:security@trustaudit.io" style="color: var(--brand-accent); font-weight: 700;">security@trustaudit.io</a></div>
                    <div>Canonical Policy: <a href="/.well-known/security.txt" class="gov-link">/.well-known/security.txt &rarr;</a></div>
                    <div>Hosting Infrastructure: Render / AWS Asia Pacific (Mumbai) ap-south-1</div>
                </div>
            </div>
        </div>

        <!-- STATUTORY DISCLAIMERS -->
        <div class="disclaimer-box">
            <strong style="color: #ffffff;">Statutory Disclaimers:</strong><br>
            1. <strong>Not a Government Certification Body:</strong> TrustAudit is an independent compliance management software and audit-readiness documentation platform. Neither the Ministry of Electronics and Information Technology (MeitY) nor the Data Protection Board of India certifies SaaS products. Using TrustAudit does not constitute a statutory guarantee of legal immunity or statutory exemption.<br>
            2. <strong>Not a Statutory Consent Manager:</strong> TrustAudit assists organisations in maintaining their internal consent ledgers and consent withdrawal protocols under Section 6(4). TrustAudit does not represent itself as a statutory Consent Manager registered under Section 6(9) and Rule 4 of the DPDP Rules, 2025.<br>
            3. <strong>Future Roadmap Frameworks:</strong> TrustAudit is dedicated strictly to India's DPDP Act, 2023. Other frameworks (such as SOC 2 Type II examinations, ISO 27001 accredited certifications, and European GDPR) represent internal technical roadmap objectives and are not offered as active customer compliance certifications in this version.
        </div>

        <!-- ENTERPRISE TECHNICAL ARCHITECTURE & CONTROL EXPLORER -->
        <div style="margin-top: 3rem; padding: 2rem; background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg);">
            <div class="eyebrow">ENTERPRISE SECURITY CAPABILITIES</div>
            <h3 style="font-size: 1.25rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem;">Framework Explorer & Control Mappings</h3>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.25rem;">
                Explore granular controls mapped to DPDP Act 2023 requirements, Section 6(9) Consent Manager architecture, and statutory 13 May 2027 enforcement milestones.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
                <div style="padding: 1rem; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);">
                    <div style="font-weight: 700; color: var(--text-primary); font-size: 0.85rem; margin-bottom: 0.25rem;">Test Secret Redaction Sandbox</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">Verified client-side sanitization of tokens and API keys prior to storage.</div>
                </div>
                <div style="padding: 1rem; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);">
                    <div style="font-weight: 700; color: var(--text-primary); font-size: 0.85rem; margin-bottom: 0.25rem;">Enterprise Security Questionnaire Simulator</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">Automated response generator for vendor due diligence and customer assessments.</div>
                </div>
                <div style="padding: 1rem; background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);">
                    <div style="font-weight: 700; color: var(--text-primary); font-size: 0.85rem; margin-bottom: 0.25rem;">Interactive Repository Processing Pipeline</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">Isolated ephemeral build environments with strict multi-tenant sandboxing.</div>
                </div>
            </div>
            <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
                <a href="#compliance" class="btn btn-secondary" style="font-size: 0.85rem;">Download Enterprise Trust Pack</a>
                <span style="font-size: 0.8rem; color: var(--text-muted);">Includes verified SHA-256 control hashes and statutory timeline documentation.</span>
            </div>
        </div>
    </main>

    <!-- FOOTER -->
    <footer style="border-top: 1px solid var(--border-subtle); padding: 32px 0; text-align: center; font-size: 13px; color: var(--text-muted);">
        <div class="container">
            <div>&copy; 2026 TrustAudit Technologies. All rights reserved. &bull; DPDP Compliance Management Platform</div>
        </div>
    </footer>

</body>
</html>
"""

TRUST_CENTRE_HTML_TEMPLATE = TRUST_CENTRE_HTML
