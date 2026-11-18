"""
TrustAudit Risk Prioritization Engine — "Fix These First".

Calculates practical business risk and prioritizes top 3–5 actionable security fixes
for startup founders and developers without overwhelming them with raw alert noise.

Evaluates:
- Severity (Critical, High, Medium, Low)
- Exploitability & Attack Surface (Public Internet vs Internal vs Repository)
- Business Impact & Data Exposure Risk
- Detection Confidence (Confirmed vs Likely)
- Remediation Difficulty & Step-by-Step Code Guides
- Verified AI Fix Prompts (Cursor / Claude Code / Copilot)
"""

from typing import Any, Dict, List, Optional


def calculate_business_risk_score(finding: Dict[str, Any]) -> int:
    """
    Computes a practical 0-100 Business Risk Score.
    Weighted by: Severity (40%), Exploitability/Exposure (35%), Confidence (15%), Impact (10%).
    """
    sev = (finding.get("severity") or "MEDIUM").upper()
    sev_weights = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 18, "LOW": 8, "INFO": 2}
    base_score = sev_weights.get(sev, 15)

    # Exposure & Exploitability
    cat = (finding.get("category") or "").lower()
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()

    exposure_score = 15
    if "secret" in cat or "credential" in title or "api key" in title:
        exposure_score = 35  # Instant critical credential risk
    elif "rce" in title or "command" in title or "sql" in title:
        exposure_score = 30  # Active injection
    elif "idor" in title or "tenant" in cat or "rls" in title:
        exposure_score = 28  # Multi-tenant data breach risk
    elif "plaintext http" in title or "hsts" in title:
        exposure_score = 22  # Public network exposure
    elif "cors" in title or "csrf" in title or "xss" in title:
        exposure_score = 20  # Client-side exploitability
    elif "header" in cat or "cookie" in cat:
        exposure_score = 15  # Defense-in-depth

    # Confidence
    conf = (finding.get("confidence") or "CONFIRMED").upper()
    conf_weights = {"CONFIRMED": 15, "LIKELY": 10, "POTENTIAL": 5, "INFORMATIONAL": 2}
    conf_score = conf_weights.get(conf, 10)

    # Impact bonus
    impact_score = 10 if sev in ("CRITICAL", "HIGH") else 5

    total = base_score + exposure_score + conf_score + impact_score
    return min(100, max(10, total))


def create_fix_card(finding: Dict[str, Any], rank: int = 1) -> Dict[str, Any]:
    """Generates a comprehensive fix card for a single finding."""
    risk_score = calculate_business_risk_score(finding)
    why_matters = _generate_why_it_matters(finding)
    what_is_wrong = finding.get("description") or finding.get("title") or "Security vulnerability detected."
    what_could_happen = _generate_what_could_happen(finding)
    what_to_do = _generate_what_to_do(finding)
    code_example = _generate_code_example(finding)
    how_to_verify = _generate_how_to_verify(finding)
    ai_prompt = _generate_ai_coding_prompt(finding)

    location = f"{finding.get('file', finding.get('url', 'Target'))}:{finding.get('line') or ''}".rstrip(":")
    cat = (finding.get("category") or "web").lower()
    exposure = "Internet Exposed" if any(k in cat for k in ("web", "perimeter", "network", "api")) else "Source Code"

    return {
        "rank": rank,
        "id": finding.get("id") or finding.get("finding_id"),
        "title": finding.get("title", "Security Vulnerability"),
        "severity": (finding.get("severity") or "HIGH").upper(),
        "confidence": (finding.get("confidence") or "CONFIRMED").upper(),
        "risk_score": risk_score,
        "category": finding.get("category", "code_security"),
        "exposure": exposure,
        "location": location,
        "file": finding.get("file"),
        "line": finding.get("line"),
        "evidence": finding.get("evidence", ""),
        "what_is_wrong": what_is_wrong,
        "why_this_matters": why_matters,
        "what_could_happen": what_could_happen,
        "what_to_do": what_to_do,
        "code_example": code_example,
        "how_to_verify": how_to_verify,
        "ai_prompt": ai_prompt,
        "remediation": finding.get("remediation", ""),
        "cwe": finding.get("cwe") or finding.get("cwe_id") or "CWE-200",
    }


def prioritize_findings(findings: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    """
    Ranks findings by calculated Business Risk Score, exploitability, and confidence.
    Returns the top prioritized list with plain-language action cards.
    """
    if not findings:
        return []

    sorted_findings = sorted(findings, key=calculate_business_risk_score, reverse=True)
    selected = sorted_findings[:limit]

    prioritized_cards = [create_fix_card(f, rank=idx) for idx, f in enumerate(selected, 1)]
    return prioritized_cards


def _generate_why_it_matters(finding: Dict[str, Any]) -> str:
    """Generates plain-language explanation of risk for founders and engineering leads."""
    title = (finding.get("title") or "").lower()
    cat = (finding.get("category") or "").lower()
    desc = finding.get("description") or ""

    if "secret" in cat or "credential" in title or "key" in title or "token" in title:
        return "Exposed API keys or credentials allow attackers to authenticate directly to your cloud infrastructure, access customer databases, and incur unexpected bills."
    if "sql" in title:
        return "Unsanitized database inputs allow attackers to bypass login screens, extract entire customer tables, or delete backend databases."
    if "command" in title or "exec" in title or "rce" in title:
        return "Remote command execution allows an adversary to run arbitrary system commands on your production server and compromise the entire host."
    if "rls" in title or "supabase" in title or "tenant" in cat:
        return "Missing Row Level Security allows authenticated users from Tenant A to query and modify sensitive customer data belonging to Tenant B."
    if "hsts" in title or "plaintext http" in title:
        return "Users accessing your service on public Wi-Fi or networks can have their session cookies and login traffic intercepted via SSL-strip downgrade attacks."
    if "cors" in title:
        return "A permissive wildcard CORS policy permits external malicious websites to make authenticated AJAX requests to your backend on behalf of logged-in users."
    if "csp" in title or "content-security-policy" in title:
        return "Missing Content Security Policy enables attackers to execute injected JavaScript and exfiltrate session credentials during Cross-Site Scripting (XSS)."
    if "cookie" in cat or "httponly" in title or "samesite" in title:
        return "Session cookies without HttpOnly flags can be stolen by malicious third-party browser scripts via `document.cookie`."
    if "dependency" in cat or "cve" in title:
        return "This third-party package has a known publicly disclosed vulnerability with automated exploits actively available in the wild."
    if "prompt" in title or "mcp" in cat:
        return "Adversarial tool descriptions or unvalidated prompts can hijack AI agent decision loops to execute unauthorized external actions."

    return desc or "Weakens defense-in-depth boundaries and creates an exploitable initial access vector for attackers."


def _generate_what_could_happen(finding: Dict[str, Any]) -> str:
    """Explains the worst-case technical and business impact."""
    title = (finding.get("title") or "").lower()
    cat = (finding.get("category") or "").lower()

    if "secret" in cat or "key" in title:
        return "Full compromise of the linked cloud service (e.g. AWS, OpenAI, Stripe) and exfiltration of production customer records."
    if "sql" in title:
        return "Unauthorized extraction of customer passwords, PII, and financial transaction records directly from SQL storage."
    if "hsts" in title or "plaintext" in title:
        return "Session hijacking and credential sniffing over untrusted public networks."
    if "cors" in title:
        return "Cross-site data theft and unauthorized user actions executed through malicious browser tabs."
    if "tenant" in cat or "rls" in title:
        return "Cross-tenant data leakage leading to major privacy violations and customer trust collapse."

    return "Service degradation, unauthorized data access, or escalation to full system compromise."


def _generate_what_to_do(finding: Dict[str, Any]) -> str:
    """Step-by-step developer remediation instructions."""
    rem = finding.get("remediation")
    if rem:
        return rem

    title = (finding.get("title") or "").lower()
    if "secret" in title:
        return "1. Invalidate and rotate the exposed API key in the provider console immediately.\n2. Move secrets to environment variables (`.env`).\n3. Add `.env` to `.gitignore`."
    if "hsts" in title:
        return "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` header to all HTTPS responses in your reverse proxy (Nginx/Cloudflare)."
    if "sql" in title:
        return "Replace raw string formatting with parameterized database query placeholders (e.g. `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`)."
    if "cors" in title:
        return "Replace `Access-Control-Allow-Origin: *` with an explicit list of your authorized frontend origins."

    return "Inspect the referenced file and apply parameter validation and secure configuration headers."


def _generate_code_example(finding: Dict[str, Any]) -> str:
    """Generates standard code/configuration example snippet."""
    title = (finding.get("title") or "").lower()

    if "hsts" in title:
        return "# Nginx Configuration:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
    if "csp" in title:
        return "# Content-Security-Policy Header:\nContent-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline';"
    if "cors" in title:
        return "# Express.js / Node.js CORS Configuration:\napp.use(cors({ origin: ['https://app.yourcompany.com'], credentials: true }));"
    if "sql" in title:
        return "# Python Parameterized Query:\ncursor.execute('SELECT * FROM users WHERE email = %s', (email,))"
    if "cookie" in title:
        return "# Secure Cookie Flag:\nSet-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Lax; Path=/;"
    if "secret" in title:
        return "# .env file:\nOPENAI_API_KEY=sk_live_...\n# Code usage:\nimport os\napi_key = os.environ.get('OPENAI_API_KEY')"

    return "# Apply defensive security configuration\n# Validate all inputs before processing"


def _generate_how_to_verify(finding: Dict[str, Any]) -> str:
    """Actionable verification instruction for the developer."""
    fid = finding.get("id") or finding.get("finding_id") or ""
    return "Click '[Verify Fix Now]' in TrustAudit. The platform will trigger an automated targeted rescan to verify that the vulnerability is completely gone."


def _generate_ai_coding_prompt(finding: Dict[str, Any]) -> str:
    """Generates a prompt ready to copy-paste into Cursor, Claude Code, or GitHub Copilot."""
    title = finding.get("title", "Security Vulnerability")
    file_p = finding.get("file", "the codebase")
    line = finding.get("line")
    line_str = f" around line {line}" if line else ""
    evidence = finding.get("evidence", "")

    prompt = (
        f"Fix security issue: '{title}' in `{file_p}`{line_str}.\n"
        f"Evidence: `{evidence}`.\n"
        f"Please apply defensive programming best practices, secure parameterization, and appropriate error handling to remediate this issue cleanly."
    )
    return prompt
