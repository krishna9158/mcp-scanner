"""
AI-Coded Application Security Analyzer (TrustAudit Platform).

TrustAudit-owned deterministic security rules for common AI-generated coding patterns:
- Insecure Authentication & Missing Authorization
- Hardcoded Credentials & Frontend Secret Leakage
- Insecure CORS & Overly Permissive Policies
- Debug / Admin Endpoints Exposed
- Weak JWT Validation & Insecure Cryptography
- Missing Rate Limiting on Sensitive Routes
- Injection Flaws (SQLi, Command Injection, XSS, SSRF, Path Traversal)
- Insecure File Upload & Unsafe Deserialization
- Prototype Pollution & Sensitive Information Logging
- Supabase & Firebase Tenancy / Security Rules Flaws

All findings from this engine are tagged as "AI-Code Security Pattern".
"""

import os
import re
from typing import Any, Dict, List

AI_APPSEC_RULES = [
    # 1. Supabase RLS & Service Role Key
    {
        "id": "AI-SUPABASE-MISSING-RLS",
        "name": "Missing Supabase Row Level Security (RLS)",
        "category": "tenancy",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)create\s+table\s+(?:public\.)?(\w+)(?![\s\S]*?enable\s+row\s+level\s+security)',
        ],
        "message": "Supabase table created without explicitly enabling Row Level Security (ALTER TABLE ... ENABLE ROW LEVEL SECURITY).",
        "remediation": "Add `ALTER TABLE <table_name> ENABLE ROW LEVEL SECURITY;` and define explicit tenant/user policies.",
        "cwe": "CWE-284",
    },
    {
        "id": "AI-SUPABASE-ANON-KEY-EXPOSURE",
        "name": "Service Role Key Exposed in Client-Side Code",
        "category": "secrets",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)\bSUPABASE_SERVICE_ROLE_KEY\b\s*[:=]\s*["\'][^"\']+["\']',
            r'(?i)createClient\s*\([^,]+,\s*process\.env\.SUPABASE_SERVICE_ROLE_KEY\)',
            r'(?i)NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
        ],
        "message": "The Supabase service_role key bypasses all RLS policies and must never be referenced in client-side code or public variables.",
        "remediation": "Use `SUPABASE_ANON_KEY` for client components and keep `SUPABASE_SERVICE_ROLE_KEY` in secure server-only environments.",
        "cwe": "CWE-798",
    },
    # 2. Firebase Rules
    {
        "id": "AI-FIREBASE-PUBLIC-RULES",
        "name": "Overly Permissive Firebase Security Rules",
        "category": "authorization",
        "severity": "CRITICAL",
        "patterns": [
            r'allow\s+read,\s*write\s*:\s*if\s+true\s*;',
            r'allow\s+write\s*:\s*if\s+true\s*;',
        ],
        "message": "Firebase security rules grant unrestricted public read/write access to any client without authentication.",
        "remediation": "Restrict access: `allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`",
        "cwe": "CWE-284",
    },
    # 3. Next.js Server Actions & Unprotected Mutations
    {
        "id": "AI-CODE-NEXTJS-UNPROTECTED-SERVER-ACTION",
        "name": "Unauthenticated Server Action with State Mutation",
        "category": "authorization",
        "severity": "HIGH",
        "patterns": [
            r'["\']use server["\'];\s*(?:export\s+)?async\s+function\s+\w+\([^)]*\)\s*\{(?![^}]*?(?:auth|getSession|currentUser|verifySession|checkAuth))',
        ],
        "message": "Next.js Server Action executes backend operations without verifying user session at entry.",
        "remediation": "Validate user session at the start of every Server Action: `const session = await auth(); if (!session) throw new Error('Unauthorized');`",
        "cwe": "CWE-306",
    },
    # 4. Insecure CORS
    {
        "id": "AI-CODE-API-UNSAFE-CORS",
        "name": "Overly Permissive CORS Configuration with Wildcard",
        "category": "authentication",
        "severity": "HIGH",
        "patterns": [
            r'(?i)Access-Control-Allow-Origin["\']?\s*,\s*["\']\*["\']',
            r'(?i)cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']\s*,\s*credentials\s*:\s*true',
            r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]',
        ],
        "message": "CORS configuration uses wildcard origin (`*`), allowing any third-party malicious website to make cross-origin requests.",
        "remediation": "Specify an explicit allowlist of approved frontend origins rather than `*`.",
        "cwe": "CWE-942",
    },
    # 5. SQL Injection via String Interpolation
    {
        "id": "AI-CODE-SQL-INJECTION-INTERPOLATION",
        "name": "SQL Query Formatted with String Interpolation",
        "category": "code_security",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)(?:execute|query|cursor\.execute)\s*\(\s*f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\{',
            r'(?i)(?:execute|query)\s*\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\+\s*(?:req|request|params)',
            r'(?i)db\.raw\s*\(\s*`[^`]*\$\{',
        ],
        "message": "Raw SQL query constructed using string formatting or template literals with dynamic variables, creating SQL injection vulnerabilities.",
        "remediation": "Use parameterized queries (e.g. `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`) or an ORM.",
        "cwe": "CWE-89",
    },
    # 6. Command Injection
    {
        "id": "AI-CODE-COMMAND-INJECTION",
        "name": "OS Command Execution with Dynamic String",
        "category": "code_security",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)os\.system\s*\(\s*f?["\'].*\{',
            r'(?i)subprocess\.(?:Popen|run|call)\s*\(\s*f?["\'].*\{.*shell\s*=\s*True',
            r'(?i)child_process\.(?:exec|execSync)\s*\(\s*`.*\$',
        ],
        "message": "Executing OS shell commands with dynamically concatenated strings allows remote command execution if input is user-controllable.",
        "remediation": "Pass commands as argument arrays with `shell=False` or use `execFile` without shell interpolation.",
        "cwe": "CWE-78",
    },
    # 7. SSRF (Server-Side Request Forgery)
    {
        "id": "AI-CODE-SSRF-UNVALIDATED-URL",
        "name": "Server-Side Request Forgery (SSRF) Vector",
        "category": "code_security",
        "severity": "HIGH",
        "patterns": [
            r'(?i)requests\.(?:get|post)\s*\(\s*(?:request\.(?:args|form|json)|req\.(?:query|body))\.',
            r'(?i)fetch\s*\(\s*(?:req\.(?:query|body)|params)\.',
            r'(?i)urllib\.request\.urlopen\s*\(\s*(?:req|request)\.',
            r'(?i)axios\.(?:get|post)\s*\(\s*(?:req\.query|req\.body)\.',
        ],
        "message": "Server issues outbound HTTP requests directly to URLs provided in untrusted user request parameters.",
        "remediation": "Validate target URLs against an explicit domain allowlist and block requests to internal IP addresses (127.0.0.1, 169.254.169.254, RFC1918).",
        "cwe": "CWE-918",
    },
    # 8. Path Traversal
    {
        "id": "AI-CODE-PATH-TRAVERSAL",
        "name": "Unsanitized File Path Access (Path Traversal)",
        "category": "code_security",
        "severity": "HIGH",
        "patterns": [
            r'(?i)open\s*\(\s*(?:os\.path\.join\([^)]*|f["\'][^"\']*\{)(?:req|request)\.',
            r'(?i)fs\.(?:readFileSync|readFile|createReadStream)\s*\(\s*(?:path\.join\([^)]*|`[^`]*\$\{)(?:req|params)\.',
            r'(?i)res\.sendFile\s*\(\s*(?:req\.(?:params|query)\.|`[^`]*\$\{)',
        ],
        "message": "Reading local files using user-supplied file names or paths without canonicalization enables directory traversal (e.g. `../../etc/passwd`).",
        "remediation": "Resolve absolute paths with `os.path.realpath` / `path.resolve` and verify the path remains within the intended directory base.",
        "cwe": "CWE-22",
    },
    # 9. Cross-Site Scripting (XSS)
    {
        "id": "AI-CODE-DOM-XSS",
        "name": "Direct HTML Injection / DOM XSS Pattern",
        "category": "code_security",
        "severity": "HIGH",
        "patterns": [
            r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitize)',
            r'\.innerHTML\s*=\s*(?:req|params|\w+\.(?:query|body))',
            r'v-html\s*=\s*["\'](?!sanitize)',
        ],
        "message": "Rendering unescaped HTML strings directly into the DOM allows Cross-Site Scripting (XSS).",
        "remediation": "Sanitize HTML using DOMPurify or use standard text content bindings (`innerText` / JSX expressions).",
        "cwe": "CWE-79",
    },
    # 10. Weak JWT Validation
    {
        "id": "AI-CODE-WEAK-JWT-VERIFICATION",
        "name": "Weak JWT Token Validation (None Algorithm / Missing Verify)",
        "category": "authentication",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False',
            r'(?i)jwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*["\']none["\']',
            r'(?i)jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature["\']?\s*:\s*False',
        ],
        "message": "JWT token decoding explicitly disables signature verification, allowing forged tokens to impersonate any identity.",
        "remediation": "Enforce signature verification with explicit allowed algorithms: `jwt.verify(token, secret, { algorithms: ['HS256', 'RS256'] })`.",
        "cwe": "CWE-347",
    },
    # 11. Debug Mode / Admin Routes Exposed
    {
        "id": "AI-CODE-DEBUG-MODE-ENABLED",
        "name": "Production Debug Mode Enabled",
        "category": "misconfiguration",
        "severity": "HIGH",
        "patterns": [
            r'(?i)app\.run\s*\([^)]*debug\s*=\s*True',
            r'(?i)^\s*DEBUG\s*=\s*True\b',
        ],
        "message": "Framework debug mode is explicitly set to True, exposing detailed stack traces, environment variables, or interactive debuggers.",
        "remediation": "Read debug configuration from environment variables (e.g. `DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'`) and disable in production.",
        "cwe": "CWE-489",
    },
    # 12. Unsafe Deserialization
    {
        "id": "AI-CODE-UNSAFE-DESERIALIZATION",
        "name": "Insecure Object Deserialization",
        "category": "code_security",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)pickle\.loads\s*\(',
            r'(?i)_pickle\.loads\s*\(',
            r'(?i)yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader|SafeLoader)',
        ],
        "message": "Deserializing untrusted data with pickle or unconstrained yaml.load can lead to arbitrary code execution.",
        "remediation": "Use safe data serialization formats like JSON, protocol buffers, or `yaml.safe_load()`.",
        "cwe": "CWE-502",
    },
    # 13. Prototype Pollution
    {
        "id": "AI-CODE-PROTOTYPE-POLLUTION",
        "name": "Potential Prototype Pollution Vector",
        "category": "code_security",
        "severity": "MEDIUM",
        "patterns": [
            r'(?i)Object\.assign\s*\(\s*\{\}\s*,\s*(?:req\.body|req\.query|params)\)',
            r'(?i)target\[key\]\s*=\s*source\[key\]',
        ],
        "message": "Merging unvalidated user objects directly into targets without filtering `__proto__` or `constructor` properties.",
        "remediation": "Use `Object.create(null)` for key-value maps or validate against prototype modification keys.",
        "cwe": "CWE-1321",
    },
    # 14. Sensitive Information Logging
    {
        "id": "AI-CODE-SENSITIVE-DATA-LOGGING",
        "name": "Sensitive Credentials Logged to Output",
        "category": "code_security",
        "severity": "LOW",
        "patterns": [
            r'(?i)(?:console\.log|logger\.(?:info|debug|error)|print)\s*\([^)]*(?:password|api_key|secret_key|auth_token)\s*[,:]',
        ],
        "message": "Sensitive authentication keys or passwords appear to be printed to console/log files.",
        "remediation": "Redact or exclude sensitive credentials prior to writing log statements.",
        "cwe": "CWE-532",
    },
    # 15. Weak Cryptography
    {
        "id": "AI-CODE-WEAK-CRYPTOGRAPHY",
        "name": "Use of Broken Cryptographic Algorithm",
        "category": "code_security",
        "severity": "LOW",
        "patterns": [
            r'(?i)CryptoJS\.(?:MD5|SHA1|DES|RC4)\b',
            r'(?i)hashlib\.(?:md5|sha1)\s*\(',
        ],
        "message": "Use of obsolete or broken cryptographic hashing/encryption algorithms.",
        "remediation": "Upgrade to modern cryptographic algorithms such as SHA-256, AES-GCM, or bcrypt/Argon2 for passwords.",
        "cwe": "CWE-327",
    },
]


def scan_ai_application_security(folder: str) -> List[Dict[str, Any]]:
    """
    Recursively scans application codebase for AI-Code Security Patterns.
    """
    findings = []
    skip_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", ".pytest_cache", ".next", "__pycache__"}

    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
        for f in files:
            if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".sql", ".json", ".rules", ".prisma", ".yaml", ".yml")):
                filepath = os.path.join(root, f)
                rel_path = os.path.relpath(filepath, folder).replace("\\", "/")

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read(500000)
                except Exception:
                    continue

                for rule in AI_APPSEC_RULES:
                    for pat in rule["patterns"]:
                        for match in re.finditer(pat, content):
                            line = content.count("\n", 0, match.start()) + 1
                            findings.append({
                                "rule_id": rule["id"],
                                "name": rule["name"],
                                "category": rule["category"],
                                "severity": rule["severity"],
                                "confidence": "CONFIRMED",
                                "file": rel_path,
                                "line": line,
                                "line_start": line,
                                "line_end": line,
                                "message": rule["message"],
                                "evidence": match.group(0)[:120],
                                "remediation": rule["remediation"],
                                "cwe": [rule.get("cwe", "CWE-20")],
                                "source_engine": "AI-Code Security Pattern",
                            })
                            break
    return findings
