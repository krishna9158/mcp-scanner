"""
Application Security Scanner for AI-Coded Applications.

Detects common OWASP Top 10, AI code-generation flaws, and critical vulnerabilities
across Python, JavaScript, TypeScript, Docker, and configuration files:
- SQL Injection (CRITICAL)
- Command Injection / Unsafe Subprocesses (CRITICAL)
- Server-Side Request Forgery (SSRF) (CRITICAL)
- Insecure JWT Verification & 'none' Algorithm (CRITICAL)
- Server-Side Template Injection (SSTI) (CRITICAL)
- NoSQL / MongoDB Object Injection (CRITICAL)
- Unsafe Dynamic Code Execution (eval, exec, new Function) (CRITICAL)
- Insecure Deserialization (pickle, unsafe YAML) (HIGH)
- Path Traversal (HIGH)
- Unvalidated Open Redirects (HIGH)
- Overly Permissive CORS with Credentials in Code (HIGH)
- Prototype Pollution & Unsafe Merges (HIGH)
- XML External Entity (XXE) Processing (HIGH)
- Weak Cryptography (MD5/SHA1, hardcoded keys) (MEDIUM)
- Disabled CSRF Protection (MEDIUM)
- Insecure Dockerfile Configuration (MEDIUM)
"""
import os
import re

APPSEC_RULES = [
    {
        "id": "APPSEC-SQLI",
        "name": "Potential SQL Injection",
        "category": "Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)\.execute\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*%\s*\(',
            r'(?i)\.execute\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)',
            r'(?i)\.execute\s*\(\s*["\'].*\+\s*[a-zA-Z_]\w*',
            r'(?i)\$query\s*=\s*["\'].*\$.*',
            r'(?i)db\.query\s*\(\s*`.*SELECT.*\$\{',
        ],
        "message": "Dynamic SQL query constructed with string concatenation or interpolation instead of parameterized queries.",
        "fix": "Use parameterized queries or ORM query builders (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))"
    },
    {
        "id": "APPSEC-CMDI",
        "name": "Dangerous Shell Command Execution",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'subprocess\.(?:call|Popen|run)\s*\(.*shell\s*=\s*True',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'child_process\.exec\s*\(',
            r'child_process\.execSync\s*\(',
        ],
        "message": "Executing shell commands with shell=True or direct system shells allows command injection if arguments contain user input.",
        "fix": "Pass command arguments as an array with shell=False, and validate all inputs against an allowlist."
    },
    {
        "id": "APPSEC-SSRF",
        "name": "Potential Server-Side Request Forgery (SSRF)",
        "category": "SSRF",
        "severity": "CRITICAL",
        "patterns": [
            r'requests\.(?:get|post|put|delete|head)\s*\(\s*(?:request\.|req\.|params|user_url|target_url|input_url)',
            r'urllib\.request\.urlopen\s*\(\s*(?:request\.|req\.|params|user_url|target_url)',
            r'axios\.(?:get|post|put|delete)\s*\(\s*(?:req\.|params|user_url|target_url|input_url)',
            r'fetch\s*\(\s*(?:req\.|params|user_url|target_url|input_url)',
            r'http\.get\s*\(\s*(?:req\.|params|user_url|target_url)',
        ],
        "message": "Server-side HTTP request made directly to a dynamic, user-supplied URL without destination validation, enabling SSRF attacks against internal services or cloud metadata.",
        "fix": "Validate destination URLs against an explicit allowlist of authorized domains and restrict internal IP/localhost resolution."
    },
    {
        "id": "APPSEC-JWT-INSECURE",
        "name": "Insecure JWT Signature Verification",
        "category": "Authentication",
        "severity": "CRITICAL",
        "patterns": [
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
            r'jwt\.decode\s*\([^)]*verify_signature\s*=\s*False',
            r'jwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*["\']none["\']',
            r'algorithms\s*=\s*\[\s*["\']none["\']\s*\]',
            r'options\s*=\s*\{\s*["\']verify_signature["\']\s*:\s*False',
        ],
        "message": "JWT token verification has signature checks disabled or allows the 'none' algorithm, permitting authentication bypass and privilege escalation.",
        "fix": "Enforce strict signature verification using secure asymmetric (RS256) or symmetric (HS256) algorithms and a strong secret key."
    },
    {
        "id": "APPSEC-SSTI",
        "name": "Server-Side Template Injection (SSTI)",
        "category": "Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'render_template_string\s*\(\s*(?:request\.|req\.|params|user_input|data)',
            r'jinja2\.Template\s*\(\s*(?:request\.|req\.|params|user_input)',
            r'ejs\.render\s*\(\s*(?:req\.|params|user_input)',
            r'nunjucks\.renderString\s*\(\s*(?:req\.|params)',
        ],
        "message": "Untrusted user input is rendered directly as a template string, enabling Remote Code Execution (RCE) via template engine sandbox escapes.",
        "fix": "Render static template files with parameterized context variables instead of compiling dynamic template strings."
    },
    {
        "id": "APPSEC-NOSQLI",
        "name": "NoSQL / MongoDB Object Injection",
        "category": "Injection",
        "severity": "CRITICAL",
        "patterns": [
            r'\$where\s*:\s*(?:request|req\.|params|user)',
            r'\.(?:find|findOne|update|deleteMany)\s*\(\s*req\.body\s*\)',
            r'\.(?:find|findOne)\s*\(\s*\{\s*\$where\s*:',
        ],
        "message": "Raw request body or user-supplied queries passed directly to MongoDB / NoSQL queries, permitting NoSQL injection and authentication bypass.",
        "fix": "Explicitly sanitize and validate query field types; never pass raw request bodies directly into database find/query methods."
    },
    {
        "id": "APPSEC-EVAL",
        "name": "Unsafe Dynamic Code Execution (eval/exec)",
        "category": "Code Execution",
        "severity": "CRITICAL",
        "patterns": [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\bnew\s+Function\s*\(',
        ],
        "message": "Use of eval() / exec() can lead to arbitrary code execution if dynamic or AI-generated input reaches it.",
        "fix": "Avoid dynamic code execution. Use safe JSON parsers or declarative dispatcher tables."
    },
    {
        "id": "APPSEC-DESER",
        "name": "Insecure Deserialization",
        "category": "Deserialization",
        "severity": "HIGH",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'_pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^,)]+\)',  # yaml.load without SafeLoader
        ],
        "message": "Deserializing untrusted data with pickle or unsafe YAML loader can trigger arbitrary code execution.",
        "fix": "Use yaml.safe_load() instead of yaml.load(), and avoid pickle for data received across boundaries (use JSON instead)."
    },
    {
        "id": "APPSEC-PATH",
        "name": "Potential Path Traversal",
        "category": "File Security",
        "severity": "HIGH",
        "patterns": [
            r'open\s*\(\s*(?:os\.path\.join\s*\([^)]*request|req\.|params|query)',
            r'fs\.readFile(?:Sync)?\s*\(\s*(?:req\.|params|query)',
            r'fs\.createReadStream\s*\(\s*(?:req\.|params|query)',
        ],
        "message": "Opening files directly using unvalidated request parameters can allow directory traversal (e.g. ../../etc/passwd).",
        "fix": "Resolve and validate absolute paths (e.g. os.path.commonpath) to ensure targets stay inside the permitted directory."
    },
    {
        "id": "APPSEC-OPEN-REDIRECT",
        "name": "Unvalidated Open Redirect",
        "category": "Redirect",
        "severity": "HIGH",
        "patterns": [
            r'redirect\s*\(\s*request\.(?:args|values|form)\.get\s*\(\s*["\'](?:next|url|redirect|target|returnTo)["\']',
            r'res\.redirect\s*\(\s*req\.(?:query|body|params)\.(?:next|url|redirect|target|returnTo)',
        ],
        "message": "Redirecting users to an unvalidated URL provided in request query parameters facilitates phishing attacks under your domain's trust.",
        "fix": "Validate redirect destinations against relative path formats (starting with '/') or an explicit domain allowlist."
    },
    {
        "id": "APPSEC-XXE",
        "name": "XML External Entity (XXE) Injection",
        "category": "XML Security",
        "severity": "HIGH",
        "patterns": [
            r'resolve_entities\s*=\s*True',
            r'etree\.XMLParser\s*\([^)]*resolve_entities\s*=\s*True',
            r'load_dtd\s*=\s*True',
            r'xml\.sax\.make_parser',
        ],
        "message": "XML parser configured to resolve external entities or DTDs, enabling local file disclosure and SSRF via XXE payloads.",
        "fix": "Disable external entity resolution: defusedxml or etree.XMLParser(resolve_entities=False, no_network=True)."
    },
    {
        "id": "APPSEC-CORS-CODE",
        "name": "Insecure CORS: Wildcard with Credentials in Code",
        "category": "CORS",
        "severity": "HIGH",
        "patterns": [
            r'CORS\s*\([^)]*origins\s*=\s*["\']\*["\'][^)]*supports_credentials\s*=\s*True',
            r'cors\s*\(\s*\{\s*origin\s*:\s*["\']\*["\']\s*,\s*credentials\s*:\s*true',
            r'Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\'].*Access-Control-Allow-Credentials["\']?\s*:\s*["\']true',
        ],
        "message": "Backend configuration allows wildcard CORS origin combined with credentials, permitting cross-origin authenticated data theft.",
        "fix": "Do not combine origin '*' with credentials. Specify explicit allowed trusted origin domains."
    },
    {
        "id": "APPSEC-PROTOTYPE-POLLUTION",
        "name": "Unsafe Object Merge & Prototype Pollution",
        "category": "Code Security",
        "severity": "HIGH",
        "patterns": [
            r'Object\.assign\s*\(\s*(?:\{\}|target)\s*,\s*req\.body',
            r'_\.merge\s*\(\s*[^,]+\s*,\s*req\.body',
            r'lodash\.merge\s*\(\s*[^,]+\s*,\s*req\.body',
        ],
        "message": "Unsafe recursive object merge with raw request payload can modify Object.prototype and cause privilege escalation or denial of service.",
        "fix": "Validate object keys to reject '__proto__' and 'constructor.prototype', or use Object.create(null)."
    },
    {
        "id": "APPSEC-CRYPTO",
        "name": "Weak Cryptographic Hash Function",
        "category": "Cryptography",
        "severity": "MEDIUM",
        "patterns": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']',
        ],
        "message": "MD5 and SHA1 are cryptographically broken and should not be used for security-sensitive hashing or passwords.",
        "fix": "Use SHA-256 / SHA-512 for checksums, or bcrypt / argon2 for password hashing."
    },
    {
        "id": "APPSEC-CSRF-DISABLED",
        "name": "CSRF Protection Explicitly Disabled",
        "category": "CSRF",
        "severity": "MEDIUM",
        "patterns": [
            r'@csrf\.exempt',
            r'csrf\s*:\s*false',
            r'csrf_protection\s*=\s*False',
            r'disable\s*\(\s*csrf\s*\)',
        ],
        "message": "CSRF protection has been disabled on an endpoint, allowing attackers to execute unauthorized state-changing actions via user browsers.",
        "fix": "Enable CSRF tokens for all state-changing endpoints (POST/PUT/DELETE) using standard framework middleware."
    },
    {
        "id": "APPSEC-DOCKERFILE-ROOT",
        "name": "Container Running as Root / Sensitive Port Exposed",
        "category": "Container Security",
        "severity": "MEDIUM",
        "patterns": [
            r'(?i)USER\s+root',
            r'(?i)EXPOSE\s+(?:22|2375|6379|27017)\b',
        ],
        "message": "Dockerfile explicitly sets root user or exposes administrative ports (SSH, Docker Daemon, Redis, MongoDB) without non-root privilege drop.",
        "fix": "Create and switch to a dedicated non-root user (e.g. USER appuser) and avoid exposing raw internal database/management ports in containers."
    },
]


def scan_code_for_vulnerabilities(content, filepath="unknown"):
    """
    Scans a single file's source code for common application security flaws.
    """
    findings = []
    for rule in APPSEC_RULES:
        for pat in rule["patterns"]:
            for match in re.finditer(pat, content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "file": filepath,
                    "line": line,
                    "message": rule["message"],
                    "matched_snippet": match.group(0)[:120],
                    "fix": rule["fix"],
                })
                break  # one finding per rule per match
    return findings


def scan_folder_for_appsec(folder, max_files=1000):
    """
    Recursively scans source files in a folder for AppSec vulnerabilities.
    """
    findings = []
    count = 0
    skip_dirs = (".git", "node_modules", "dist", "build", ".venv", "venv", ".pytest_cache")

    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
        for file in files:
            file_lower = file.lower()
            if (
                file_lower.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".yaml", ".yml"))
                or file_lower.startswith("dockerfile")
            ):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(500000)
                    file_findings = scan_code_for_vulnerabilities(content, filepath)
                    findings.extend(file_findings)
                except Exception:
                    continue
                count += 1
                if count >= max_files:
                    return findings
    return findings
