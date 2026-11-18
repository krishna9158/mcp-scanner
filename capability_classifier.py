"""
11-Category Dangerous Capability Classifier for MCP Tools & AI Systems.

Taxonomy:
- READ: Read-only files, data queries, informational APIs
- WRITE: File modifications, record updates, state changes
- DELETE: File deletion, table dropping, data purges
- EXECUTE: Shell execution, subprocesses, arbitrary code evaluation
- NETWORK: Outbound HTTP, socket connections, API requests
- FILESYSTEM: Direct disk and path operations
- DATABASE: SQL, MongoDB, Redis, and ORM database operations
- CREDENTIAL: Environment variables, secret tokens, private keys
- FINANCIAL: Payment processing, money transfer, billing manipulation
- EXTERNAL_COMMUNICATION: Sending emails, webhooks, messages, public posts
- ADMIN: Access grants, role escalation, sudo/root, system termination
"""
import re

CAPABILITY_TAXONOMY = {
    "FINANCIAL": {
        "severity": "CRITICAL",
        "keywords": [r'\btransfer[_-]?money\b', r'\btransfer[_-]?funds\b', r'\bsend[_-]?payment\b', r'\bpay\b', r'\bwithdraw\b', r'\bbilling\b', r'\bcheckout\b', r'\bcharge[_-]?card\b'],
        "code_patterns": [r'stripe\.Charge', r'stripe\.PaymentIntent', r'paypal', r'plaid'],
        "description": "Financial and monetary transactions (funds transfer, credit card charging)"
    },
    "ADMIN": {
        "severity": "CRITICAL",
        "keywords": [r'\bgrant[_-]?access\b', r'\brevoke\b', r'\badmin\b', r'\bsudo\b', r'\broot\b', r'\bescalate\b', r'\bshutdown\b', r'\bterminate[_-]?system\b', r'\bkill[_-]?process\b'],
        "code_patterns": [r'os\.kill\b', r'sys\.exit\b', r'sudo\s+', r'chmod\s+777'],
        "description": "Administrative privilege manipulation, role escalation, and host process termination"
    },
    "EXECUTE": {
        "severity": "CRITICAL",
        "keywords": [r'\bexecute[_-]?command\b', r'\brun[_-]?shell\b', r'\beval[_-]?code\b', r'\bexec[_-]?code\b', r'\bspawn\b', r'\brun[_-]?script\b'],
        "code_patterns": [r'subprocess\.', r'os\.system\b', r'os\.popen\b', r'child_process\.', r'exec\s*\(', r'eval\s*\('],
        "description": "Arbitrary command execution, subprocess invocation, and dynamic code evaluation"
    },
    "DELETE": {
        "severity": "HIGH",
        "keywords": [r'\bdelete\b', r'\bdrop\b', r'\bwipe\b', r'\bdestroy\b', r'\bpurge\b', r'\bformat\b', r'\bunlink\b', r'\bremove[_-]?all\b'],
        "code_patterns": [r'os\.remove\b', r'os\.unlink\b', r'shutil\.rmtree\b', r'fs\.unlink\b', r'DROP\s+TABLE', r'DELETE\s+FROM'],
        "description": "Irreversible data deletion, filesystem wiping, or database record removal"
    },
    "CREDENTIAL": {
        "severity": "HIGH",
        "keywords": [r'\bcredentials?\b', r'\bsecrets?\b', r'\bapi[_-]?keys?\b', r'\benvironment\b', r'\bauth[_-]?token\b', r'\bprivate[_-]?key\b'],
        "code_patterns": [r'os\.environ\b', r'process\.env\b', r'dotenv', r'aws_access_key', r'secret_key'],
        "description": "Access to operating system environment variables, secrets, and private credentials"
    },
    "EXTERNAL_COMMUNICATION": {
        "severity": "HIGH",
        "keywords": [r'\bsend[_-]?email\b', r'\bsend[_-]?message\b', r'\bpost[_-]?public\b', r'\bpublish\b', r'\bbroadcast\b', r'\bnotify\b', r'\bdiscord\b', r'\bslack\b', r'\btweet\b'],
        "code_patterns": [r'smtplib', r'sendgrid', r'twilio', r'hooks\.slack\.com', r'api\.telegram\.org'],
        "description": "Broadcasting data outward via emails, messaging channels, or external notification hooks"
    },
    "DATABASE": {
        "severity": "HIGH",
        "keywords": [r'\bdatabase\b', r'\bsql\b', r'\bquery\b', r'\bmongo\b', r'\bredis\b', r'\bpostgres\b', r'\bmysql\b', r'\btable\b'],
        "code_patterns": [r'sqlite3\.', r'psycopg2\.', r'sqlalchemy\.', r'pymongo\.', r'redis\.', r'mongoose\.', r'\.query\s*\('],
        "description": "Interacting with relational or NoSQL datastores and databases"
    },
    "NETWORK": {
        "severity": "MEDIUM",
        "keywords": [r'\bnetwork\b', r'\bhttp\b', r'\burl\b', r'\bweb\b', r'\bfetch\b', r'\bdownload\b', r'\bapi\b', r'\brequest\b', r'\bendpoint\b'],
        "code_patterns": [r'requests\.', r'urllib\.', r'httpx\.', r'aiohttp\.', r'fetch\s*\(', r'axios\.'],
        "description": "Outbound HTTP/HTTPS network connections and external web requests"
    },
    "FILESYSTEM": {
        "severity": "MEDIUM",
        "keywords": [r'\bfilesystem\b', r'\bpath\b', r'\bdirectory\b', r'\bfolder\b', r'\bdisk\b'],
        "code_patterns": [r'os\.path\b', r'pathlib\.', r'fs\.', r'glob\.'],
        "description": "Traversing, listing, and inspecting local filesystem directory structures"
    },
    "WRITE": {
        "severity": "MEDIUM",
        "keywords": [r'\bwrite\b', r'\bupdate\b', r'\bmodify\b', r'\bcreate\b', r'\bupload\b', r'\bedit\b', r'\bsave\b', r'\bstore\b'],
        "code_patterns": [r'open\s*\([^)]*["\'][wa\+]', r'fs\.writeFile', r'INSERT\s+INTO', r'UPDATE\s+'],
        "description": "Modifying files on disk, saving objects, or inserting database records"
    },
    "READ": {
        "severity": "LOW",
        "keywords": [r'\bread\b', r'\bget\b', r'\blookup\b', r'\blist\b', r'\bsearch\b', r'\bfind\b', r'\binfo\b', r'\bview\b'],
        "code_patterns": [r'open\s*\([^)]*["\']r["\']', r'fs\.readFile', r'SELECT\s+'],
        "description": "Read-only data retrieval and lookup operations"
    },
}


def classify_tool_capabilities(tool_name, description="", code_snippet=""):
    """
    Evaluates tool text and code snippet to classify it across the 11 capability categories.
    Returns a list of matched categories with severity and evidence.
    """
    text_corpus = f"{tool_name} {description}".lower()
    code_corpus = str(code_snippet or "")
    
    detected_caps = []

    for cap, rule in CAPABILITY_TAXONOMY.items():
        matched = False
        evidence = []

        # 1. Keyword check in name & description
        for kw in rule["keywords"]:
            if re.search(kw, text_corpus, re.IGNORECASE):
                matched = True
                evidence.append(f"Keyword match: {kw.replace(r'\\b', '')}")
                break

        # 2. Code pattern check
        for cp in rule["code_patterns"]:
            if re.search(cp, code_corpus):
                matched = True
                evidence.append(f"Code pattern match: {cp}")
                break

        if matched:
            detected_caps.append({
                "category": cap,
                "severity": rule["severity"],
                "description": rule["description"],
                "evidence": ", ".join(evidence)
            })

    # Default to READ if nothing flagged
    if not detected_caps:
        detected_caps.append({
            "category": "READ",
            "severity": "LOW",
            "description": "Read-only or informational tool",
            "evidence": "Default baseline classification"
        })

    # Sort by severity hierarchy
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detected_caps.sort(key=lambda c: severity_order.get(c["severity"], 4))
    return detected_caps
