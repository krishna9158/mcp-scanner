"""
MCP Authentication & Transport Security Analyzer.

Evaluates how MCP servers are hosted and authenticated:
- Stdio transport (local process isolation) vs SSE/HTTP network transports.
- Presence of authentication middleware, API key validation, Bearer token checks.
- Exposure of unauthenticated public endpoints.
- Hardcoded authentication tokens / weak auth bypasses.

Uses evidence-based confidence:
- CONFIRMED: Directly observable hardcoded token or unauthenticated route.
- LIKELY: Network transport used with zero auth references across server files.
- POTENTIAL: Auth patterns detected but verification completeness uncertain.
- INFORMATIONAL: Architecture notes (e.g. stdio transport isolation).
"""
import os
import re

TRANSPORT_PATTERNS = {
    "sse": [
        r'\bSSEServerTransport\b',
        r'\bcreate_sse_server\b',
        r'\/sse\b',
        r'\bEventSource\b',
        r'\bSseServer\b',
    ],
    "http": [
        r'\bFastAPI\b',
        r'\bFlask\b',
        r'\bexpress\(\)',
        r'\bhttp\.createServer\b',
        r'\bapp\.(?:get|post|listen)\(',
    ],
    "stdio": [
        r'\bstdio_server\b',
        r'\bStdioServerTransport\b',
        r'\bmcp\.server\.stdio\b',
        r'\bprocess\.stdin\b',
    ],
    "websocket": [
        r'\bWebSocketServer\b',
        r'\bws:\/\/',
        r'\bwss:\/\/',
    ]
}

AUTH_GUARD_PATTERNS = [
    r'\bBearer\s+',
    r'\bAuthorization\b',
    r'\bapi[_-]?key\b',
    r'\bverify_token\b',
    r'\bauthenticate\b',
    r'\bOAuth\b',
    r'\bget_current_user\b',
    r'\bSecurityScopes\b',
    r'\bjwt\.decode\b',
    r'\bDepends\(',
    r'\brequireAuth\b',
    r'\bpassport\.authenticate\b',
]

HARDCODED_AUTH_PATTERNS = [
    (r'(?i)\bauth(?:orization)?[_-]?token\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Hardcoded auth token in MCP server"),
    (r'(?i)\bapi[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Hardcoded API key in MCP server"),
    (r'(?i)\bbearer\s+([a-zA-Z0-9_\-]{20,})', "Hardcoded Bearer credential in MCP endpoint"),
]


def analyze_mcp_authentication(folder_or_files):
    """
    Scans repository files for MCP transport configuration and authentication security.
    Accepts either a folder path (str) or a list of file paths.
    Returns a structured analysis dictionary.
    """
    files_to_scan = []
    if isinstance(folder_or_files, str):
        if os.path.isdir(folder_or_files):
            for root, dirs, files in os.walk(folder_or_files):
                dirs[:] = [d for d in dirs if d.lower() not in (
                    ".git", "node_modules", "dist", "build", ".venv", "venv", ".pytest_cache"
                )]
                for f in files:
                    if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml")):
                        files_to_scan.append(os.path.join(root, f))
        elif os.path.isfile(folder_or_files):
            files_to_scan.append(folder_or_files)
    elif isinstance(folder_or_files, (list, tuple)):
        files_to_scan = list(folder_or_files)

    transports_found = set()
    auth_guards_found = []
    hardcoded_tokens = []
    evidence_lines = []
    config_network_unauth = []

    for filepath in files_to_scan:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(500000)  # read up to 500KB
        except Exception:
            continue

        rel_path = filepath.replace("\\", "/")

        # 0. Check MCP configuration files (e.g. mcp.json, claude_desktop_config.json)
        if filepath.lower().endswith(".json"):
            try:
                import json as _json
                cfg_data = _json.loads(content)
                servers = cfg_data.get("mcpServers") if isinstance(cfg_data, dict) else None
                if isinstance(servers, dict):
                    for s_name, s_conf in servers.items():
                        if isinstance(s_conf, dict):
                            s_url = str(s_conf.get("url") or "")
                            s_trans = str(s_conf.get("transport") or "").lower()
                            has_net = any(k in s_url.lower() for k in ["http://", "https://", "ws://", "wss://", "0.0.0.0"]) or s_trans in ("sse", "http", "websocket")
                            has_auth = bool(s_conf.get("headers") or s_conf.get("auth") or s_conf.get("token") or s_conf.get("apiKey") or s_conf.get("api_key"))
                            if has_net:
                                transports_found.add(s_trans or "network")
                                if not has_auth:
                                    config_network_unauth.append({
                                        "server_name": s_name,
                                        "file": rel_path,
                                        "url": s_url,
                                        "transport": s_trans or "network"
                                    })
                            elif s_conf.get("command") or s_trans == "stdio":
                                transports_found.add("stdio")
            except Exception:
                pass

        # 1. Detect transports in source code
        for transport_type, patterns in TRANSPORT_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, content):
                    transports_found.add(transport_type)
                    evidence_lines.append(f"Found {transport_type.upper()} transport indicator in {os.path.basename(filepath)}")
                    break

        # 2. Detect auth guards / middleware
        for pat in AUTH_GUARD_PATTERNS:
            match = re.search(pat, content, re.IGNORECASE)
            if match:
                auth_guards_found.append({
                    "file": rel_path,
                    "pattern": pat,
                    "snippet": match.group(0)
                })

        # 3. Detect hardcoded auth tokens
        for pat, desc in HARDCODED_AUTH_PATTERNS:
            for match in re.finditer(pat, content):
                val = match.group(1)
                # Ignore placeholders
                if val.lower() in ("your_token_here", "insert_key_here", "bearer token", "example"):
                    continue
                line_no = content.count("\n", 0, match.start()) + 1
                hardcoded_tokens.append({
                    "file": rel_path,
                    "line": line_no,
                    "type": desc,
                    "preview": f"{val[:3]}...{val[-2:]}" if len(val) > 6 else "***"
                })

    # Evaluate overall status
    is_network_facing = "sse" in transports_found or "http" in transports_found or "websocket" in transports_found
    has_auth_guards = len(auth_guards_found) > 0
    has_hardcoded_tokens = len(hardcoded_tokens) > 0

    findings = []
    base_folder = folder_or_files if isinstance(folder_or_files, str) else ""

    try:
        from universal_validator import validate_and_sanitize_finding
    except ImportError:
        def validate_and_sanitize_finding(f):
            return f
    
    if has_hardcoded_tokens:
        for t in hardcoded_tokens:
            f_item = {
                "title": t["type"],
                "type": t["type"],
                "category": "secrets",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "file": t["file"],
                "line": t["line"],
                "evidence": f"Credential token `{t['preview']}` hardcoded at line {t['line']}.",
                "recommendation": "Remove hardcoded credentials from source code. Ingest auth tokens dynamically via environment variables or secret vaults."
            }
            val_f = validate_and_sanitize_finding(f_item)
            if val_f:
                findings.append(val_f)

    # 4. MCP Auth/Exposure Check (Basic v1)
    if config_network_unauth:
        for cu in config_network_unauth:
            f_item = {
                "title": "Unauthenticated Network-Accessible MCP Server",
                "type": "Unauthenticated Network-Accessible MCP Server",
                "category": "mcp_security",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "file": cu["file"],
                "line": 1,
                "evidence": f"MCP server '{cu['server_name']}' is configured for network transport ({cu['url'] or cu['transport']}) with no authentication credentials or headers.",
                "description": f"MCP server config found with no authentication and appears network-accessible ({cu['url'] or cu['transport']}), allowing unauthenticated remote clients to invoke tools.",
                "recommendation": "Restrict the MCP server to local stdio transport, or enforce authentication (e.g. Bearer token or API key header verification) before accepting incoming JSON-RPC connections.",
                "remediation": "Restrict the MCP server to local stdio transport, or enforce authentication (e.g. Bearer token or API key header verification) before accepting incoming JSON-RPC connections.",
                "cwe": "CWE-306"
            }
            val_f = validate_and_sanitize_finding(f_item)
            if val_f:
                findings.append(val_f)

    elif is_network_facing and not has_auth_guards:
        f_item = {
            "title": "Unauthenticated Network-Accessible MCP Server",
            "type": "Unauthenticated Network-Accessible MCP Server",
            "category": "mcp_security",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "file": list(transports_found)[0] if transports_found else "network",
            "line": 1,
            "evidence": f"MCP server implements network transport ({', '.join(sorted(transports_found))}) with no detected authentication/authorization middleware.",
            "description": "MCP server appears network-accessible (not local/stdio) and has no authentication configured, allowing unauthenticated remote clients to invoke its tools.",
            "recommendation": "Implement authentication middleware (e.g. Bearer token validation, OAuth, or API key header verification) before accepting incoming MCP JSON-RPC messages.",
            "remediation": "Implement authentication middleware (e.g. Bearer token validation, OAuth, or API key header verification) before accepting incoming MCP JSON-RPC messages.",
            "cwe": "CWE-306"
        }
        val_f = validate_and_sanitize_finding(f_item)
        if val_f:
            findings.append(val_f)

    elif is_network_facing and has_auth_guards:
        findings.append({
            "title": "Network Transport with Auth Verification",
            "type": "Network Transport with Auth Verification",
            "category": "mcp_security",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "file": auth_guards_found[0]["file"] if auth_guards_found else "server",
            "line": 1,
            "evidence": f"Detected authentication patterns in network transport ({len(auth_guards_found)} references).",
            "recommendation": "Ensure token validation includes signature verification, expiration check, and proper error handling.",
            "remediation": "Ensure token validation includes signature verification, expiration check, and proper error handling."
        })
    elif "stdio" in transports_found and not is_network_facing:
        findings.append({
            "title": "Stdio Process-Isolated Transport",
            "type": "Stdio Process-Isolated Transport",
            "category": "mcp_security",
            "severity": "LOW",
            "confidence": "INFORMATIONAL",
            "file": "stdio",
            "line": 1,
            "evidence": "Server runs over local standard I/O (stdin/stdout). Authentication is delegated to host process OS-level permissions.",
            "recommendation": "If exposing over network (e.g. via proxy), ensure TLS and token authentication are added.",
            "remediation": "If exposing over network (e.g. via proxy), ensure TLS and token authentication are added."
        })

    # Overall score for auth category
    if has_hardcoded_tokens:
        status = "CRITICAL RISK"
        score = "RED"
    elif is_network_facing and not has_auth_guards:
        status = "HIGH RISK"
        score = "RED"
    elif is_network_facing and has_auth_guards:
        status = "AUTHENTICATED"
        score = "GREEN"
    else:
        status = "LOCAL ISOLATED"
        score = "GREEN"

    return {
        "status": status,
        "score": score,
        "transports": list(transports_found),
        "is_network_facing": is_network_facing,
        "has_auth_guards": has_auth_guards,
        "findings": findings,
        "evidence": evidence_lines
    }
