"""
MCP-Specific Differentiation Engine for TrustAudit Platform.

Provides specialized security intelligence for the Model Context Protocol (MCP) ecosystem:
1. MCP Package Reputation & Registry Lookup (Official ModelContextProtocol & Smithery registries).
2. MCP Typosquatting Cross-Referencing (character substitutions, deceptive suffixes, and namespace confusion).
3. Permission-Change & Tool-Drift Diffing (identifying silent permission creep and rug-pull risks between releases).
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 1. Curated Registry of Official & Verified MCP Servers
# ---------------------------------------------------------------------------
OFFICIAL_MCP_SERVERS = {
    # Official Anthropic / ModelContextProtocol packages
    "@modelcontextprotocol/server-filesystem": {
        "name": "@modelcontextprotocol/server-filesystem",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 98,
        "standard_capabilities": ["READ_FILE", "WRITE_FILE", "LIST_DIR"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-github": {
        "name": "@modelcontextprotocol/server-github",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 96,
        "standard_capabilities": ["NETWORK_EGRESS", "API_ACCESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-postgres": {
        "name": "@modelcontextprotocol/server-postgres",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 95,
        "standard_capabilities": ["DATABASE_QUERY"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-sqlite": {
        "name": "@modelcontextprotocol/server-sqlite",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 95,
        "standard_capabilities": ["DATABASE_QUERY", "READ_FILE"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-fetch": {
        "name": "@modelcontextprotocol/server-fetch",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 94,
        "standard_capabilities": ["NETWORK_EGRESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-brave-search": {
        "name": "@modelcontextprotocol/server-brave-search",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 93,
        "standard_capabilities": ["NETWORK_EGRESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-slack": {
        "name": "@modelcontextprotocol/server-slack",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 94,
        "standard_capabilities": ["NETWORK_EGRESS", "API_ACCESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-puppeteer": {
        "name": "@modelcontextprotocol/server-puppeteer",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 90,
        "standard_capabilities": ["BROWSER_AUTOMATION", "NETWORK_EGRESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-memory": {
        "name": "@modelcontextprotocol/server-memory",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 95,
        "standard_capabilities": ["IN_MEMORY_GRAPH"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-sentry": {
        "name": "@modelcontextprotocol/server-sentry",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 93,
        "standard_capabilities": ["API_ACCESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-gitlab": {
        "name": "@modelcontextprotocol/server-gitlab",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 94,
        "standard_capabilities": ["NETWORK_EGRESS", "API_ACCESS"],
        "is_official": True,
    },
    "@modelcontextprotocol/server-google-drive": {
        "name": "@modelcontextprotocol/server-google-drive",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 92,
        "standard_capabilities": ["NETWORK_EGRESS", "FILE_ACCESS"],
        "is_official": True,
    },
    # Popular Python & Community Packages
    "mcp-server-git": {
        "name": "mcp-server-git",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 95,
        "standard_capabilities": ["GIT_OPERATIONS", "READ_FILE"],
        "is_official": True,
    },
    "mcp-server-sqlite": {
        "name": "mcp-server-sqlite",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 95,
        "standard_capabilities": ["DATABASE_QUERY"],
        "is_official": True,
    },
    "mcp-server-fetch": {
        "name": "mcp-server-fetch",
        "publisher": "ModelContextProtocol (Official)",
        "tier": "OFFICIAL_VERIFIED",
        "reputation_score": 94,
        "standard_capabilities": ["NETWORK_EGRESS"],
        "is_official": True,
    },
    "mcp-server-redis": {
        "name": "mcp-server-redis",
        "publisher": "Community Verified",
        "tier": "COMMUNITY_TRUSTED",
        "reputation_score": 88,
        "standard_capabilities": ["DATABASE_QUERY"],
        "is_official": False,
    }
}

# Deceptive prefixes/suffixes used in typosquatting / spoofing attacks
DECEPTIVE_MODIFIERS = [
    "-v2", "-v3", "-plus", "-pro", "-official", "-secure", "-safe",
    "-fast", "-new", "-fixed", "-updated", "-community", "official-",
    "real-", "verified-", "secure-"
]


# ---------------------------------------------------------------------------
# 2. Levenshtein Distance & Homoglyph Substitution Matrix
# ---------------------------------------------------------------------------
def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_homoglyphs(name: str) -> str:
    """Normalizes visual homoglyphs (e.g. '0' -> 'o', '1' -> 'l', 'rn' -> 'm')."""
    s = name.lower()
    s = s.replace("0", "o")
    s = s.replace("1", "l")
    s = s.replace("rn", "m")
    s = s.replace("vv", "w")
    return s


# ---------------------------------------------------------------------------
# 3. MCP Package Reputation & Registry Lookup
# ---------------------------------------------------------------------------
def lookup_mcp_reputation(package_name: str) -> Dict[str, Any]:
    """
    Evaluates community reputation and verification status for an MCP package.
    """
    clean_name = package_name.strip().lower()
    
    # 1. Exact match against official registry
    if clean_name in OFFICIAL_MCP_SERVERS:
        entry = OFFICIAL_MCP_SERVERS[clean_name]
        return {
            "package_name": package_name,
            "reputation_score": entry["reputation_score"],
            "trust_tier": entry["tier"],
            "publisher": entry["publisher"],
            "is_verified_publisher": True,
            "is_official": entry["is_official"],
            "risk_level": "LOW",
            "summary": f"Verified official MCP package published by {entry['publisher']}.",
            "expected_capabilities": entry["standard_capabilities"],
        }

    # 2. Verified official scope namespace (@modelcontextprotocol/*)
    if clean_name.startswith("@modelcontextprotocol/"):
        return {
            "package_name": package_name,
            "reputation_score": 92,
            "trust_tier": "OFFICIAL_VERIFIED",
            "publisher": "ModelContextProtocol Org",
            "is_verified_publisher": True,
            "is_official": True,
            "risk_level": "LOW",
            "summary": "Official ModelContextProtocol organization package.",
            "expected_capabilities": ["STANDARD_MCP"],
        }

    # 3. Check for Typosquatting / Homoglyphs against official servers
    typo_match = check_mcp_typosquatting(package_name)
    if typo_match:
        return {
            "package_name": package_name,
            "reputation_score": 15,
            "trust_tier": "SUSPICIOUS_TYPOSQUAT",
            "publisher": "Unknown / Impersonator",
            "is_verified_publisher": False,
            "is_official": False,
            "risk_level": "CRITICAL",
            "summary": typo_match["reason"],
            "resembles": typo_match["resembles"],
        }

    # 4. Standard third-party community package
    return {
        "package_name": package_name,
        "reputation_score": 65,
        "trust_tier": "UNVERIFIED_THIRD_PARTY",
        "publisher": "Community Developer",
        "is_verified_publisher": False,
        "is_official": False,
        "risk_level": "MEDIUM",
        "summary": "Unverified community MCP package. Manual inspection of tools and permissions recommended.",
        "expected_capabilities": ["CUSTOM"],
    }


# ---------------------------------------------------------------------------
# 4. MCP Typosquatting Cross-Referencing Engine
# ---------------------------------------------------------------------------
def _strip_mcp_prefixes(name: str) -> str:
    s = name.lower().strip()
    s = s.replace("@modelcontextprotocol/", "")
    if s.startswith("mcp-server-"):
        s = s[len("mcp-server-"):]
    elif s.startswith("mcp-"):
        s = s[len("mcp-"):]
    elif s.startswith("server-"):
        s = s[len("server-"):]
    return s


def check_mcp_typosquatting(package_or_tool_name: str) -> Optional[Dict[str, Any]]:
    """
    Detects if an MCP server or tool name deceptive mimics an official MCP server.
    """
    candidate = package_or_tool_name.strip().lower()
    
    # Exact official name is trusted
    if candidate in OFFICIAL_MCP_SERVERS:
        return None

    cand_normalized = _normalize_homoglyphs(candidate)
    cand_base = _strip_mcp_prefixes(candidate)

    for official_name in OFFICIAL_MCP_SERVERS:
        off_norm = _normalize_homoglyphs(official_name)
        off_base = _strip_mcp_prefixes(official_name)

        # A. Homoglyph match (e.g. '@modelcontextprotoco1/server-github' -> '@modelcontextprotocol/server-github')
        if candidate != official_name and cand_normalized == off_norm:
            return {
                "package": package_or_tool_name,
                "resembles": official_name,
                "attack_type": "HOMOGLYPH_SUBSTITUTION",
                "severity": "CRITICAL",
                "reason": f"'{package_or_tool_name}' uses visual character substitution to impersonate official '{official_name}'."
            }

        # B. Deceptive prefix/suffix modifier (e.g. 'mcp-server-filesystem-v2' or 'official-mcp-server-github')
        for mod in DECEPTIVE_MODIFIERS:
            # Check suffix on raw and base
            if (candidate == f"{official_name}{mod}" or 
                cand_base == f"{off_base}{mod}" or
                candidate.replace("@modelcontextprotocol/", "") == f"{official_name.replace('@modelcontextprotocol/', '')}{mod}"):
                return {
                    "package": package_or_tool_name,
                    "resembles": official_name,
                    "attack_type": "DECEPTIVE_MODIFIER",
                    "severity": "CRITICAL",
                    "reason": f"'{package_or_tool_name}' mimics official '{official_name}' using deceptive modifier '{mod}'."
                }
            # Check prefix on raw and base
            if mod.endswith("-") and (
                candidate == f"{mod}{official_name}" or
                cand_base == f"{mod}{off_base}" or
                candidate == f"{mod}{official_name.replace('@modelcontextprotocol/', '')}" or
                candidate.replace("mcp-server-", "") == f"{mod}{official_name.replace('@modelcontextprotocol/server-', '')}"
            ):
                return {
                    "package": package_or_tool_name,
                    "resembles": official_name,
                    "attack_type": "DECEPTIVE_MODIFIER",
                    "severity": "CRITICAL",
                    "reason": f"'{package_or_tool_name}' prepends deceptive prefix '{mod}' to impersonate official '{official_name}'."
                }

        # C. Levenshtein edit distance check (1 or 2 edits away)
        if abs(len(cand_base) - len(off_base)) <= 2 and cand_base != off_base:
            dist = _levenshtein_distance(cand_base, off_base)
            if 0 < dist <= 2 and len(off_base) >= 4:
                return {
                    "package": package_or_tool_name,
                    "resembles": official_name,
                    "attack_type": "LEVENSHTEIN_TYPOSQUAT",
                    "distance": dist,
                    "severity": "CRITICAL",
                    "reason": f"'{package_or_tool_name}' is suspiciously close to official package '{official_name}' (edit distance {dist})."
                }

    return None


def scan_mcp_manifest_for_typosquatting(dependencies_or_tools: List[str]) -> List[Dict[str, Any]]:
    """
    Scans a list of MCP package names or tool names for typosquatting signals.
    """
    findings = []
    for item in dependencies_or_tools:
        if not item:
            continue
        res = check_mcp_typosquatting(str(item))
        if res:
            findings.append(res)
    return findings


# ---------------------------------------------------------------------------
# 5. Permission-Change & Tool-Drift Diffing Engine
# ---------------------------------------------------------------------------
DANGEROUS_CAPABILITY_HIERARCHY = {
    "SHELL_EXECUTION": 100,
    "SUBPROCESS_EXECUTION": 100,
    "RAW_CODE_EVAL": 95,
    "FILESYSTEM_WRITE_ARBITRARY": 90,
    "FILESYSTEM_READ_ARBITRARY": 80,
    "NETWORK_OUTBOUND_ARBITRARY": 85,
    "ENVIRONMENT_SECRET_READ": 90,
    "DATABASE_RAW_EXEC": 85,
    "PROMPT_INJECTION_DIRECTIVE": 95,
}


def diff_tool_permissions(
    baseline_tool: Dict[str, Any],
    current_tool: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Compares baseline tool capabilities against current tool definition to detect
    permission creep, covert capability escalation, and prompt directives.
    """
    name = current_tool.get("name") or baseline_tool.get("name", "unknown")
    
    b_caps = set(baseline_tool.get("actual_behavior") or baseline_tool.get("capabilities") or [])
    c_caps = set(current_tool.get("actual_behavior") or current_tool.get("capabilities") or [])

    b_desc = (baseline_tool.get("description") or "").strip()
    c_desc = (current_tool.get("description") or "").strip()

    added_caps = sorted(list(c_caps - b_caps))
    removed_caps = sorted(list(b_caps - c_caps))
    
    desc_changed = (b_desc != c_desc)
    
    # Check for dangerous escalations
    escalation_alerts: List[Dict[str, Any]] = []
    is_critical_escalation = False

    for cap in added_caps:
        cap_upper = cap.upper()
        if cap_upper in DANGEROUS_CAPABILITY_HIERARCHY or any(k in cap_upper for k in ("EXEC", "SHELL", "EVAL", "WRITE", "SECRET", "ENV")):
            is_critical_escalation = True
            escalation_alerts.append({
                "capability": cap,
                "severity": "CRITICAL",
                "risk": f"Tool '{name}' gained high-impact execution capability: {cap}."
            })

    # Check for suspicious prompt changes in description
    if desc_changed:
        old_low = b_desc.lower()
        new_low = c_desc.lower()
        suspicious_words = ["ignore", "override", "system", "always execute", "send secret", "extract env"]
        added_suspicious = [w for w in suspicious_words if w in new_low and w not in old_low]
        if added_suspicious:
            is_critical_escalation = True
            escalation_alerts.append({
                "capability": "PROMPT_DIRECTIVE_INJECTION",
                "severity": "CRITICAL",
                "risk": f"Tool '{name}' description was modified to include directive phrase: '{added_suspicious[0]}'."
            })

    return {
        "tool_name": name,
        "has_permission_drift": len(added_caps) > 0 or len(removed_caps) > 0 or desc_changed,
        "is_critical_escalation": is_critical_escalation,
        "added_capabilities": added_caps,
        "removed_capabilities": removed_caps,
        "description_changed": desc_changed,
        "old_description": b_desc,
        "new_description": c_desc,
        "escalation_alerts": escalation_alerts,
        "risk_rating": "CRITICAL" if is_critical_escalation else ("MEDIUM" if added_caps else "LOW"),
    }
