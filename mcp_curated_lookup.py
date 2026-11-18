"""
Curated MCP Package Reputation Lookup (Basic v1).

Provides lightweight cross-referencing of MCP packages against a small, manually-curated
dataset derived from OWASP MCP Top 10 and public security research.
"""

import json
import os
from typing import Any, Dict, List, Optional

CURATED_DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "mcp_curated_reputation.json")


def _normalize_pkg_name(name: str) -> str:
    s = (name or "").strip().lower()
    s = s.replace("@modelcontextprotocol/", "")
    if s.startswith("mcp-server-"):
        s = s[len("mcp-server-"):]
    elif s.startswith("mcp-"):
        s = s[len("mcp-"):]
    elif s.startswith("server-"):
        s = s[len("server-"):]
    return s


def load_curated_reputation_dataset() -> List[Dict[str, Any]]:
    """Loads the curated 15-entry OWASP MCP Top 10 dataset."""
    if not os.path.exists(CURATED_DATASET_PATH):
        return []
    try:
        with open(CURATED_DATASET_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def lookup_curated_mcp_reputation(package_name: str) -> Dict[str, Any]:
    """
    Looks up an MCP package name against the curated dataset.
    Returns either specific flagged concerns or 'No known issues found'.
    """
    raw_name = (package_name or "").strip()
    if not raw_name:
        return {
            "package": "",
            "flagged": False,
            "status": "CLEAN",
            "message": "No package specified."
        }

    dataset = load_curated_reputation_dataset()
    normalized_query = _normalize_pkg_name(raw_name)

    for entry in dataset:
        entry_pkg = entry.get("package", "")
        if raw_name.lower() == entry_pkg.lower() or normalized_query == _normalize_pkg_name(entry_pkg):
            return {
                "package": raw_name,
                "matched_entry": entry_pkg,
                "flagged": True,
                "status": "CONCERNS_DOCUMENTED",
                "owasp_mcp_category": entry.get("owasp_mcp_category", "OWASP MCP Security Advisory"),
                "concerns": entry.get("concerns", []),
                "remediation": entry.get("remediation", "Review tool scopes and permissions.")
            }

    return {
        "package": raw_name,
        "flagged": False,
        "status": "CLEAN",
        "message": "No known issues found in curated database."
    }
