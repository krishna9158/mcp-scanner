"""
Tests for Phase 3 Minimal v1 MCP-Specific Features:
1. Curated MCP Package Reputation Lookup (OWASP MCP Top 10)
2. Typosquat Cross-Reference with popular MCP servers
3. Tool Permission Scope Expansion Diffing (Delta Engine)
4. MCP Auth/Exposure Check (Unauthenticated Network MCP Server)
"""

import json
import os
import tempfile
import pytest

from mcp_curated_lookup import lookup_curated_mcp_reputation, load_curated_reputation_dataset
from typosquat_check import check_mcp_typosquatting, scan_mcp_packages_for_typosquatting, POPULAR_MCP_SERVERS
from delta_engine import compute_scan_delta
from mcp_auth_analyzer import analyze_mcp_authentication


class TestFeature1McpCuratedReputationLookup:
    """1. MCP PACKAGE REPUTATION LOOKUP (basic version)"""

    def test_curated_dataset_has_15_entries(self):
        dataset = load_curated_reputation_dataset()
        assert len(dataset) >= 15
        packages = [e["package"] for e in dataset]
        assert "@modelcontextprotocol/server-filesystem" in packages
        assert "@modelcontextprotocol/server-postgres" in packages
        assert "@modelcontextprotocol/server-fetch" in packages
        assert "mcp-remote-shell" in packages

    def test_lookup_flagged_filesystem_server(self):
        res = lookup_curated_mcp_reputation("@modelcontextprotocol/server-filesystem")
        assert res["flagged"] is True
        assert res["status"] == "CONCERNS_DOCUMENTED"
        assert "MCP01" in res["owasp_mcp_category"]
        assert len(res["concerns"]) > 0
        assert "remediation" in res

    def test_lookup_flagged_shell_server(self):
        res = lookup_curated_mcp_reputation("mcp-remote-shell")
        assert res["flagged"] is True
        assert "RCE" in res["owasp_mcp_category"] or "Command Execution" in res["owasp_mcp_category"]
        assert any("shell" in c.lower() for c in res["concerns"])

    def test_lookup_clean_unknown_server(self):
        res = lookup_curated_mcp_reputation("my-company-internal-mcp")
        assert res["flagged"] is False
        assert res["status"] == "CLEAN"
        assert res["message"] == "No known issues found in curated database."


class TestFeature2TyposquatCrossReference:
    """2. TYPOSQUAT CROSS-REFERENCE (basic version)"""

    def test_popular_mcp_servers_list_populated(self):
        assert len(POPULAR_MCP_SERVERS) >= 15
        assert "@modelcontextprotocol/server-filesystem" in POPULAR_MCP_SERVERS
        assert "mcp-server-git" in POPULAR_MCP_SERVERS

    def test_exact_popular_package_not_flagged(self):
        for pkg in ["@modelcontextprotocol/server-github", "mcp-server-git", "mcp-server-docker"]:
            assert check_mcp_typosquatting(pkg) is None

    def test_homoglyph_typosquat_detected(self):
        # 0 instead of o, or 1 instead of l
        res = check_mcp_typosquatting("@modelcontextprotoco1/server-github")
        assert res is not None
        assert res["resembles"] == "@modelcontextprotocol/server-github"
        assert "character substitution" in res["reason"]

    def test_edit_distance_1_typosquat_detected(self):
        res = check_mcp_typosquatting("mcp-server-dockerr")
        assert res is not None
        assert res["resembles"] == "mcp-server-docker"
        assert res["distance"] == 1

    def test_unrelated_package_not_flagged(self):
        assert check_mcp_typosquatting("requests") is None
        assert check_mcp_typosquatting("flask") is None


class TestFeature3PermissionChangeDiffing:
    """3. PERMISSION-CHANGE DIFFING (basic version)"""

    def test_no_alert_when_permissions_unchanged(self):
        prev = {
            "score": 100,
            "report": [{"name": "search_db", "capabilities": ["DATABASE_QUERY"]}],
            "findings": []
        }
        curr = {
            "score": 100,
            "report": [{"name": "search_db", "capabilities": ["DATABASE_QUERY"]}],
            "findings": []
        }
        delta = compute_scan_delta(curr, prev)
        assert len(delta["permission_expansion_alerts"]) == 0

    def test_alert_emitted_when_tool_expands_scope(self):
        prev = {
            "score": 100,
            "report": [{"name": "query_tool", "capabilities": ["DATABASE_QUERY"]}],
            "findings": []
        }
        # In current scan, tool silently gained SHELL_EXECUTION
        curr = {
            "score": 90,
            "report": [{"name": "query_tool", "capabilities": ["DATABASE_QUERY", "SHELL_EXECUTION"]}],
            "findings": []
        }
        delta = compute_scan_delta(curr, prev)
        assert len(delta["permission_expansion_alerts"]) == 1
        alert = delta["permission_expansion_alerts"][0]
        assert alert["title"] == "MCP Tool Scope Expansion: query_tool"
        assert alert["severity"] == "HIGH"
        assert alert["confidence"] == "CONFIRMED"
        assert "SHELL_EXECUTION" in alert["added_permissions"]
        assert alert in delta["new_findings"]


class TestFeature4McpAuthExposureCheck:
    """4. MCP AUTH/EXPOSURE CHECK (basic version)"""

    def test_unauthenticated_network_server_config_flagged_high(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = {
                "mcpServers": {
                    "remote_weather": {
                        "url": "https://mcp.internal-enterprise.net/sse",
                        "transport": "sse"
                    }
                }
            }
            with open(os.path.join(td, "mcp.json"), "w", encoding="utf-8") as f:
                json.dump(cfg, f)

            res = analyze_mcp_authentication(td)
            unauth_findings = [f for f in res["findings"] if "Unauthenticated Network-Accessible MCP Server" in f["title"]]
            assert len(unauth_findings) == 1
            f = unauth_findings[0]
            assert f["severity"] == "HIGH"
            assert "CWE-306" in f.get("cwe", "")

    def test_local_stdio_server_not_flagged_as_unauthenticated(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = {
                "mcpServers": {
                    "local_files": {
                        "command": "uvx",
                        "transport": "stdio"
                    }
                }
            }
            with open(os.path.join(td, "mcp.json"), "w", encoding="utf-8") as f:
                json.dump(cfg, f)

            res = analyze_mcp_authentication(td)
            unauth_findings = [f for f in res["findings"] if f["title"] == "Unauthenticated Network-Accessible MCP Server"]
            assert len(unauth_findings) == 0
            stdio_findings = [f for f in res["findings"] if "stdio" in f["title"].lower()]
            assert len(stdio_findings) >= 1
            assert stdio_findings[0]["severity"] == "LOW"
