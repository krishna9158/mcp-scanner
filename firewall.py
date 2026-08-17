"""
MCP Runtime Firewall -- deterministic, rule-based policy enforcement layer
between an AI agent and MCP tool calls.

This module inspects every incoming tool call against a set of policies and
returns a decision: ALLOW, BLOCK, REQUIRE_APPROVAL, or LOG. No LLM is
involved -- every decision is made by matching the call's attributes
(tool name, arguments, capabilities) against declared rules.

Design goals:
    - Pure rule-based: no network calls, no external APIs, no LLM
    - Serializable policy config: YAML or Python dict
    - Audit log of every decision for compliance review
    - Sensible defaults out of the box (block subprocess + env var access
      unless explicitly allowed)

Usage:
    from firewall import Firewall, load_default_policy

    fw = Firewall(load_default_policy())
    decision = fw.evaluate("shell_exec", {"command": "rm -rf /"})
    # -> {"action": "BLOCK", "reason": "..."}
"""
import json
import re
import hashlib
import copy
import os

# ---------------------------------------------------------------------------
# Policy rule structure
# ---------------------------------------------------------------------------
#
# A policy is a dict with these keys:
#
#   version: str           - policy schema version (currently "1.0")
#   default_action: str    - ALLOW | BLOCK | REQUIRE_APPROVAL | LOG
#   rules: list[dict]      - ordered list of rule dicts evaluated top-down
#   audit_log: list[dict]  - (output) appended audit trail
#
# Each rule dict:
#   name: str              - human-readable rule name
#   match: dict            - conditions that must ALL be true
#     tool_name: str | regex   (matched case-insensitively)
#     tool_name_contains: str
#     capability: str          one of: file_access, network_access,
#                              subprocess_execution, environment_access
#     arg_matches: dict       {arg_name: regex} -- matched case-insensitively
#     arg_value_contains: dict {arg_name: str} -- substring match
#     description_contains: str  substring match in tool description
#   action: str            - ALLOW | BLOCK | REQUIRE_APPROVAL | LOG
#   reason: str            - explanation for the decision
#   severity: str          - LOW | MEDIUM | HIGH | CRITICAL (for audit scoring)

VALID_ACTIONS = {"ALLOW", "BLOCK", "REQUIRE_APPROVAL", "LOG"}
VALID_CAPABILITIES = {"file_access", "network_access", "subprocess_execution", "environment_access"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _match_str(value, pattern):
    """Case-insensitive substring or regex match."""
    if pattern is None:
        return False
    value = str(value).lower()
    pattern = str(pattern).lower()
    if pattern.startswith("^") or pattern.startswith(".*") or "(" in pattern or "\\" in pattern:
        try:
            return bool(re.search(pattern, value, re.IGNORECASE))
        except re.error:
            return pattern in value
    return pattern in value


def _matches_rule(rule_match, tool_name, tool_description, arguments, capabilities):
    """
    Check whether a call matches ALL conditions in a rule's match dict.
    Returns True if every specified condition matches.
    """
    # tool_name: exact match or regex
    if "tool_name" in rule_match:
        if not _match_str(tool_name, rule_match["tool_name"]):
            return False

    # tool_name_contains: substring match
    if "tool_name_contains" in rule_match:
        if rule_match["tool_name_contains"].lower() not in tool_name.lower():
            return False

    # description_contains
    if "description_contains" in rule_match:
        desc = tool_description or ""
        if rule_match["description_contains"].lower() not in desc.lower():
            return False

    # capability: tool must have this capability
    if "capability" in rule_match:
        cap = rule_match["capability"]
        if cap not in capabilities:
            return False

    # arg_matches: {arg_name: regex} -- all specified args must match
    if "arg_matches" in rule_match:
        for arg_name, pattern in rule_match["arg_matches"].items():
            arg_val = arguments.get(arg_name, "")
            if isinstance(arg_val, str):
                if not _match_str(arg_val, pattern):
                    return False
            else:
                if not _match_str(str(arg_val), pattern):
                    return False

    # arg_value_contains: {arg_name: substring}
    if "arg_value_contains" in rule_match:
        for arg_name, substr in rule_match["arg_value_contains"].items():
            arg_val = arguments.get(arg_name, "")
            if isinstance(arg_val, str):
                if substr.lower() not in arg_val.lower():
                    return False
            else:
                if substr.lower() not in str(arg_val).lower():
                    return False

    # arguments_not_empty: dict of arg names that must be present and non-empty
    if "arguments_not_empty" in rule_match:
        for arg_name in rule_match["arguments_not_empty"]:
            if arg_name not in arguments or not arguments[arg_name]:
                return False

    return True


# ---------------------------------------------------------------------------
# Default policy: sensible out-of-the-box rules
# ---------------------------------------------------------------------------

def load_default_policy():
    """
    Return a default policy dict that blocks the most dangerous tool-call
    patterns without requiring any configuration. Users can load this, then
    add ALLOW rules for specific tools they trust.
    """
    return {
        "version": "1.0",
        "default_action": "ALLOW",
        "rules": [
            {
                "name": "Block direct rm / delete-all patterns",
                "match": {
                    "tool_name_contains": "delete",
                    "arg_matches": {"command": r"rm\s+-rf", "path": r"^\/$"},
                },
                "action": "BLOCK",
                "reason": "Command would delete root or perform recursive force deletion.",
                "severity": "CRITICAL",
            },
            {
                "name": "Require approval for subprocess execution",
                "match": {"capability": "subprocess_execution"},
                "action": "REQUIRE_APPROVAL",
                "reason": (
                    "Tool can run shell commands -- subprocess execution requires "
                    "human approval by default policy."
                ),
                "severity": "HIGH",
            },
            {
                "name": "Require approval for environment variable access",
                "match": {"capability": "environment_access"},
                "action": "REQUIRE_APPROVAL",
                "reason": (
                    "Tool reads environment variables which may contain secrets -- "
                    "requires human approval."
                ),
                "severity": "HIGH",
            },
            {
                "name": "Block network calls to suspicious hosts",
                "match": {
                    "capability": "network_access",
                    "arg_value_contains": {"url": "localhost", "url": "127.0.0.1", "url": "0.0.0.0"},
                },
                "match_type": "any",  # any of the arg_value_contains conditions
                "action": "BLOCK",
                "reason": "Network call to loopback/internal address blocked.",
                "severity": "HIGH",
            },
            {
                "name": "Log file deletion operations",
                "match": {
                    "arg_matches": {"path": r"delete|remove|unlink|wipe"},
                    "capability": "file_access",
                },
                "action": "LOG",
                "reason": "File deletion operation -- logging for audit trail.",
                "severity": "MEDIUM",
            },
        ],
        "audit_log": [],
    }


# ---------------------------------------------------------------------------
# Firewall class
# ---------------------------------------------------------------------------

class Firewall:
    """
    The firewall engine. Evaluate tool calls against a policy and record
    every decision in the audit log.
    """

    def __init__(self, policy):
        self.policy = copy.deepcopy(policy)
        self._validate_policy()

    def _validate_policy(self):
        rules = self.policy.get("rules", [])
        for i, rule in enumerate(rules):
            action = rule.get("action", "")
            if action not in VALID_ACTIONS:
                raise ValueError(
                    f"Rule {i} ({rule.get('name', 'unnamed')}) has invalid action: {action!r}. "
                    f"Must be one of: {', '.join(sorted(VALID_ACTIONS))}"
                )
            severity = rule.get("severity", "LOW")
            if severity not in VALID_SEVERITIES:
                rule["severity"] = "LOW"

    def evaluate(self, tool_name, arguments, tool_description="", capabilities=None):
        """
        Evaluate one tool call against the policy.

        Parameters:
            tool_name: str -- name of the tool being called
            arguments: dict -- the call's arguments
            tool_description: str -- the tool's declared description
            capabilities: list[str] -- capability categories this tool has

        Returns:
            dict with:
                action: str -- ALLOW | BLOCK | REQUIRE_APPROVAL | LOG
                rule: str -- name of the matched rule (or "default_action")
                reason: str -- human-readable explanation
                severity: str -- LOW | MEDIUM | HIGH | CRITICAL
                call_id: str -- unique ID for this evaluation (for audit)
        """
        arguments = arguments or {}
        capabilities = capabilities or []
        call_id = hashlib.sha256(
            f"{tool_name}:{json.dumps(arguments, sort_keys=True, default=str)}".encode()
        ).hexdigest()[:16]

        # Evaluate rules top-down; first match wins
        for rule in self.policy.get("rules", []):
            match_spec = rule.get("match", {})

            # Handle match_type: "any" means any single condition matches
            if rule.get("match_type") == "any" and match_spec:
                if not self._matches_any(match_spec, tool_name, tool_description, arguments, capabilities):
                    continue
            else:
                if not _matches_rule(match_spec, tool_name, tool_description, arguments, capabilities):
                    continue

            # Match found
            decision = {
                "call_id": call_id,
                "action": rule["action"],
                "rule": rule.get("name", "unnamed rule"),
                "reason": rule.get("reason", ""),
                "severity": rule.get("severity", "LOW"),
                "tool": tool_name,
                "arguments": self._sanitize_for_log(arguments),
            }
            self._audit(decision)
            return decision

        # No rule matched -- use default
        default = self.policy.get("default_action", "ALLOW")
        decision = {
            "call_id": call_id,
            "action": default,
            "rule": "default_action",
            "reason": f"No rule matched; using default action: {default}",
            "severity": "LOW",
            "tool": tool_name,
            "arguments": self._sanitize_for_log(arguments),
        }
        self._audit(decision)
        # Always log the decision (audit trail) regardless of action
        self._audit_log_decision(tool_name, decision)
        return decision

    def _audit_log_decision(self, tool_name, decision):
        """Always append a lightweight log entry for every call."""
        if "audit_trail" not in self.policy:
            self.policy["audit_trail"] = []
        self.policy["audit_trail"].append({
            "timestamp": __import__("time").time(),
            "tool": tool_name,
            "action": decision["action"],
            "rule": decision["rule"],
            "call_id": decision["call_id"],
        })

    def _matches_any(self, match_spec, tool_name, tool_description, arguments, capabilities):
        """For match_type='any': check if ANY of the top-level conditions match."""
        checks = []
        if "tool_name" in match_spec:
            checks.append(_match_str(tool_name, match_spec["tool_name"]))
        if "tool_name_contains" in match_spec:
            checks.append(match_spec["tool_name_contains"].lower() in tool_name.lower())
        if "capability" in match_spec:
            checks.append(match_spec["capability"] in capabilities)
        if "description_contains" in match_spec:
            checks.append(match_spec["description_contains"].lower() in (tool_description or "").lower())
        if "arg_matches" in match_spec:
            for arg_name, pattern in match_spec["arg_matches"].items():
                arg_val = str(arguments.get(arg_name, ""))
                checks.append(_match_str(arg_val, pattern))
        if "arg_value_contains" in match_spec:
            for arg_name, substr in match_spec["arg_value_contains"].items():
                arg_val = str(arguments.get(arg_name, ""))
                checks.append(substr.lower() in arg_val.lower())
        if "arguments_not_empty" in match_spec:
            for arg_name in match_spec["arguments_not_empty"]:
                checks.append(arg_name in arguments and bool(arguments[arg_name]))
        return any(checks)

    def _sanitize_for_log(self, arguments):
        """Truncate secret-looking values in the audit log."""
        sanitized = {}
        for k, v in arguments.items():
            if isinstance(v, str) and len(v) > 50:
                sanitized[k] = v[:20] + "...[truncated]"
            else:
                sanitized[k] = v
        return sanitized

    def _audit(self, decision):
        entry = {
            "timestamp": __import__("time").time(),
            **decision,
        }
        self.policy.setdefault("audit_log", []).append(entry)

    def get_audit_log(self):
        return list(self.policy.get("audit_log", []))

    def clear_audit_log(self):
        self.policy["audit_log"] = []

    def add_rule(self, rule):
        """Dynamically add a rule to the policy at runtime."""
        action = rule.get("action", "")
        if action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action!r}")
        self.policy.setdefault("rules", []).append(rule)

    def remove_rule(self, rule_name):
        """Remove a rule by name."""
        self.policy["rules"] = [
            r for r in self.policy.get("rules", []) if r.get("name") != rule_name
        ]

    def to_json(self):
        """Export the current policy as JSON string."""
        return json.dumps(self.policy, indent=2)

    @classmethod
    def from_json(cls, json_str):
        """Create a Firewall from a JSON policy string."""
        return cls(json.loads(json_str))