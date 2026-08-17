"""
MCP Runtime Firewall -- CLI entry point.

Provides a command-line interface to the MCP Runtime Firewall. Supports:
    - Evaluating tool calls against a policy interactively
    - Running a batch of test calls against a policy from JSON
    - Starting an interactive policy-testing loop
    - Exporting/importing policies

Usage:
    python firewall_cli.py                     # interactive mode
    python firewall_cli.py test-calls calls.json   # batch test
    python firewall_cli.py export-policy           # print default policy
    python firewall_cli.py add-rule "Rule name" --action BLOCK --tool_name "shell_exec"
"""
import argparse
import json
import sys

from firewall import Firewall, load_default_policy, VALID_ACTIONS


def interactive_mode(firewall):
    """Interactive loop: prompt for tool name + args, show firewall decision."""
    print("=" * 60)
    print("MCP Runtime Firewall -- Interactive Mode")
    print("  Type 'quit' or 'exit' to leave.")
    print("  Type 'log' to see audit log.")
    print("  Type 'clear' to clear audit log.")
    print("=" * 60)

    while True:
        tool_name = input("\nTool name: ").strip()
        if tool_name.lower() in ("quit", "exit", "q"):
            break
        if tool_name.lower() == "log":
            log = firewall.get_audit_log()
            if log:
                for entry in log:
                    print(f"  [{entry['action']}] {entry['tool']} via '{entry['rule']}' - {entry['reason'][:60]}")
            else:
                print("  (audit log is empty)")
            continue
        if tool_name.lower() == "clear":
            firewall.clear_audit_log()
            print("  Audit log cleared.")
            continue
        if not tool_name:
            continue

        desc = input("Description (optional): ").strip()

        args_raw = input("Arguments as JSON (or '{}'): ").strip()
        try:
            arguments = json.loads(args_raw) if args_raw else {}
        except json.JSONDecodeError:
            print(f"  Invalid JSON: {args_raw}")
            continue

        caps_raw = input("Capabilities (comma-separated, optional): ").strip()
        capabilities = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []

        decision = firewall.evaluate(tool_name, arguments, tool_description=desc, capabilities=capabilities)

        action = decision["action"]
        color = {"ALLOW": "\033[92m", "BLOCK": "\033[91m", "REQUIRE_APPROVAL": "\033[93m", "LOG": "\033[94m"}.get(action, "")
        reset = "\033[0m"
        print(f"\n  {color}[{action}]{reset} via rule '{decision['rule']}' (severity: {decision['severity']})")
        print(f"  Reason: {decision['reason']}")
        print(f"  Call ID: {decision['call_id']}")


def test_calls_mode(firewall, calls_file):
    """
    Read a JSON file of test calls and run them all through the firewall.
    The file should be a JSON array of objects with at least 'tool_name'
    and optionally 'arguments', 'description', 'capabilities'.
    """
    try:
        with open(calls_file, "r", encoding="utf-8") as f:
            calls = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading calls file: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(calls, list):
        print("Calls file must be a JSON array.", file=sys.stderr)
        sys.exit(2)

    results = []
    for call in calls:
        tool_name = call.get("tool_name", "unknown")
        arguments = call.get("arguments", {})
        desc = call.get("description", "")
        caps = call.get("capabilities", [])

        decision = firewall.evaluate(tool_name, arguments, tool_description=desc, capabilities=caps)
        results.append({
            "tool": tool_name,
            "action": decision["action"],
            "rule": decision["rule"],
            "severity": decision["severity"],
            "reason": decision["reason"],
            "call_id": decision["call_id"],
        })

    print(json.dumps(results, indent=2))

    blocked = sum(1 for r in results if r["action"] == "BLOCK")
    approved = sum(1 for r in results if r["action"] == "REQUIRE_APPROVAL")
    print(f"\nTotal calls: {len(results)} | BLOCKED: {blocked} | REQUIRE_APPROVAL: {approved}")

    if blocked > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="MCP Runtime Firewall -- rule-based policy enforcement for MCP tool calls.",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="interactive",
        choices=["interactive", "test-calls", "export-policy"],
        help="Operation mode (default: interactive).",
    )
    parser.add_argument("calls_file", nargs="?", help="JSON file of test calls (for test-calls mode).")
    parser.add_argument("--policy", help="Path to a JSON policy file (default: built-in policy).")
    parser.add_argument("--add-rule", metavar="NAME", help="Add a named rule before running.")
    parser.add_argument("--action", choices=sorted(VALID_ACTIONS), default="BLOCK",
                        help="Action for --add-rule (default: BLOCK).")
    parser.add_argument("--tool_name", help="Tool name pattern for --add-rule.")
    parser.add_argument("--capability", help="Capability filter for --add-rule.")
    args = parser.parse_args()

    if args.policy:
        try:
            with open(args.policy, "r", encoding="utf-8") as f:
                policy = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading policy: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        policy = load_default_policy()

    firewall = Firewall(policy)

    if args.add_rule:
        match = {}
        if args.tool_name:
            match["tool_name"] = args.tool_name
        if args.capability:
            match["capability"] = args.capability
        firewall.add_rule({
            "name": args.add_rule,
            "match": match,
            "action": args.action,
            "reason": f"User-added rule: {args.add_rule}",
            "severity": "HIGH" if args.action == "BLOCK" else "MEDIUM",
        })
        print(f"Added rule '{args.add_rule}' with action {args.action}.")

    if args.mode == "interactive":
        interactive_mode(firewall)
    elif args.mode == "test-calls":
        if not args.calls_file:
            print("Error: test-calls mode requires a calls_file argument.", file=sys.stderr)
            sys.exit(2)
        test_calls_mode(firewall, args.calls_file)
    elif args.mode == "export-policy":
        print(firewall.to_json())


if __name__ == "__main__":
    main()