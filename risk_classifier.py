import re

RISK_KEYWORDS = {
    "CRITICAL": [
        "delete", "drop", "wipe", "destroy", "purge", "format",
        "transfer_money", "transfer_funds", "send_payment", "pay", "withdraw",
        "shutdown", "terminate", "kill_process", "sudo", "root_access",
    ],
    "HIGH": [
        "send_email", "send_message", "post_public", "publish", "broadcast",
        "grant_access", "revoke", "admin", "override", "bypass", "escalate",
        "execute_command", "run_shell", "eval_code", "exec_code",
    ],
    "MEDIUM": [
        "update", "modify", "write", "create", "upload", "edit", "change_password",
        "reset_password", "install", "uninstall", "deploy",
    ],
}

RISK_EXPLANATIONS = {
    "CRITICAL": "This tool's name/description suggests it can cause irreversible or high-impact harm (data loss, financial transactions, system shutdown).",
    "HIGH": "This tool's name/description suggests it can affect other people or systems (sending messages, granting access, running commands).",
    "MEDIUM": "This tool's name/description suggests it modifies data or state, but in a typically reversible way.",
    "LOW": "This tool appears to be primarily read-only or informational based on its name/description.",
}


def classify_tool_risk(name, description):
    combined_text = f"{name} {description}".lower()
    combined_text = re.sub(r'[_\-]', ' ', combined_text)

    for level in ("CRITICAL", "HIGH", "MEDIUM"):
        for keyword in RISK_KEYWORDS[level]:
            normalized_keyword = keyword.replace("_", " ")
            if re.search(r'\b' + re.escape(normalized_keyword) + r'\b', combined_text):
                return {
                    "risk_level": level,
                    "matched_keyword": keyword,
                    "explanation": RISK_EXPLANATIONS[level],
                }

    return {
        "risk_level": "LOW",
        "matched_keyword": None,
        "explanation": RISK_EXPLANATIONS["LOW"],
    }
