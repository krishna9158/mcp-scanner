"""
Impact and prevention guidance for every finding type this scanner
produces.

A raw label like "network_access mismatch" or "CRITICAL risk" tells an
expert what happened, but not why it matters or what to do about it. This
module turns each finding into a concrete, plain-language "if this is
real, here's what could actually happen" scenario, plus a specific fix -
the same pattern used by mature tools like GitHub security alerts or
Snyk. This is explanation, not new detection - it doesn't change what
gets flagged, only how clearly the result is communicated.
"""

CAPABILITY_IMPACT = {
    "network_access": {
        "impact": (
            "If a tool secretly makes network calls that its description never mentions, "
            "it could send your data (files, credentials, conversation content) to a "
            "server you never approved - including one controlled by an attacker. An AI "
            "agent that trusts the description would use this tool without knowing it "
            "talks to the outside world at all."
        ),
        "prevention": (
            "Update the tool's description to explicitly state what it connects to and "
            "why (e.g. 'fetches data from the company's internal API'). If the network "
            "call isn't actually necessary for the tool's stated purpose, remove it."
        ),
    },
    "subprocess_execution": {
        "impact": (
            "A tool that runs shell commands or other programs without saying so in its "
            "description is one of the most dangerous kinds of hidden behavior - if the "
            "command or its arguments can be influenced by user input, this can escalate "
            "into arbitrary code execution, letting an attacker run anything on the "
            "machine the tool runs on, including stealing files, installing malware, or "
            "pivoting to other systems on the same network."
        ),
        "prevention": (
            "Disclose command execution explicitly in the description. Validate/sanitize "
            "any input that reaches the command, avoid shell=True-style invocations where "
            "possible, and use an allow-list of permitted commands rather than passing "
            "arbitrary strings through to the shell."
        ),
    },
    "environment_access": {
        "impact": (
            "Environment variables are a common place secrets live - API keys, database "
            "passwords, cloud credentials. A tool that reads them without disclosing this "
            "could leak those secrets through its output, logs, or by sending them "
            "somewhere unexpected (especially dangerous when combined with an undisclosed "
            "network call)."
        ),
        "prevention": (
            "Disclose which environment variables the tool reads and why. Avoid reading "
            "broad environment access when only one specific value is needed, and never "
            "echo secret values back in tool output or error messages."
        ),
    },
    "file_access": {
        "impact": (
            "A tool that reads, writes, or deletes files without saying so could expose "
            "sensitive files (source code, config files, other users' data) or silently "
            "modify/delete something important. Lower severity than the categories above, "
            "but still a real disclosure gap."
        ),
        "prevention": (
            "Disclose file access in the description, and restrict the tool to only the "
            "specific directory/files it actually needs rather than open-ended filesystem "
            "access."
        ),
    },
}

RISK_LEVEL_PREVENTION = {
    "CRITICAL": (
        "Require explicit human confirmation before this tool executes (a 'are you sure?' "
        "step), rather than letting an AI agent call it autonomously. Consider whether "
        "this action needs to be exposed to an AI agent at all, versus handled through a "
        "traditional, audited workflow."
    ),
    "HIGH": (
        "Add logging/audit trails for every call to this tool, and consider rate-limiting "
        "or requiring confirmation for actions that affect other people or systems (like "
        "sending messages or granting access)."
    ),
    "MEDIUM": (
        "Make sure this tool's changes are reversible (versioning, soft-deletes, undo "
        "capability) since an AI agent may call it in ways a human wouldn't anticipate."
    ),
    "LOW": (
        "No specific action needed based on risk level alone - this tool appears to be "
        "primarily read-only or informational."
    ),
}

INJECTION_IMPACT = {
    "impact": (
        "If a tool's description contains hidden instructions aimed at the AI agent "
        "itself (rather than documentation for a human), an attacker who controls that "
        "description can manipulate the AI into taking actions the user never asked for - "
        "silently sending data elsewhere, calling other tools without permission, or "
        "hiding its actions from the user. This is one of the more severe categories, "
        "since it can compromise the AI's behavior across an entire session, not just "
        "this one tool call."
    ),
    "prevention": (
        "Rewrite the description in plain, factual language describing only what the "
        "tool does - remove any language that instructs behavior ('always', 'never', "
        "'don't tell the user'), and strip any invisible/zero-width characters. If you're "
        "evaluating a third-party MCP server, treat descriptions with this kind of "
        "language as a strong reason not to install it."
    ),
}

SHADOWING_IMPACT = {
    "impact": (
        "If two tools share the same name, or one tool's description tries to redirect "
        "calls meant for another tool, whichever one actually runs when it's called "
        "becomes unpredictable and attacker-influenceable - a malicious tool can "
        "effectively impersonate a trusted one, intercepting calls and data meant for it."
    ),
    "prevention": (
        "Rename tools so every name is unique across the server, and remove any "
        "description language that references or tries to override another tool by "
        "name. If evaluating a third-party server, be suspicious of any tool whose "
        "description talks about other tools at all."
    ),
}

SECRET_IMPACT = {
    "impact": (
        "A hardcoded secret (API key, password, token) committed to a public or "
        "shared repository can be found and used by anyone who can see the code - "
        "including automated bots that scan GitHub specifically for leaked credentials, "
        "often within minutes of a commit going public. This can lead to unauthorized "
        "access to whatever service that key controls (cloud infrastructure, payment "
        "systems, customer data)."
    ),
    "prevention": (
        "Remove the secret from the code and rotate it immediately (treat it as "
        "compromised, even if you catch it quickly) - assume it's been seen. Load "
        "secrets from environment variables or a secrets manager instead, and add the "
        "file to .gitignore if it shouldn't be tracked at all."
    ),
}

DEPENDENCY_IMPACT = {
    "impact": (
        "A dependency with a known, published vulnerability (CVE) means the exact "
        "weakness is public knowledge - attackers can look up which vulnerable versions "
        "are still in use and target them specifically, often with existing, "
        "ready-made exploit code, since the details are already documented publicly."
    ),
    "prevention": (
        "Upgrade the package to a patched version. If no patch exists yet, check the "
        "vulnerability's details for a workaround, or consider whether the dependency "
        "can be replaced or removed entirely."
    ),
}

TYPOSQUAT_IMPACT = {
    "impact": (
        "A typosquatted package name (e.g. 'reqeusts' instead of 'requests') is a "
        "classic supply-chain attack: someone publishes a malicious package under a name "
        "close enough to a popular one that a small typo or misconfiguration installs "
        "the malicious version instead. Once installed, it runs with the same "
        "permissions as any other dependency - it can read files, exfiltrate secrets, "
        "or install further malware, often silently."
    ),
    "prevention": (
        "Double-check the exact package name against the real package's official page "
        "before adding it to requirements.txt. If this was unintentional, replace it "
        "with the correct package name and audit whether the wrong package was ever "
        "actually installed and run."
    ),
}


def get_capability_impact(category):
    return CAPABILITY_IMPACT.get(category)


def get_risk_prevention(risk_level):
    return RISK_LEVEL_PREVENTION.get(risk_level, "")
