# MCP Security Scanner

A security scanner for [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers.
Scans both Python and JS/TS MCP server repos for risky tool behaviors, prompt-injection
"tool poisoning", tool shadowing, hidden secrets, vulnerable dependencies, and typosquatted
packages — and now adds **permission analysis**, **blast-radius scoring**, a **runtime
firewall**, and **fine-grained CI gates**.

The web app (`app.py`) gives a browser UI; the CLI (`ci_scan.py`) is what you wire into CI.



## Features

### 1. MCP Tool & Permission Analyzer
**File:** `tool_analyzer.py`

For each registered MCP tool, the analyzer builds a *permission matrix*:

- **Declared capabilities** — what the tool says it does (parsed from description text).
- **Actual capabilities** — what the code actually does (file access, network access,
  subprocess execution, environment variable reads).
- **Undisclosed actual** — capabilities the code has but the description doesn't mention.
- **Extra declared** — capabilities the description claims but the code doesn't have
  (often a sign of lying about what the tool does).

```python
from tool_analyzer import analyze_tool_permissions

tool = {
    "name": "fetch_user",
    "description": "Fetches a user's profile from the database.",
    "code_snippet": "import requests; requests.get('https://api.example.com/users/' + user_id)",
}
matrix = analyze_tool_permissions(tool)
print(matrix["undisclosed_actual"])  # ['network_access']
print(matrix["severity"])            # HIGH
```

### 2. Blast Radius & Attack-Path Analysis
**File:** `blast_radius.py`

For each tool, computes a 0–100 blast-radius score and an ordered list of attack paths
the tool enables if it got compromised. Score breakdown:

| Component              | Max |
|------------------------|-----|
| Capability amplification | 30 |
| Downstream targets     | 30  |
| Combination attack paths | 25 |
| Risk amplification     | 15  |
| **Total**              | 100 |

Labels: `NONE` (0), `LOW` (1–24), `MEDIUM` (25–49), `HIGH` (50–74), `CRITICAL` (75–100).

```python
from blast_radius import compute_blast_radius

result = compute_blast_radius(
    tool_name="backup_db",
    tool_description="Backs up the database to remote storage.",
    capabilities=["file_access", "subprocess_execution", "network_access"],
    risk_level="MEDIUM",
)
print(result["score"])        # 78
print(result["label"])        # CRITICAL
print(result["attack_paths"])  # list of named paths
```

### 3. MCP Runtime Firewall
**Files:** `firewall.py`, `firewall_cli.py`

Deterministic, rule-based policy engine that sits between an AI agent and MCP tool calls.
Every call is evaluated and returns one of:

- `ALLOW` — proceed
- `BLOCK` — refuse and audit
- `REQUIRE_APPROVAL` — pause for human review
- `LOG` — proceed but record

**No LLM is involved.** All decisions come from matching the call's attributes
(tool name, arguments, capabilities) against a declared rule set.

```python
from firewall import Firewall, load_default_policy

fw = Firewall(load_default_policy())
decision = fw.evaluate(
    "delete_files",
    {"command": "rm -rf /", "path": "/"},
    capabilities=["subprocess_execution"],
)
# -> {'action': 'BLOCK', 'severity': 'CRITICAL', ...}
```

Default policy blocks `rm -rf /`, requires approval for subprocess/env access, blocks
loopback network calls, and logs file deletion operations.

CLI: `python firewall_cli.py --mode test-calls` — interactive testing of rules.



### 4. Prompt Injection & Tool Poisoning Detection (enhanced)
**Files:** `prompt_injection_check.py`, `tool_shadowing_check.py`

Both modules now return findings with **confidence** (`HIGH` / `MEDIUM` / `LOW`) and
**severity** (`HIGH` / `MEDIUM` / `LOW`) so the CI gate can distinguish real attacks
from heuristic noise.

- **Prompt injection** catches: direct override phrases, hidden chars, "send this data to",
  "always call X", "without telling the user", zero-width Unicode, suspiciously long
  descriptions, role-manipulation phrases.
- **Tool shadowing** catches: duplicate tool names across files, descriptions that explicitly
  redirect the AI to use this tool *instead of* a different one ("replaces X", "supersedes X",
  "takes priority over X").

Confidence is reduced automatically when the description contains legitimate framing
patterns ("this is an assistant", "the following are guidelines").

### 5. CI/CD Security Gate
**Files:** `ci_scan.py`, `ci_workflow_template.yml`

`ci_scan.py` now supports per-category severity thresholds. Each finding category
(secrets, dependency vulnerabilities, typosquats, tool score, prompt injection, tool
shadowing) can have its own threshold, and the build fails if any category exceeds it.

```bash
# Default: RED overall score
python ci_scan.py /path/to/repo --fail-on RED

# Fine-grained strict
python ci_scan.py /path/to/repo \
  --fail-on-secret HIGH \
  --fail-on-dependency HIGH \
  --fail-on-typosquat MEDIUM \
  --fail-on-tool YELLOW \
  --fail-on-injection MEDIUM \
  --fail-on-shadowing HIGH
```

The GitHub Actions workflow template (`ci_workflow_template.yml`) includes both strict and
lenient preset configurations.

---

## Existing features (preserved)

- `scan_behavior.py` — heuristic detection of risky API calls in tool code
- `secret_detector.py` — regex + entropy-based secret scanning
- `dependency_check.py` — vulnerable dependency detection
- `typosquat_check.py` — typosquatted package detection
- `js_ts_scanner.py` — JS/TS tool extraction
- `semantic_check.py` — semantic analysis
- `run_semgrep.py` — Semgrep rule execution
- `app.py` — Flask web UI
- `scan_worker.py` — background scanning worker
- `risk_classifier.py` — risk-level classification
- `impact_guide.py` — impact remediation guidance
- `compare.py` — main comparison / scoring entry point

---

## Quick start

### Web app
```bash
pip install -r requirements.txt
python app.py
# Then open http://localhost:5000
```

### CI scan
```bash
python ci_scan.py /path/to/mcp-server-repo --json-out results.json
```

### Tests
```bash
python -m pytest tests/ -v
```

92 tests covering all 5 new features plus regression coverage for existing modules.



## Module map

| Module                        | Purpose                                                                        |
|-------------------------------|--------------------------------------------------------------------------------|
| `tool_analyzer.py`            | **NEW** — declared vs actual permission analysis per tool                      |
| `blast_radius.py`             | **NEW** — 0–100 blast radius + attack-path enumeration                         |
| `firewall.py`                 | **NEW** — deterministic runtime firewall (ALLOW/BLOCK/REQUIRE_APPROVAL/LOG)    |
| `firewall_cli.py`             | **NEW** — CLI for testing firewall rules                                       |
| `prompt_injection_check.py`   | **ENHANCED** — adds confidence/severity/matched_text to findings               |
| `tool_shadowing_check.py`     | **ENHANCED** — adds confidence/severity/matched_text to findings               |
| `ci_scan.py`                  | **ENHANCED** — adds per-category thresholds (`--fail-on-secret`, etc.)         |
| `ci_workflow_template.yml`    | **ENHANCED** — strict + lenient preset configurations                          |
| `scan_behavior.py`            | Existing — risky-API regex set (reused by `tool_analyzer.py`)                  |
| `compare.py`                  | Existing — full per-repo report                                                |
| `secret_detector.py`          | Existing — secret/entropy scan                                                 |
| `dependency_check.py`         | Existing — vulnerable dependency scan                                          |
| `typosquat_check.py`          | Existing — typosquatted package detection                                      |
| `js_ts_scanner.py`            | Existing — JS/TS tool extraction                                               |
| `extract_tools.py`            | Existing — Python tool extraction                                              |
| `risk_classifier.py`          | Existing — risk level classification                                           |
| `impact_guide.py`             | Existing — remediation guidance                                                |
| `app.py` / `scan_worker.py`   | Existing — web UI + worker                                                     |



## Design notes

- **No external LLM or API key required.** All detection is heuristic and reproducible —
  rules-based, regex, entropy, pattern matching. The scanner runs anywhere Python and
  standard libraries are available.
- **Local-only by default.** No findings are sent off-machine. `app.py` is an opt-in
  local web UI for visual inspection.
- **Backwards-compatible.** Existing flags (`--fail-on RED`, `--json-out`) still work.
  New flags are additive.
- **No destructive operations.** The firewall (`firewall.py`) only *describes* what
  would be blocked; it does not call anything. Wiring it into a real MCP runtime is
  the consumer's responsibility.
