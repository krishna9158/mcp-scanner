TRUSTED_PACKAGES = {
    "requests", "flask", "django", "numpy", "pandas", "torch", "tensorflow",
    "boto3", "pytest", "sqlalchemy", "pydantic", "fastapi", "click", "aiohttp",
    "httpx", "cryptography", "pyyaml", "jinja2", "markdown", "beautifulsoup4",
    "selenium", "scrapy", "pillow", "matplotlib", "scikit-learn", "transformers",
    "langchain", "openai", "anthropic", "mcp", "gitpython", "semgrep", "pygit2",
    "urllib3", "certifi", "setuptools", "wheel", "pip", "virtualenv", "black",
    "flake8", "mypy", "tqdm", "python-dotenv", "redis", "celery", "gunicorn",
    "uvicorn", "starlette", "typer", "rich", "pyjwt", "passlib", "bcrypt",
}


def levenshtein_distance(a, b):
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(package_name):
    name_lower = package_name.lower()

    if name_lower in TRUSTED_PACKAGES:
        return None

    for trusted in TRUSTED_PACKAGES:
        if abs(len(name_lower) - len(trusted)) > 2:
            continue

        distance = levenshtein_distance(name_lower, trusted)
        max_allowed_distance = 1 if len(trusted) <= 4 else 2
        if 0 < distance <= max_allowed_distance:
            return {
                "package": package_name,
                "resembles": trusted,
                "distance": distance,
                "reason": (
                    f"'{package_name}' closely resembles the well-known package "
                    f"'{trusted}' (edit distance {distance}) - possible typosquatting."
                ),
            }

    return None


def scan_requirements_for_typosquatting(package_names):
    findings = []
    for name in package_names:
        result = check_typosquatting(name)
        if result:
            findings.append(result)
    return findings


# ---------------------------------------------------------------------------
# Popular Legitimate MCP Servers (17 well-known official & community servers)
# ---------------------------------------------------------------------------
POPULAR_MCP_SERVERS = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-drive",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-docker",
    "mcp-server-fetch",
    "mcp-server-kubernetes",
]


def check_mcp_typosquatting(package_name):
    """
    Checks if an MCP package name closely resembles one of the popular
    legitimate MCP servers using a similarity-distance check.
    """
    if not package_name or not isinstance(package_name, str):
        return None

    name_clean = package_name.strip().lower()

    # Exact match against popular list is legitimate
    if name_clean in [s.lower() for s in POPULAR_MCP_SERVERS]:
        return None

    for popular in POPULAR_MCP_SERVERS:
        pop_clean = popular.lower()

        # Homoglyphs check (e.g. 0 <-> o, 1 <-> l, rn <-> m)
        norm_name = name_clean.replace("0", "o").replace("1", "l").replace("rn", "m")
        norm_pop = pop_clean.replace("0", "o").replace("1", "l").replace("rn", "m")
        if norm_name == norm_pop and name_clean != pop_clean:
            return {
                "package": package_name,
                "resembles": popular,
                "distance": 1,
                "reason": f"'{package_name}' uses visual character substitution to impersonate popular MCP server '{popular}'."
            }

        if abs(len(name_clean) - len(pop_clean)) > 3:
            continue

        dist = levenshtein_distance(name_clean, pop_clean)
        if 0 < dist <= 2:
            return {
                "package": package_name,
                "resembles": popular,
                "distance": dist,
                "reason": f"'{package_name}' closely resembles popular MCP server '{popular}' (edit distance {dist}) - possible typosquatting."
            }

    return None


def scan_mcp_packages_for_typosquatting(package_names):
    """Scans a list of MCP package or tool names for typosquatting."""
    findings = []
    for name in package_names:
        result = check_mcp_typosquatting(name)
        if result:
            findings.append(result)
    return findings

