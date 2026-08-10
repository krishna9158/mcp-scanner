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
