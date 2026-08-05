import os

try:
    import requests
except ImportError:
    requests = None

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-3-5-haiku-latest"  # fast/cheap model - good enough for a yes/no judgment call


def semantic_check_available():
    """
    True only if an ANTHROPIC_API_KEY is set in the environment and the
    requests library is available. If not, semantic verification is
    silently skipped and the scanner falls back to keyword-only matching -
    it never crashes or blocks a scan just because this isn't configured.
    """
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and requests is not None


def verify_mismatch_with_llm(tool_name, description, category, code_snippet):
    """
    Second opinion on top of cheap keyword matching. Keyword matching alone
    would flag a description like "retrieves data from a remote server" as
    NOT mentioning network access, just because the literal word "network"
    isn't present - even though a human reader would clearly understand it
    does. This asks an LLM to judge the actual meaning instead of just
    checking for exact words.

    Returns a dict: {"covered": bool, "reasoning": str}
    On any failure (no API key, network error, bad response), returns
    covered=False so the original keyword-based mismatch is kept as-is -
    this is a strictly additive check, never a way to silently hide a
    real finding.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key or requests is None:
        return {
            "covered": False,
            "reasoning": "Semantic verification not configured (no ANTHROPIC_API_KEY set) - using keyword match result.",
        }

    readable_category = category.replace("_", " ")
    prompt = (
        f"A software tool named '{tool_name}' has this description:\n"
        f"\"{description}\"\n\n"
        f"Its actual code was found to perform: {readable_category}.\n"
        f"Here is a snippet of its code:\n{code_snippet[:800]}\n\n"
        f"Question: Does the description reasonably and honestly convey to a reader "
        f"that this tool performs {readable_category}, even if it doesn't use that "
        f"exact phrase? Answer with only one word first (YES or NO), then a dash, "
        f"then a one-sentence reason. Example: 'YES - the description mentions "
        f"fetching remote data, which implies network access.'"
    )

    try:
        response = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 150,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        ).strip()

        covered = text.upper().startswith("YES")
        reasoning = text.split("-", 1)[1].strip() if "-" in text else text
        return {"covered": covered, "reasoning": reasoning}

    except Exception as e:
        return {
            "covered": False,
            "reasoning": f"Semantic verification call failed ({e}) - keeping keyword-based result.",
        }
