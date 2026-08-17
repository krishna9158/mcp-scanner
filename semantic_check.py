import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import requests
except ImportError:
    requests = None

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"


_semantic_check_failed_permanently = False


def semantic_check_available():
    global _semantic_check_failed_permanently
    if _semantic_check_failed_permanently:
        return False
    return bool(os.environ.get("ANTHROPIC_API_KEY")) and requests is not None


def verify_mismatch_with_llm(tool_name, description, category, code_snippet):
    global _semantic_check_failed_permanently
    if _semantic_check_failed_permanently:
        return {
            "covered": False,
            "reasoning": "Semantic verification skipped (previous API call failed).",
        }

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
            timeout=5,
        )
        if response.status_code in (401, 403):
            _semantic_check_failed_permanently = True
            return {
                "covered": False,
                "reasoning": "Anthropic API key is invalid or unauthorized - disabling semantic verification for remaining tools.",
            }
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

