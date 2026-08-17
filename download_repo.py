import git
import os
import re
import stat
import shutil
import uuid
import tempfile

GITHUB_URL_PATTERN = re.compile(
    r'^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?$'
)


def normalize_github_url(url):
    """
    Normalizes user-supplied GitHub URLs, allowing inputs like:
    - https://github.com/owner/repo
    - http://github.com/owner/repo
    - github.com/owner/repo
    - owner/repo
    - https://github.com/owner/repo.git
    - https://github.com/owner/repo/tree/main
    """
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:"):]
    elif not url.startswith("http://") and not url.startswith("https://"):
        if url.startswith("github.com/"):
            url = "https://" + url
        elif re.match(r'^[\w.-]+/[\w.-]+$', url):
            url = f"https://github.com/{url}"

    match = re.match(r'^(https?://github\.com/[\w.-]+/[\w.-]+?)(?:/(?:tree|blob)/.+)?(?:\.git)?/?$', url)
    if match:
        base = match.group(1)
        if base.startswith("http://"):
            base = "https://" + base[len("http://"):]
        return base
    return url


def is_valid_github_url(url):
    if not url or not isinstance(url, str):
        return False
    normalized = normalize_github_url(url)
    return bool(normalized and GITHUB_URL_PATTERN.match(normalized))


def remove_readonly(func, path, excinfo):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def download_repo(github_url, destination_folder=None):
    normalized = normalize_github_url(github_url)
    if not normalized or not is_valid_github_url(normalized):
        print(f"Rejected URL (must look like https://github.com/<owner>/<repo>): {github_url}")
        return None

    if destination_folder is None:
        destination_folder = os.path.join(
            tempfile.gettempdir(), f"mcp_scan_{uuid.uuid4().hex[:12]}"
        )

    print(f"Downloading from: {normalized}")
    print(f"Saving to: {destination_folder}")

    try:
        env = os.environ.copy()
        env["GIT_ALLOW_PROTOCOL"] = "https"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "echo"
        env["GIT_HTTP_LOW_SPEED_LIMIT"] = "1000"
        env["GIT_HTTP_LOW_SPEED_TIME"] = "30"
        git.Repo.clone_from(normalized, destination_folder, depth=1, env=env)
        print("Success! The code has been downloaded.")
        return destination_folder
    except Exception as e:
        print(f"Something went wrong: {e}")
        if os.path.exists(destination_folder):
            shutil.rmtree(destination_folder, onerror=remove_readonly)
        return None


if __name__ == "__main__":
    url = input("Paste a GitHub URL to an MCP server: ")
    download_repo(url)

