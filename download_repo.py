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


def is_valid_github_url(url):
    if not url or not isinstance(url, str):
        return False
    return bool(GITHUB_URL_PATTERN.match(url.strip()))


def remove_readonly(func, path, excinfo):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def download_repo(github_url, destination_folder=None):
    if not is_valid_github_url(github_url):
        print(f"Rejected URL (must look like https://github.com/<owner>/<repo>): {github_url}")
        return None

    if destination_folder is None:
        destination_folder = os.path.join(
            tempfile.gettempdir(), f"mcp_scan_{uuid.uuid4().hex[:12]}"
        )

    print(f"Downloading from: {github_url}")
    print(f"Saving to: {destination_folder}")

    try:
        env = os.environ.copy()
        env["GIT_ALLOW_PROTOCOL"] = "https"
        git.Repo.clone_from(github_url, destination_folder, depth=1, env=env)
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
