import git
import os
import stat
import shutil
import uuid
import tempfile

def remove_readonly(func, path, excinfo):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass  # best-effort cleanup only - never let cleanup failures crash a scan

def download_repo(github_url, destination_folder=None):
    # Give every scan its own unique folder instead of reusing/deleting one
    # fixed folder. Reusing one folder meant deleting the previous clone
    # before every new scan - on Windows, git or antivirus sometimes still
    # holds a lock on files inside .git/objects/pack, causing WinError 32.
    # A fresh folder per scan avoids needing that delete at all.
    if destination_folder is None:
        destination_folder = os.path.join(
            tempfile.gettempdir(), f"mcp_scan_{uuid.uuid4().hex[:12]}"
        )

    print(f"Downloading from: {github_url}")
    print(f"Saving to: {destination_folder}")

    try:
        git.Repo.clone_from(github_url, destination_folder, depth=1)
        print("Success! The code has been downloaded.")
        return destination_folder
    except Exception as e:
        print(f"Something went wrong: {e}")
        # Best-effort cleanup of a partial clone; ignore if it fails
        if os.path.exists(destination_folder):
            shutil.rmtree(destination_folder, onerror=remove_readonly)
        return None

if __name__ == "__main__":
    url = input("Paste a GitHub URL to an MCP server: ")
    download_repo(url)