import git
import os
import stat
import shutil

def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def download_repo(github_url, destination_folder="downloaded_repo"):
    if os.path.exists(destination_folder):
        shutil.rmtree(destination_folder, onerror=remove_readonly)

    print(f"Downloading from: {github_url}")
    print(f"Saving to: {destination_folder}")

    try:
        git.Repo.clone_from(github_url, destination_folder, depth=1)
        print("Success! The code has been downloaded.")
        return destination_folder
    except Exception as e:
        print(f"Something went wrong: {e}")
        return None

if __name__ == "__main__":
    url = input("Paste a GitHub URL to an MCP server: ")
    download_repo(url)