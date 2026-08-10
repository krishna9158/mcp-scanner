"""
Worker function for running a scan in its own isolated process.

This lives in its own file on purpose - it must NOT be defined inside
app.py. Python's multiprocessing needs to be able to import the target
function by name in the new background process it starts. When the
function instead lives inside the script you run directly (app.py, which
becomes the "__main__" module when you type "python app.py"), some Python
installs - notably the Windows Store version of python.exe - fail to
correctly re-import "__main__" in that new process, causing an error like:

    AttributeError: Can't get attribute '_run_scan_worker' on
    <module '__main__' (<class '_frozen_importlib.BuiltinImporter'>)>

Putting the function in its own ordinary, importable module avoids that
problem entirely: the background process can just "import scan_worker"
like any other module, regardless of how the main script was launched.
"""
import os
from download_repo import download_repo
from compare import compare
from secret_detector import scan_folder_for_secrets
from dependency_check import scan_dependencies, parse_requirements_txt
from typosquat_check import scan_requirements_for_typosquatting


def run_scan_worker(github_url, full_scan, destination_folder, result_queue):
    """
    Runs in a separate process. Never talks to Flask directly - just puts
    a plain (status, payload) tuple on the queue for the parent process to
    read. "full_scan" (no file limit) is only ever honored here, inside
    this isolated, killable child process - never on an unbounded thread.
    """
    try:
        folder = download_repo(github_url, destination_folder=destination_folder)
        if not folder:
            result_queue.put(("error", "Could not download that repo. Double-check the GitHub URL is correct and public."))
            return
        report, warning = compare(folder, full_scan=full_scan)
        secrets = scan_folder_for_secrets(folder)
        dependencies = scan_dependencies(folder, max_packages=30)

        typosquats = []
        req_path = os.path.join(folder, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    packages = parse_requirements_txt(f.read())
                package_names = [name for name, _version in packages]
                typosquats = scan_requirements_for_typosquatting(package_names)
            except Exception:
                pass  # typosquat check is a bonus signal - never let it block a scan

        result_queue.put(("ok", (report, warning, secrets, dependencies, typosquats)))
    except Exception as e:
        result_queue.put(("error", str(e)))
