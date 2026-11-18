"""
Base Scanner Interface for TrustAudit Platform.

All third-party and built-in scanner engines inherit from BaseScanner:
- check_available(): Checks if the tool CLI or underlying engine is installed.
- get_version(): Retrieves tool version string.
- health_check(): Returns engine operational telemetry.
- scan(target, **kwargs): Executes scan with timeout and safety constraints.
- parse_results(raw_output): Parses machine-readable JSON/text output.
- normalize_findings(raw_findings): Transforms findings into unified schema.
"""

import abc
import glob
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional


def get_extended_search_paths() -> List[str]:
    """Discovers additional potential binary installation paths on Windows and POSIX systems."""
    extra_paths = []
    home = os.path.expanduser("~")
    local_app = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    gopath = os.environ.get("GOPATH", "")

    if sys.platform.startswith("win"):
        # 1. WinGet symlink & package directories
        if local_app:
            extra_paths.append(os.path.join(local_app, "Microsoft", "WinGet", "Links"))
            extra_paths.append(os.path.join(local_app, "Microsoft", "WinGet", "Packages"))
            extra_paths.append(os.path.join(local_app, "Programs"))
            extra_paths.append(os.path.join(local_app, "Programs", "nuclei"))
            # Python WindowsApps and local package caches
            extra_paths.extend(glob.glob(os.path.join(local_app, "Packages", "PythonSoftwareFoundation*", "LocalCache", "local-packages", "*", "Scripts")))
            extra_paths.extend(glob.glob(os.path.join(local_app, "Programs", "Python", "*", "Scripts")))

        # 2. Go binaries (%USERPROFILE%\go\bin, %GOPATH%\bin)
        extra_paths.append(os.path.join(home, "go", "bin"))
        if gopath:
            extra_paths.append(os.path.join(gopath, "bin"))

        # 3. ProjectDiscovery Tool Manager (.pdtm) & tool default directories
        extra_paths.append(os.path.join(home, ".pdtm", "go", "bin"))
        extra_paths.append(os.path.join(home, ".projectdiscovery", "bin"))

        # 4. Package managers (Chocolatey, Scoop, Cargo, npm)
        extra_paths.append(r"C:\ProgramData\chocolatey\bin")
        extra_paths.append(os.path.join(home, "scoop", "shims"))
        extra_paths.append(os.path.join(home, "scoop", "apps", "nuclei", "current"))
        extra_paths.append(os.path.join(home, ".cargo", "bin"))
        extra_paths.append(os.path.join(home, "AppData", "Roaming", "npm"))
        extra_paths.append(os.path.join(home, "AppData", "Roaming", "Python", "*", "Scripts"))

        # 5. Standard Program Files
        extra_paths.append(os.path.join(program_files, "nuclei"))
        extra_paths.append(os.path.join(program_files_x86, "nuclei"))
        extra_paths.append(r"C:\Program Files\Git\cmd")
        extra_paths.append(r"C:\Program Files\Git\bin")
    else:
        extra_paths.extend([
            os.path.join(home, "go", "bin"),
            os.path.join(home, ".pdtm", "go", "bin"),
            os.path.join(home, ".projectdiscovery", "bin"),
            os.path.join(home, ".cargo", "bin"),
            os.path.join(home, ".local", "bin"),
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/opt/homebrew/opt/nuclei/bin",
        ])

    return [p for p in extra_paths if os.path.exists(p)]


def get_subprocess_env() -> Dict[str, str]:
    """Constructs environment dictionary with extended PATH for subprocess execution."""
    env = os.environ.copy()
    current_path = env.get("PATH", "")
    extra_paths = get_extended_search_paths()
    new_path = os.pathsep.join(extra_paths) + os.pathsep + current_path
    env["PATH"] = new_path
    return env


class BaseScanner(abc.ABC):
    """Abstract base class for all security scanner integrations."""

    def __init__(self, name: str, timeout_seconds: int = 30):
        self.name = name
        self.timeout_seconds = timeout_seconds
        self._cached_version: Optional[str] = None
        self._cached_binary_path: Optional[str] = None

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        """Finds executable path for the scanner binary in system PATH or extended search paths."""
        if self._cached_binary_path and os.path.exists(self._cached_binary_path):
            return self._cached_binary_path

        # 1. Check tool-specific environment variable (e.g. NUCLEI_PATH, GITLEAKS_PATH)
        env_var_name = f"{self.name.upper()}_PATH"
        custom_path = os.environ.get(env_var_name, "").strip()
        if custom_path:
            if os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
                self._cached_binary_path = custom_path
                return custom_path
            elif os.path.isdir(custom_path):
                for ext in ("", ".exe", ".cmd", ".bat"):
                    candidate = os.path.join(custom_path, f"{self.name}{ext}")
                    if os.path.isfile(candidate):
                        self._cached_binary_path = candidate
                        return candidate

        binary_names = candidates or [self.name]
        search_dirs = get_extended_search_paths()
        env_path = get_subprocess_env().get("PATH", "")

        for bname in binary_names:
            # 2. Standard shutil.which lookup across extended PATH
            path = shutil.which(bname, path=env_path)
            if path and os.path.isfile(path):
                self._cached_binary_path = path
                return path

            # 3. Check in extended search directories
            for sdir in search_dirs:
                for ext in ("", ".exe", ".cmd", ".bat"):
                    candidate = os.path.join(sdir, f"{bname}{ext}")
                    if os.path.isfile(candidate):
                        self._cached_binary_path = candidate
                        return candidate

        return None

    def check_available(self) -> bool:
        """Determines if the scanner binary is available in the execution environment."""
        return self.get_binary_path() is not None

    def get_version(self) -> Optional[str]:
        """Queries the scanner binary for its version string."""
        if self._cached_version:
            return self._cached_version
        bin_path = self.get_binary_path()
        if not bin_path:
            return None
        try:
            res = subprocess.run(
                [bin_path, "-version" if self.name == "nuclei" else "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env=get_subprocess_env(),
            )
            out = (res.stdout or res.stderr or "").strip()
            self._cached_version = out.splitlines()[0] if out else "installed"
            return self._cached_version
        except Exception:
            return "installed"

    def health_check(self) -> Dict[str, Any]:
        """Returns diagnostic telemetry for this scanner engine."""
        available = self.check_available()
        return {
            "name": self.name,
            "available": available,
            "version": self.get_version() if available else None,
            "binary_path": self.get_binary_path() if available else None,
            "status": "READY" if available else "UNAVAILABLE",
        }

    @abc.abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Executes a scan on the target path or URL.
        """
        pass

    def parse_results(self, raw_output: str, **kwargs) -> List[Dict[str, Any]]:
        """Parses scanner output into raw finding dictionaries."""
        return []

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalizes raw finding dicts into the standardized schema."""
        return raw_findings
