"""
TrustAudit Software Component Inventory & SBOM Extraction Engine.

Discovers, extracts, and stores structured software component inventories (SBOM)
across repositories, manifest files, and web perimeter technologies:
- Node.js: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- Python: requirements.txt, Pipfile.lock, poetry.lock, pyproject.toml
- Java: pom.xml, build.gradle
- Go: go.mod, go.sum
- Rust: Cargo.toml, Cargo.lock
- Web Technologies: Web frameworks, HTTP servers, TLS libraries
"""

import json
import os
import re
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

DATA_FILE = os.path.join(os.path.dirname(__file__), "inventory_data.json")


def _load_inventory_store() -> Dict[str, Any]:
    """Loads stored inventory components."""
    if not os.path.exists(DATA_FILE):
        initial = {"components": {}, "manifests": {}}
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(initial, f, indent=2)
        except Exception:
            pass
        return initial
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"components": {}, "manifests": {}}


def _save_inventory_store(data: Dict[str, Any]) -> None:
    """Persists inventory components."""
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[INVENTORY] Failed to save inventory data: {e}", flush=True)


# ---------------------------------------------------------------------------
# Manifest Parsers
# ---------------------------------------------------------------------------

def parse_requirements_txt(content: str) -> List[Tuple[str, str]]:
    """Parses pinned dependencies from requirements.txt."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2)))
        else:
            # Unpinned or ranged package
            match_unpinned = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if match_unpinned:
                pkg_name = match_unpinned.group(1).lower()
                if pkg_name not in ("git+", "https:", "http:"):
                    packages.append((pkg_name, "UNKNOWN VERSION"))
    return packages


def parse_poetry_lock(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from poetry.lock."""
    packages = []
    current_name = None
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[[package]]"):
            current_name = None
        elif line.startswith("name = "):
            m = re.match(r'name\s*=\s*"([^"]+)"', line)
            if m:
                current_name = m.group(1).lower()
        elif line.startswith("version = ") and current_name:
            m = re.match(r'version\s*=\s*"([^"]+)"', line)
            if m:
                packages.append((current_name, m.group(1)))
                current_name = None
    return packages


def parse_pipfile_lock(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from Pipfile.lock."""
    packages = []
    try:
        data = json.loads(content)
        for section in ("default", "develop"):
            for pkg, meta in data.get(section, {}).items():
                if isinstance(meta, dict):
                    raw_ver = meta.get("version", "")
                    clean_ver = raw_ver.replace("==", "").strip()
                    packages.append((pkg.lower(), clean_ver or "UNKNOWN VERSION"))
    except Exception:
        pass
    return packages


def parse_pyproject_toml(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from pyproject.toml."""
    packages = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^\[.*dependencies.*\]", line, re.I):
            in_deps = True
            continue
        elif line.startswith("["):
            in_deps = False
            continue
        if in_deps and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip().strip('"').strip("'").lower()
            val = parts[1].strip().strip('"').strip("'")
            clean_ver = re.sub(r"[\^~>=<]", "", val).strip()
            if name and not name.startswith("#"):
                packages.append((name, clean_ver if re.match(r"^\d", clean_ver) else "UNKNOWN VERSION"))
    return packages


def parse_package_json(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from package.json or package-lock.json."""
    packages = []
    try:
        data = json.loads(content)
    except Exception:
        return packages

    # 1. package.json direct dependencies
    for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(dep_key, {})
        if isinstance(deps, dict):
            for name, ver in deps.items():
                clean_ver = re.sub(r"[\^~>=<]", "", ver).strip()
                packages.append((name, clean_ver if re.match(r"^\d", clean_ver) else "UNKNOWN VERSION"))

    # 2. package-lock.json packages tree
    lock_pkgs = data.get("packages", {})
    if isinstance(lock_pkgs, dict):
        for pkg_path, meta in lock_pkgs.items():
            if isinstance(meta, dict) and meta.get("version"):
                name = meta.get("name") or pkg_path.replace("node_modules/", "")
                if name and not name.startswith("node_modules/"):
                    packages.append((name, meta["version"]))

    # 3. package-lock.json v1 dependencies tree
    v1_deps = data.get("dependencies", {})
    if isinstance(v1_deps, dict):
        for name, meta in v1_deps.items():
            if isinstance(meta, dict) and meta.get("version"):
                packages.append((name, meta["version"]))

    return list(dict.fromkeys(packages))


def parse_yarn_lock(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from yarn.lock (v1 & v2+)."""
    packages = []
    current_pkg = None
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Header line e.g. "next@^15.2.0", "@types/node@^20.0.0":
        if line.endswith(":") and not line.startswith("version"):
            header = line.rstrip(":")
            # Extract package name before @version
            for part in header.split(","):
                part = part.strip().strip('"').strip("'")
                m = re.match(r"^(@?[^@]+)@", part)
                if m:
                    current_pkg = m.group(1)
                    break
        elif line.startswith("version ") or line.startswith('version:'):
            m = re.search(r'version[:\s]+["\']?([^"\'\s]+)["\']?', line)
            if m and current_pkg:
                packages.append((current_pkg, m.group(1)))
                current_pkg = None
    return list(dict.fromkeys(packages))


def parse_pnpm_lock(content: str) -> List[Tuple[str, str]]:
    """Parses dependencies from pnpm-lock.yaml."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        # Matches e.g. "  /next@15.2.0:" or "  '@types/node@20.0.0':"
        m = re.match(r"^['\"/]?(@?[^@\s]+)@([0-9A-Za-z.\-+]+)['\"]?:", line)
        if m:
            packages.append((m.group(1), m.group(2)))
    return list(dict.fromkeys(packages))


def parse_go_mod(content: str) -> List[Tuple[str, str]]:
    """Parses Go dependencies from go.mod."""
    packages = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        elif line == ")" and in_require:
            in_require = False
            continue
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                packages.append((parts[1], parts[2].lstrip("v")))
        elif in_require:
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                packages.append((parts[0], parts[1].lstrip("v")))
    return packages


def parse_cargo_toml_and_lock(toml_content: Optional[str], lock_content: Optional[str]) -> List[Tuple[str, str]]:
    """Parses Rust dependencies from Cargo.lock (preferred) or Cargo.toml."""
    packages = []
    if lock_content:
        current_name = None
        for line in lock_content.splitlines():
            line = line.strip()
            if line.startswith("[[package]]"):
                current_name = None
            elif line.startswith("name = "):
                m = re.match(r'name\s*=\s*"([^"]+)"', line)
                if m:
                    current_name = m.group(1)
            elif line.startswith("version = ") and current_name:
                m = re.match(r'version\s*=\s*"([^"]+)"', line)
                if m:
                    packages.append((current_name, m.group(1)))
                    current_name = None
    elif toml_content:
        in_deps = False
        for line in toml_content.splitlines():
            line = line.strip()
            if re.match(r"^\[.*dependencies.*\]", line, re.I):
                in_deps = True
                continue
            elif line.startswith("["):
                in_deps = False
                continue
            if in_deps and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip().strip('"').strip("'")
                val = parts[1].strip().strip('"').strip("'")
                clean_ver = re.sub(r"[\^~>=<]", "", val).strip()
                if name and not name.startswith("#"):
                    packages.append((name, clean_ver if re.match(r"^\d", clean_ver) else "UNKNOWN VERSION"))
    return list(dict.fromkeys(packages))


def parse_pom_xml(content: str) -> List[Tuple[str, str]]:
    """Parses Java dependencies from pom.xml."""
    packages = []
    try:
        root = ET.fromstring(content)
        # Handle namespaces
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        for dep in root.findall(f".//{ns}dependency"):
            group_id = dep.find(f"{ns}groupId")
            art_id = dep.find(f"{ns}artifactId")
            ver = dep.find(f"{ns}version")
            if art_id is not None and art_id.text:
                full_name = f"{group_id.text}:{art_id.text}" if group_id is not None and group_id.text else art_id.text
                version_str = ver.text.strip() if ver is not None and ver.text else "UNKNOWN VERSION"
                packages.append((full_name, version_str))
    except Exception:
        pass
    return packages


def parse_build_gradle(content: str) -> List[Tuple[str, str]]:
    """Parses Java/Kotlin dependencies from build.gradle."""
    packages = []
    # Match patterns like: implementation 'org.springframework.boot:spring-boot-starter-web:3.1.0'
    matches = re.findall(r"(?:implementation|compile|api)\s+['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]", content)
    for group, art, ver in matches:
        packages.append((f"{group}:{art}", ver))
    return packages


# ---------------------------------------------------------------------------
# Repository Inventory Scanner
# ---------------------------------------------------------------------------

def scan_and_record_repository_inventory(
    target_dir: str,
    project_id: str = "proj-default",
    asset_id: Optional[str] = None,
    repository_url: Optional[str] = None,
    org_id: str = "org-default",
    environment: str = "Source Code"
) -> List[Dict[str, Any]]:
    """
    Scans a repository workspace folder, extracts dependencies across all ecosystems,
    and saves normalized components into the inventory data store.
    """
    discovered: List[Dict[str, Any]] = []
    now = time.time()
    store = _load_inventory_store()

    if not os.path.exists(target_dir):
        return []

    # 1. Python
    # requirements.txt
    req_file = os.path.join(target_dir, "requirements.txt")
    if os.path.exists(req_file):
        try:
            with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_requirements_txt(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "PyPI",
                        "manifest_file": "requirements.txt",
                    })
        except Exception:
            pass

    # poetry.lock
    poetry_file = os.path.join(target_dir, "poetry.lock")
    if os.path.exists(poetry_file):
        try:
            with open(poetry_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_poetry_lock(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "PyPI",
                        "manifest_file": "poetry.lock",
                    })
        except Exception:
            pass

    # Pipfile.lock
    pipfile = os.path.join(target_dir, "Pipfile.lock")
    if os.path.exists(pipfile):
        try:
            with open(pipfile, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_pipfile_lock(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "PyPI",
                        "manifest_file": "Pipfile.lock",
                    })
        except Exception:
            pass

    # pyproject.toml
    pyproject = os.path.join(target_dir, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            with open(pyproject, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_pyproject_toml(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "PyPI",
                        "manifest_file": "pyproject.toml",
                    })
        except Exception:
            pass

    # 2. Node.js
    # package.json
    pkg_json = os.path.join(target_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_package_json(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "npm",
                        "manifest_file": "package.json",
                    })
        except Exception:
            pass

    # yarn.lock
    yarn_file = os.path.join(target_dir, "yarn.lock")
    if os.path.exists(yarn_file):
        try:
            with open(yarn_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_yarn_lock(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "npm",
                        "manifest_file": "yarn.lock",
                    })
        except Exception:
            pass

    # pnpm-lock.yaml
    pnpm_file = os.path.join(target_dir, "pnpm-lock.yaml")
    if os.path.exists(pnpm_file):
        try:
            with open(pnpm_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_pnpm_lock(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "npm",
                        "manifest_file": "pnpm-lock.yaml",
                    })
        except Exception:
            pass

    # 3. Go
    go_mod = os.path.join(target_dir, "go.mod")
    if os.path.exists(go_mod):
        try:
            with open(go_mod, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_go_mod(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "Go",
                        "manifest_file": "go.mod",
                    })
        except Exception:
            pass

    # 4. Rust
    cargo_toml = os.path.join(target_dir, "Cargo.toml")
    cargo_lock = os.path.join(target_dir, "Cargo.lock")
    if os.path.exists(cargo_toml) or os.path.exists(cargo_lock):
        toml_content = None
        lock_content = None
        try:
            if os.path.exists(cargo_toml):
                with open(cargo_toml, "r", encoding="utf-8", errors="ignore") as f:
                    toml_content = f.read()
            if os.path.exists(cargo_lock):
                with open(cargo_lock, "r", encoding="utf-8", errors="ignore") as f:
                    lock_content = f.read()
            for pkg, ver in parse_cargo_toml_and_lock(toml_content, lock_content):
                discovered.append({
                    "package_name": pkg,
                    "version": ver,
                    "ecosystem": "crates.io",
                    "manifest_file": "Cargo.lock" if lock_content else "Cargo.toml",
                })
        except Exception:
            pass

    # 5. Java
    pom_file = os.path.join(target_dir, "pom.xml")
    if os.path.exists(pom_file):
        try:
            with open(pom_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_pom_xml(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "Maven",
                        "manifest_file": "pom.xml",
                    })
        except Exception:
            pass

    gradle_file = os.path.join(target_dir, "build.gradle")
    if os.path.exists(gradle_file):
        try:
            with open(gradle_file, "r", encoding="utf-8", errors="ignore") as f:
                for pkg, ver in parse_build_gradle(f.read()):
                    discovered.append({
                        "package_name": pkg,
                        "version": ver,
                        "ecosystem": "Maven",
                        "manifest_file": "build.gradle",
                    })
        except Exception:
            pass

    # Deduplicate & Persist
    recorded_components = []
    seen_keys = set()

    for item in discovered:
        pkg_name = item["package_name"]
        ver = item["version"]
        eco = item["ecosystem"]
        key = f"{project_id}:{eco}:{pkg_name}"

        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Check existing in store
        existing = store.get("components", {}).get(key)
        comp_id = existing.get("id") if existing else f"comp-{uuid.uuid4().hex[:10]}"
        first_seen = existing.get("first_seen", now) if existing else now

        component_record = {
            "id": comp_id,
            "org_id": org_id,
            "project_id": project_id,
            "asset_id": asset_id or f"asset-repo-{project_id}",
            "repository": repository_url or target_dir,
            "package_name": pkg_name,
            "version": ver,
            "ecosystem": eco,
            "manifest_file": item.get("manifest_file", "manifest"),
            "environment": environment,
            "first_seen": first_seen,
            "last_seen": now,
        }
        store.setdefault("components", {})[key] = component_record
        recorded_components.append(component_record)

    _save_inventory_store(store)
    return recorded_components


def record_web_technologies_inventory(
    tech_info: Dict[str, Any],
    project_id: str = "proj-default",
    asset_id: Optional[str] = None,
    target_url: Optional[str] = None,
    org_id: str = "org-default"
) -> List[Dict[str, Any]]:
    """
    Records detected web application perimeter technologies as software components.
    """
    store = _load_inventory_store()
    now = time.time()
    recorded = []

    # Map detected technologies
    detected_techs = tech_info.get("detected_technologies", [])
    server_header = tech_info.get("server_header", "")
    powered_by = tech_info.get("x_powered_by", "")

    raw_candidates = list(detected_techs)
    if server_header:
        raw_candidates.append(server_header)
    if powered_by:
        raw_candidates.append(powered_by)

    for item in raw_candidates:
        if not item or not isinstance(item, str):
            continue
        parts = item.split("/", 1) if "/" in item else item.split(" ", 1)
        name = parts[0].strip().lower()
        ver = parts[1].strip() if len(parts) > 1 and re.match(r"^\d", parts[1].strip()) else "UNKNOWN VERSION"

        key = f"{project_id}:web:{name}"
        existing = store.get("components", {}).get(key)
        comp_id = existing.get("id") if existing else f"comp-{uuid.uuid4().hex[:10]}"
        first_seen = existing.get("first_seen", now) if existing else now

        rec = {
            "id": comp_id,
            "org_id": org_id,
            "project_id": project_id,
            "asset_id": asset_id or f"asset-web-{project_id}",
            "repository": target_url or "https://example.com",
            "package_name": name,
            "version": ver,
            "ecosystem": "WebTech",
            "manifest_file": "HTTP Response Headers / DOM",
            "environment": "Production",
            "first_seen": first_seen,
            "last_seen": now,
        }
        store.setdefault("components", {})[key] = rec
        recorded.append(rec)

    _save_inventory_store(store)
    return recorded


def get_all_inventory_components(org_id: str = "org-default", project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all stored software inventory components for an organization/project."""
    store = _load_inventory_store()
    comps = list(store.get("components", {}).values())
    filtered = [c for c in comps if c.get("org_id") == org_id]
    if project_id:
        filtered = [c for c in filtered if c.get("project_id") == project_id]
    return filtered
