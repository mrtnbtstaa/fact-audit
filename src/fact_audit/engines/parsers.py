"""Parse dependency manifests (npm, Python, Go) into Dependency records."""

import json
import re
import tomllib
from pathlib import Path

from fact_audit.dataclasses.deps import Dependency, Manifest

PINNED_NPM = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$")
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def parse_manifest(path: Path, ecosystem: str, parser: str) -> Manifest:
    manifest = Manifest(path=str(path), kind=path.name, ecosystem=ecosystem)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        manifest.error = str(exc)
        return manifest

    try:
        if parser == "package_json":
            manifest.dependencies = _package_json(text)
        elif parser == "npm_lock":
            manifest.dependencies = _npm_lock(text)
        elif parser == "pyproject":
            manifest.dependencies = _pyproject(text)
        elif parser == "go_mod":
            manifest.dependencies = _go_mod(text)
        elif parser == "go_sum":
            manifest.dependencies = _go_sum(text)
        else:
            manifest.dependencies = _requirements(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        manifest.error = _error_text(exc)
        manifest.dependencies = []
    return manifest


def _error_text(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"{exc.msg} (line {exc.lineno}, column {exc.colno})"
    return str(exc)


def _package_json(text: str) -> list[Dependency]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json must contain an object")
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            raise ValueError(f"{section} must be an object")
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            pinned = PINNED_NPM.match(spec.strip())
            deps.append(
                Dependency(
                    name=name,
                    ecosystem="npm",
                    declared=spec,
                    version=pinned.group(1) if pinned else None,
                    is_range=pinned is None,
                )
            )
    return deps


def _npm_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict) or entry.get("link"):
                continue
            version = entry.get("version")
            if not version:
                continue
            deps.append(
                Dependency(
                    name=key.split("node_modules/")[-1],
                    ecosystem="npm",
                    declared=version,
                    version=version,
                    license=entry.get("license") or "UNKNOWN",
                    transitive=True,
                )
            )
        return deps

    def walk(node: dict) -> None:  # lockfile v1
        for name, entry in (node or {}).items():
            if not isinstance(entry, dict):
                continue
            if entry.get("version"):
                deps.append(
                    Dependency(
                        name=name,
                        ecosystem="npm",
                        declared=entry["version"],
                        version=entry["version"],
                        transitive=True,
                    )
                )
            walk(entry.get("dependencies"))

    walk(data.get("dependencies") or {})
    return deps


def _requirements(text: str) -> list[Dependency]:
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQUIREMENT.match(line)
        if not match:
            continue
        name, spec = match.group(1), match.group(2).strip()
        version = None
        if spec.startswith("==="):
            version = spec[3:].strip()
        elif spec.startswith("=="):
            version = spec[2:].strip()
        if version and "*" in version:
            version = None
        deps.append(
            Dependency(
                name=name,
                ecosystem="python",
                declared=spec or "*",
                version=version,
                is_range=version is None,
            )
        )
    return deps


def _pyproject(text: str) -> list[Dependency]:
    data = tomllib.loads(text)
    project = data.get("project") or {}
    requirements = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        requirements.extend(group)
    return _requirements("\n".join(requirements))


def _go_mod(text: str) -> list[Dependency]:
    deps = []
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_require:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        deps.append(
            Dependency(
                name=parts[0],
                ecosystem="go",
                declared=parts[1],
                version=parts[1][1:],
            )
        )
    return deps


def _go_sum(text: str) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    deps = []
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        version = parts[1].removesuffix("/go.mod").lstrip("v")
        if not version or (name, version) in seen:
            continue
        seen.add((name, version))
        deps.append(
            Dependency(
                name=name,
                ecosystem="go",
                declared=f"v{version}",
                version=version,
                transitive=True,
            )
        )
    return deps
